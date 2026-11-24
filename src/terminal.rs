//! Bound, resumable tool interactions over the resident SSH connection.
//!
//! The MCP connection can disappear while a command runs: the command task, its private
//! logs and its explicit target binding belong to the service, not to that request. A
//! lost SSH shell is never recreated and a command is never replayed implicitly.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::{json, Map, Value};
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};

use crate::errors::{BridgeError, BridgeResult};
use crate::execution::Runner;
use crate::guard;
use crate::inventory::{shell_quote, Host};
use crate::rest::AssetCatalog;
use crate::scheduler::{queue_rejection, Lane, SlotWait, Timings};
use crate::storage::results::{atomic_json, ResultStore};
use crate::transport::session::{
    find, new_nonce, ready_marker, ready_packet, terminal_packet, MARKER_SUFFIX,
};
use crate::transport::ssh::{ChannelShell, ChannelWriter, ShellEvent};

pub const DEFAULT_TERMINAL_WAIT_MS: u64 = 15_000;

const SHELL_GUARD: &str = "JMS_SCRIPT_PATTERN_GUARD: already-authorized action needs \
allow_dangerous=true; this acknowledges only the local guard, never client or JumpServer policy";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdState {
    Queued,
    Running,
    Completed,
    Unknown,
    NotStarted,
}

impl CmdState {
    fn as_str(self) -> &'static str {
        match self {
            CmdState::Queued => "queued",
            CmdState::Running => "running",
            CmdState::Completed => "completed",
            CmdState::Unknown => "unknown",
            CmdState::NotStarted => "not_started",
        }
    }
}

pub struct Command {
    pub result_id: String,
    state: CmdState,
    sent: bool,
    started: Arc<AtomicBool>,
    exit_code: Option<i32>,
    error: Option<String>,
    rejection: Map<String, Value>,
    cursor: HashMap<String, u64>,
    changed: Arc<Notify>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Command {
    fn new(result_id: String) -> Self {
        let mut cursor = HashMap::new();
        cursor.insert("stdout".to_string(), 0);
        cursor.insert("stderr".to_string(), 0);
        Self {
            result_id,
            state: CmdState::Queued,
            sent: false,
            started: Arc::new(AtomicBool::new(false)),
            exit_code: None,
            error: None,
            rejection: Map::new(),
            cursor,
            changed: Arc::new(Notify::new()),
            task: None,
        }
    }

    /// The same verdict is used for the live command and its retained result.
    fn evidence(&self) -> Map<String, Value> {
        let mut values = self.rejection.clone();
        let completed = self.state == CmdState::Completed;
        values.insert("ok".into(), json!(completed && self.exit_code == Some(0)));
        values.insert("execution_state".into(), json!(self.state.as_str()));
        values.insert(
            "completion_unknown".into(),
            json!(self.state == CmdState::Unknown),
        );
        values.insert(
            "executed".into(),
            if completed || self.started.load(Ordering::SeqCst) {
                Value::Bool(true)
            } else if self.sent {
                Value::Null
            } else {
                Value::Bool(false)
            },
        );
        if completed {
            values.insert("exit_code".into(), json!(self.exit_code.unwrap_or(255)));
        }
        if let Some(error) = &self.error {
            values.insert("error".into(), json!(error));
        }
        values
    }

    /// Called under the command lock, before a new command can replace this one.
    fn persist_verdict(&self, store: &ResultStore, timings: Option<&Timings>) -> BridgeResult<()> {
        let mut values = self.evidence();
        if let Some(timings) = timings {
            values.insert("timing".into(), timings.snapshot());
        }
        let stored = store.finish(&self.result_id, values).map(|_| ());
        self.changed.notify_waiters();
        stored
    }

    /// A command occupies the terminal from the moment it is admitted.
    ///
    /// The worker handle is deliberately *not* part of this test: between admission and
    /// the `task` assignment there is a window where the handle is still `None`, and
    /// treating that as idle let two callers own the same terminal.
    fn is_busy(&self) -> bool {
        matches!(self.state, CmdState::Queued | CmdState::Running)
    }
}

/// One demultiplexed output stream with its unread tail retained between reads.
struct StreamSource {
    receiver: mpsc::Receiver<Bytes>,
    buffer: Vec<u8>,
    closed: bool,
}

impl StreamSource {
    async fn fill(&mut self) -> bool {
        match self.receiver.recv().await {
            Some(chunk) => {
                self.buffer.extend_from_slice(&chunk);
                true
            }
            None => {
                self.closed = true;
                false
            }
        }
    }

    /// Await the next chunk, or report closure immediately for a closed stream.
    ///
    /// A closed receiver returns `Ready(None)` straight away, so polling it again would
    /// spin: every wait site must ask this first and stop watching closed streams.
    fn is_closed(&self) -> bool {
        self.closed
    }
}

/// What one wait on the output streams observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamEvent {
    /// At least one chunk arrived (it is now in that stream's buffer).
    Data,
    /// One stream ended; the other may still have queued data or a marker to deliver.
    StreamClosed,
    /// Both streams ended: no further evidence can arrive.
    AllClosed,
}

/// Wait for one chunk from whichever stream is still open.
///
/// A single ended stream is reported as an event, never as "the shell is dead": the
/// other stream may still hold a queued completion marker. Closed streams are not
/// polled again, so this cannot spin.
async fn wait_any_chunk(out: &mut StreamSource, err: &mut StreamSource) -> StreamEvent {
    if out.is_closed() && err.is_closed() {
        return StreamEvent::AllClosed;
    }
    if out.is_closed() {
        return if err.fill().await {
            StreamEvent::Data
        } else {
            StreamEvent::StreamClosed
        };
    }
    if err.is_closed() {
        return if out.fill().await {
            StreamEvent::Data
        } else {
            StreamEvent::StreamClosed
        };
    }
    tokio::select! {
        got = out.fill() => if got { StreamEvent::Data } else { StreamEvent::StreamClosed },
        got = err.fill() => if got { StreamEvent::Data } else { StreamEvent::StreamClosed },
    }
}

struct Streams {
    out: StreamSource,
    err: StreamSource,
}

/// The markers and payload of one terminal command.
struct CommandPlan {
    start: Vec<u8>,
    end: Vec<u8>,
    packet: Vec<u8>,
}

impl CommandPlan {
    fn new(script: &str) -> Self {
        let nonce = new_nonce();
        let mut start = b"\x1eSTART".to_vec();
        start.extend_from_slice(nonce.as_bytes());
        start.push(MARKER_SUFFIX);
        Self {
            start,
            end: format!("\x1eEND{nonce}:").into_bytes(),
            packet: terminal_packet(&nonce, script),
        }
    }
}

/// A bound shell: a writer usable at any time plus the streams of its current command.
pub struct TerminalShell {
    writer: ChannelWriter,
    streams: AsyncMutex<Streams>,
    lost: Arc<AtomicBool>,
    protection: Arc<crate::execution::TerminalProtection>,
    demux: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

async fn demux_terminal_output(
    events: impl Stream<Item = ShellEvent>,
    out_tx: mpsc::Sender<Bytes>,
    err_tx: mpsc::Sender<Bytes>,
    mark_lost: impl FnOnce(),
) {
    futures::pin_mut!(events);
    while let Some(event) = events.next().await {
        let (queue, data) = match event {
            ShellEvent::Data(data) => (&out_tx, data),
            ShellEvent::ExtData(data) => (&err_tx, data),
            // Terminal completion is proved by shell markers, not SSH Exit.
            // EOF means no more markers can arrive. Dropping the senders
            // lets capture drain any data already queued before seeing closure.
            ShellEvent::Eof | ShellEvent::Closed | ShellEvent::ExecRejected => break,
            ShellEvent::Exit(_) => continue,
        };
        if queue.send(data).await.is_err() {
            break;
        }
    }
    mark_lost();
}

impl TerminalShell {
    async fn open(
        runner: &Runner,
        host: &Host,
        command: &str,
        protection: Arc<crate::execution::TerminalProtection>,
    ) -> BridgeResult<Self> {
        let (shell, _reconnected) = runner.pool.open_process(host, command).await?;
        let ChannelShell { writer, reader } = shell;
        let (out_tx, out_rx) = mpsc::channel(64);
        let (err_tx, err_rx) = mpsc::channel(64);
        let lost = Arc::new(AtomicBool::new(false));
        let lost_for_reader = lost.clone();
        let protection_for_reader = Arc::downgrade(&protection);
        let events = futures::stream::unfold(reader, |mut reader| async {
            reader.next().await.map(|event| (event, reader))
        });
        let demux = tokio::spawn(demux_terminal_output(events, out_tx, err_tx, move || {
            lost_for_reader.store(true, Ordering::SeqCst);
            if let Some(protection) = protection_for_reader.upgrade() {
                protection.release();
            }
        }));
        let shell = Self {
            writer,
            streams: AsyncMutex::new(Streams {
                out: StreamSource {
                    receiver: out_rx,
                    buffer: Vec::new(),
                    closed: false,
                },
                err: StreamSource {
                    receiver: err_rx,
                    buffer: Vec::new(),
                    closed: false,
                },
            }),
            lost,
            protection,
            demux: Mutex::new(Some(demux)),
        };
        if let Err(error) = shell.prime(Duration::from_secs(10)).await {
            shell.close().await;
            return Err(error);
        }
        Ok(shell)
    }

    async fn prime(&self, timeout: Duration) -> BridgeResult<()> {
        let nonce = new_nonce();
        let marker = ready_marker(&nonce);
        self.writer.write(&ready_packet(&nonce)).await?;
        let mut streams = self.streams.lock().await;
        let deadline = Instant::now() + timeout;
        let mut out_ready = false;
        let mut err_ready = false;
        while !(out_ready && err_ready) {
            if Instant::now() >= deadline {
                return Err(BridgeError::ssh(
                    "remote shell did not acknowledge readiness in time; script was not sent",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Streams { out, err } = &mut *streams;
            let waited = tokio::time::timeout(remaining, wait_any_chunk(out, err))
                .await
                .map_err(|_| {
                    BridgeError::ssh(
                        "remote shell did not acknowledge readiness in time; script was not sent",
                    )
                })?;
            if waited == StreamEvent::AllClosed {
                self.mark_lost();
                return Err(BridgeError::ssh(
                    "remote shell closed during startup; script was not sent",
                ));
            }
            if !out_ready {
                if let Some(position) = find(&streams.out.buffer, &marker) {
                    streams.out.buffer.drain(..position + marker.len());
                    out_ready = true;
                }
            }
            if !err_ready {
                if let Some(position) = find(&streams.err.buffer, &marker) {
                    streams.err.buffer.drain(..position + marker.len());
                    err_ready = true;
                }
            }
        }
        Ok(())
    }

    fn is_closing(&self) -> bool {
        let closing = self.lost.load(Ordering::SeqCst) || self.writer.is_closed();
        if closing {
            self.protection.release();
        }
        closing
    }

    fn mark_lost(&self) {
        self.lost.store(true, Ordering::SeqCst);
        self.protection.release();
    }

    async fn write_input(&self, text: &str) -> BridgeResult<()> {
        self.writer.write(text.as_bytes()).await
    }

    async fn send_signal(&self, signal: &str) -> BridgeResult<()> {
        self.writer.signal(signal).await
    }

    async fn write_eof(&self) {
        self.writer.write_eof().await;
    }

    async fn close(&self) {
        self.mark_lost();
        self.writer.close().await;
        if let Some(demux) = self.demux.lock().expect("demux lock").take() {
            demux.abort();
        }
    }

    /// Write the command packet.
    ///
    /// The caller commits the send under the command lock before writing, so
    /// `close` cannot report "not started" once a write may occur.
    async fn send_packet(&self, packet: &[u8]) -> BridgeResult<()> {
        let mut streams = self.streams.lock().await;
        streams.out.buffer.clear();
        streams.err.buffer.clear();
        self.writer.write(packet).await
    }

    /// Capture one command's output on both streams until both markers close it.
    async fn capture_after_send(
        &self,
        plan: &CommandPlan,
        out_path: &std::path::Path,
        err_path: &std::path::Path,
        started: &Arc<AtomicBool>,
        changed: &Arc<Notify>,
        deadline: Duration,
    ) -> BridgeResult<i32> {
        let start = plan.start.clone();
        let end = plan.end.clone();
        let mut streams = self.streams.lock().await;
        let (mut out_file, mut err_file) = (
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(out_path)?,
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(err_path)?,
        );
        let mut out_state = CaptureState::default();
        let mut err_state = CaptureState::default();
        let mut out_code: Option<i32> = None;
        let mut err_code: Option<i32> = None;
        let began = Instant::now();
        loop {
            // Drain what is already buffered before waiting for the next packet. Both
            // streams are scanned every round: the command is only complete once both
            // reported their end marker, so a late stderr line is never dropped.
            if out_code.is_none() {
                out_code = capture_stream(
                    &mut streams.out.buffer,
                    &mut out_file,
                    &start,
                    &end,
                    &mut out_state,
                )?;
            }
            if err_code.is_none() {
                err_code = capture_stream(
                    &mut streams.err.buffer,
                    &mut err_file,
                    &start,
                    &end,
                    &mut err_state,
                )?;
            }
            if out_state.started || err_state.started {
                started.store(true, Ordering::SeqCst);
                changed.notify_waiters();
            }
            if let Some(resolved) = resolve_completion(out_code, err_code) {
                return resolved.and_then(|code| finish_capture(code, &out_file));
            }
            let remaining = deadline.checked_sub(began.elapsed()).unwrap_or_default();
            if began.elapsed() >= deadline {
                return Err(BridgeError::ssh(
                    "terminal command timed out; completion is unknown",
                ));
            }
            // A stream that ended without its end marker makes completion impossible:
            // waiting for the other one would keep this command "running" until the
            // multi-hour deadline for no reason.
            if completion_impossible(
                streams.out.is_closed(),
                out_state.end_marker.is_some(),
                streams.err.is_closed(),
                err_state.end_marker.is_some(),
            ) {
                self.mark_lost();
                return Err(BridgeError::ssh(
                    "terminal stream closed before the completion marker; completion is unknown",
                ));
            }
            let Streams { out, err } = &mut *streams;
            let waited = tokio::time::timeout(remaining, wait_any_chunk(out, err)).await;
            match waited {
                // A single stream ending is not a verdict: loop again so the marker that
                // is already queued on the other stream is consumed, and let
                // `completion_impossible` decide when evidence can no longer arrive.
                Ok(StreamEvent::Data | StreamEvent::StreamClosed) => continue,
                Ok(StreamEvent::AllClosed) => {
                    self.mark_lost();
                    return Err(BridgeError::ssh(
                        "terminal shell closed before the completion marker; completion is unknown",
                    ));
                }
                Err(_) => {
                    return Err(BridgeError::ssh(
                        "terminal command timed out; completion is unknown",
                    ))
                }
            }
        }
    }
}

fn finish_capture(code: i32, _file: &std::fs::File) -> BridgeResult<i32> {
    Ok(code)
}

/// A command is complete only when both streams reported the same status.
fn resolve_completion(out_code: Option<i32>, err_code: Option<i32>) -> Option<BridgeResult<i32>> {
    match (out_code, err_code) {
        (Some(exit_out), Some(exit_err)) if exit_out == exit_err => Some(Ok(exit_out)),
        (Some(exit_out), Some(exit_err)) => Some(Err(BridgeError::ssh(format!(
            "terminal streams reported different statuses ({exit_out} and {exit_err}); \
completion is unknown"
        )))),
        _ => None,
    }
}

/// Check readiness and commit to sending under the command lock. If close
/// won or the shell was already lost, nothing can reach the remote side.
fn try_take_over(guard: &mut Command, shell_lost: bool, store: &ResultStore) -> bool {
    if guard.state != CmdState::Queued {
        return false;
    }
    if shell_lost {
        let error = "terminal shell was lost before sending";
        guard.state = CmdState::NotStarted;
        guard.error = Some(error.into());
        let _ = guard.persist_verdict(store, None);
        return false;
    }
    guard.state = CmdState::Running;
    guard.sent = true;
    true
}

/// What a closed terminal records for its current command.
///
/// `None` means "leave the stored result alone": a command that already reached a
/// terminal state keeps it.
fn close_final_state(state: CmdState) -> Option<(CmdState, &'static str)> {
    match state {
        CmdState::Queued => Some((CmdState::NotStarted, "not_started")),
        CmdState::Running => Some((CmdState::Unknown, "closed_by_caller")),
        CmdState::NotStarted | CmdState::Completed | CmdState::Unknown => None,
    }
}

/// Whether the completion markers can no longer both arrive.
///
/// Completion needs an end marker on *both* streams, so a stream that closed without
/// one ends the command as unknown instead of letting it look "running" forever.
fn completion_impossible(out_closed: bool, out_end: bool, err_closed: bool, err_end: bool) -> bool {
    (out_closed && !out_end) || (err_closed && !err_end)
}

#[derive(Default)]
struct CaptureState {
    active: bool,
    started: bool,
    done: bool,
    /// The end marker was seen on this stream (carrying the exit code).
    end_marker: Option<i32>,
}

/// One stream's marker scan, mirroring the isolated execution's buffer rules.
fn capture_stream(
    buffer: &mut Vec<u8>,
    file: &mut std::fs::File,
    start: &[u8],
    end: &[u8],
    state: &mut CaptureState,
) -> BridgeResult<Option<i32>> {
    if !state.active {
        match find(buffer, start) {
            Some(position) => {
                buffer.drain(..position + start.len());
                state.active = true;
                state.started = true;
            }
            None => {
                if buffer.len() >= start.len() {
                    let cut = buffer.len() - (start.len() - 1);
                    buffer.drain(..cut);
                }
                return Ok(None);
            }
        }
    }
    let Some(position) = find(buffer, end) else {
        // Publish short prompts immediately; retain only a possible marker prefix.
        let keep = (1..end.len().min(buffer.len()) + 1)
            .rev()
            .find(|count| buffer.ends_with(&end[..*count]))
            .unwrap_or(0);
        if keep > 0 {
            let cut = buffer.len() - keep;
            let _ = std::io::Write::write_all(file, &buffer[..cut]);
            buffer.drain(..cut);
        } else {
            let _ = std::io::Write::write_all(file, buffer);
            buffer.clear();
        }
        return Ok(None);
    };
    let suffix_start = position + end.len();
    match buffer[suffix_start..]
        .iter()
        .position(|byte| *byte == MARKER_SUFFIX)
    {
        Some(offset) => {
            let code = String::from_utf8_lossy(&buffer[suffix_start..suffix_start + offset])
                .trim()
                .parse()
                .unwrap_or(255);
            let _ = std::io::Write::write_all(file, &buffer[..position]);
            let rest = buffer[suffix_start + offset + 1..].to_vec();
            buffer.clear();
            buffer.extend_from_slice(&rest);
            state.done = true;
            state.end_marker = Some(code);
            Ok(Some(code))
        }
        None => {
            let _ = std::io::Write::write_all(file, &buffer[..position]);
            buffer.drain(..position);
            Ok(None)
        }
    }
}

struct Binding {
    session: String,
    host: Host,
    shell: Arc<TerminalShell>,
    command: Option<Arc<AsyncMutex<Command>>>,
    closed: bool,
}

impl Binding {
    async fn check_exec_admission(&self) -> BridgeResult<()> {
        let busy = match &self.command {
            Some(current) => current.lock().await.is_busy(),
            None => false,
        };
        // A worker can mark the shell lost while admission waits for its command
        // lock. Check liveness after observing whether that command ended.
        if self.closed || self.shell.is_closing() {
            return Err(BridgeError::invalid(
                "terminal shell was closed/lost; open a new session explicitly",
            ));
        }
        if busy {
            return Err(BridgeError::invalid(
                "terminal is busy; read/write its active command first",
            ));
        }
        Ok(())
    }
}

pub struct Interactive {
    catalog: Arc<AssetCatalog>,
    runner: Arc<Runner>,
    store: Arc<ResultStore>,
    bindings: AsyncMutex<HashMap<String, Arc<AsyncMutex<Binding>>>>,
    lost: Mutex<HashMap<String, Value>>,
    registry: PathBuf,
    save_lock: AsyncMutex<()>,
}

impl Interactive {
    pub fn new(catalog: Arc<AssetCatalog>, runner: Arc<Runner>, store: Arc<ResultStore>) -> Self {
        let registry = store
            .root
            .parent()
            .unwrap_or(&store.root)
            .join("terminal_sessions.json");
        let mut lost = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(&registry) {
            if let Ok(Value::Array(rows)) = serde_json::from_str::<Value>(&text) {
                for row in rows {
                    if let Some(session) = row.get("session").and_then(Value::as_str) {
                        lost.insert(session.to_string(), row.clone());
                    }
                }
            }
        }
        Self {
            catalog,
            runner,
            store,
            bindings: AsyncMutex::new(HashMap::new()),
            lost: Mutex::new(lost),
            registry,
            save_lock: AsyncMutex::new(()),
        }
    }

    /// Mark results left running by a previous process as unknown, then persist.
    pub async fn start(&self) -> BridgeResult<()> {
        let lost = self.lost.lock().expect("lost lock").clone();
        for (_session, row) in lost {
            let Some(result_id) = row.get("result_id").and_then(Value::as_str) else {
                continue;
            };
            if let Ok(meta) = self.store.metadata(result_id) {
                if meta.get("status").and_then(Value::as_str) == Some("running") {
                    let mut values = Map::new();
                    values.insert("ok".into(), Value::Bool(false));
                    values.insert("execution_state".into(), Value::from("unknown"));
                    values.insert("completion_unknown".into(), Value::Bool(true));
                    values.insert(
                        "error".into(),
                        Value::from("service restarted; inspect saved output before further work"),
                    );
                    let _ = self.store.finish(result_id, values);
                }
            }
        }
        self.save().await
    }

    async fn save(&self) -> BridgeResult<()> {
        let _guard = self.save_lock.lock().await;
        let mut rows: Vec<Value> = self
            .lost
            .lock()
            .expect("lost lock")
            .values()
            .cloned()
            .collect();
        let bindings = self.bindings.lock().await;
        for binding in bindings.values() {
            let binding = binding.lock().await;
            if binding.closed {
                continue;
            }
            let result_id = match &binding.command {
                Some(command) => Value::from(command.lock().await.result_id.clone()),
                None => Value::Null,
            };
            rows.push(json!({
                "session": binding.session,
                "asset_id": binding.host.asset_id,
                "host": binding.host.name,
                "result_id": result_id,
            }));
        }
        rows.sort_by_key(|row| row.to_string());
        atomic_json(&self.registry, &Value::Array(rows))
    }

    fn check(&self, text: &str, allowed: bool) -> BridgeResult<()> {
        if text.contains('\0') {
            return Err(BridgeError::invalid("NUL is invalid"));
        }
        if guard::is_dangerous(text) && !allowed {
            return Err(BridgeError::invalid(SHELL_GUARD));
        }
        Ok(())
    }

    async fn binding(&self, session: &str) -> BridgeResult<Arc<AsyncMutex<Binding>>> {
        if let Some(row) = self.lost.lock().expect("lost lock").get(session) {
            return Err(BridgeError::invalid(format!(
                "terminal state lost after restart; never replay automatically; saved result_id={}",
                row.get("result_id")
                    .map(|value| value.to_string())
                    .unwrap_or_default()
            )));
        }
        let bindings = self.bindings.lock().await;
        bindings
            .get(session)
            .cloned()
            .ok_or_else(|| BridgeError::invalid("unknown terminal session"))
    }

    async fn permitted(&self, binding: &Binding) -> BridgeResult<()> {
        let inventory = self.catalog.ensure().await?;
        let asset_id = binding
            .host
            .asset_id
            .clone()
            .ok_or_else(|| BridgeError::invalid("bound asset is no longer permitted"))?;
        let hosts = inventory.resolve(std::slice::from_ref(&asset_id))?;
        if hosts.len() != 1 || hosts[0].connection_key()? != binding.host.connection_key()? {
            return Err(BridgeError::invalid(
                "bound asset/account is no longer permitted",
            ));
        }
        Ok(())
    }

    pub async fn open(
        &self,
        target: &str,
        container: Option<&str>,
        image: Option<&str>,
        docker_args: &[String],
        cwd: Option<&str>,
        env: &[(String, String)],
    ) -> BridgeResult<Value> {
        if target.eq_ignore_ascii_case("all") || target.contains(['*', '?', '[', ']']) {
            return Err(BridgeError::invalid("terminal needs one exact target"));
        }
        let inventory = self.catalog.ensure().await?;
        let hosts = inventory.resolve(&[target.to_string()])?;
        if hosts.len() != 1 {
            return Err(BridgeError::invalid(
                "terminal needs exactly one permitted asset",
            ));
        }
        if env.iter().any(|(key, _)| !valid_env_name(key)) {
            return Err(BridgeError::invalid("invalid environment variable name"));
        }
        if cwd.unwrap_or("").contains('\0')
            || env.iter().any(|(_, value)| value.contains('\0'))
            || docker_args.iter().any(|value| value.contains('\0'))
        {
            return Err(BridgeError::invalid("NUL is invalid"));
        }
        let host = hosts.into_iter().next().expect("one host");
        let command = self.runner.command(container, image, docker_args, true)?;
        let key = host.connection_key()?;
        let lease = self
            .runner
            .recovery
            .enter(&key, self.runner.queue_timeout)
            .await?;
        let mut timings = Timings::default();
        let slot = self
            .runner
            .scheduler
            .acquire(
                Lane::General,
                Duration::from_secs_f64(self.runner.queue_timeout),
                &mut timings,
            )
            .await
            .map_err(|wait| match wait {
                SlotWait::Full(full) => BridgeError::invalid(full.message()),
                SlotWait::Timeout(timeout) => BridgeError::invalid(timeout.message()),
            })?;
        // Register the protection before the shell exists: the connection must not be
        // replaced between opening the channel and the binding becoming visible.
        let protection = Arc::new(self.runner.protect_terminal(&key));
        let shell = TerminalShell::open(&self.runner, &host, &command, protection.clone()).await;
        drop(slot);
        drop(lease);
        let shell = match shell {
            Ok(shell) => shell,
            Err(error) => {
                drop(protection);
                return Err(error);
            }
        };
        let mut session = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
        {
            let bindings = self.bindings.lock().await;
            let lost = self.lost.lock().expect("lost lock");
            while bindings.contains_key(&session) || lost.contains_key(&session) {
                session = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
            }
        }
        let binding = Arc::new(AsyncMutex::new(Binding {
            session: session.clone(),
            host: host.clone(),
            shell: Arc::new(shell),
            command: None,
            closed: false,
        }));
        self.bindings
            .lock()
            .await
            .insert(session.clone(), binding.clone());
        let mut setup: Vec<String> = Vec::new();
        if let Some(cwd) = cwd {
            setup.push(format!("cd -- {}", shell_quote(cwd)));
        }
        for (key, value) in env {
            setup.push(format!("export {key}={}", shell_quote(value)));
        }
        let script = if setup.is_empty() {
            ":".to_string()
        } else {
            setup.join(" && ")
        };
        let setup_deadline = Instant::now() + Duration::from_secs(10);
        let value = self
            .execute_with_wait(
                &session,
                &script,
                false,
                ReadWait::Completion(setup_deadline),
                4096,
                None,
                None,
            )
            .await;
        let value = match value {
            Ok(value) => value,
            Err(error) => {
                let _ = self.close(&session).await;
                return Err(error);
            }
        };
        if value.get("state").and_then(Value::as_str) != Some("completed")
            || value.get("exit_code").and_then(Value::as_i64) != Some(0)
        {
            let _ = self.close(&session).await;
            return Err(BridgeError::invalid(format!(
                "terminal setup failed; result_id={}",
                value.get("result_id").and_then(Value::as_str).unwrap_or("")
            )));
        }
        self.save().await?;
        Ok(json!({
            "ok": true,
            "session": session,
            "host": target,
            "state": "idle",
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute(
        &self,
        session: &str,
        script: &str,
        allow_dangerous: bool,
        wait_ms: u64,
        max_bytes: usize,
        cursor: Option<&Value>,
        progress: Option<&dyn crate::storage::journal::ProgressSink>,
    ) -> BridgeResult<Value> {
        self.execute_with_wait(
            session,
            script,
            allow_dangerous,
            ReadWait::Output(wait_ms),
            max_bytes,
            cursor,
            progress,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_with_wait(
        &self,
        session: &str,
        script: &str,
        allow_dangerous: bool,
        wait: ReadWait,
        max_bytes: usize,
        cursor: Option<&Value>,
        progress: Option<&dyn crate::storage::journal::ProgressSink>,
    ) -> BridgeResult<Value> {
        self.check(script, allow_dangerous)?;
        let binding = self.binding(session).await?;
        // Admission is one critical section: check the shell, check that no command is
        // active, and install this command. Two concurrent execs can no longer both pass.
        let (host, command, result_id) = {
            let mut binding_guard = binding.lock().await;
            self.permitted(&binding_guard).await?;
            binding_guard.check_exec_admission().await?;
            let host = binding_guard.host.clone();
            let mut metadata = Map::new();
            metadata.insert("kind".into(), Value::from("terminal"));
            metadata.insert("host".into(), Value::from(host.name.clone()));
            if let Some(asset_id) = &host.asset_id {
                metadata.insert("asset_id".into(), Value::from(asset_id.clone()));
            }
            metadata.insert("session_id".into(), Value::from(session));
            let result_id = self.store.create(metadata)?;
            for stream in ["stdout", "stderr"] {
                let created = self.store.path(&result_id, stream).and_then(|path| {
                    std::fs::File::create(&path).map(|_| path).map_err(|error| {
                        crate::errors::BridgeError::storage(format!(
                            "cannot create the {stream} file for {result_id}: {error}"
                        ))
                    })
                });
                if let Err(error) = created {
                    // The result exists but can never be produced: close it so cleanup
                    // does not treat it as an active transfer forever.
                    let _ = self.store.finish(
                        &result_id,
                        json!({
                            "ok": false, "executed": false, "execution_state": "not_started",
                            "completion_unknown": false, "failure_stage": "results",
                            "error": error.message(),
                        })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                    );
                    binding_guard.command = None;
                    return Err(error);
                }
            }
            let command = Arc::new(AsyncMutex::new(Command::new(result_id.clone())));
            binding_guard.command = Some(command.clone());
            (host, command, result_id)
        };
        self.persist_admission(&host, &result_id, &command, progress)
            .await?;
        // The worker owns the shell for the duration of the command; the caller only
        // polls its files, so an MCP disconnect cannot cancel accepted work.
        let runner = self.runner.clone();
        let store = self.store.clone();
        let shell = { binding.lock().await.shell.clone() };
        let host_for_task = host.clone();
        let script = script.to_string();
        let command_for_task = command.clone();
        let session_id = session.to_string();
        // The worker must not run before its handle is published: `close` needs the
        // handle to abort a send that is stuck on the channel.
        let gate = Arc::new(tokio::sync::Notify::new());
        let worker_gate = gate.clone();
        let task = tokio::spawn(async move {
            worker_gate.notified().await;
            let _ = run_terminal_command(
                runner,
                store,
                host_for_task,
                shell,
                command_for_task,
                script,
                session_id,
            )
            .await;
        });
        {
            let mut command_guard = command.lock().await;
            command_guard.task = Some(task);
        }
        gate.notify_one();
        // Bound to our own command: reading "the session's current command" could return
        // a newer command's result id if ours finished in the meantime.
        read_command_state(&self.store, session, &command, wait, max_bytes, cursor).await
    }

    async fn persist_admission(
        &self,
        host: &Host,
        result_id: &str,
        command: &Arc<AsyncMutex<Command>>,
        progress: Option<&dyn crate::storage::journal::ProgressSink>,
    ) -> BridgeResult<()> {
        // No worker is started until both mappings exist; without them a crash
        // could leave a result nobody can address.
        if let Some(progress) = progress {
            if let Err(error) = progress.record(
                "execution_results",
                json!({"host": host.name, "result_id": result_id}),
            ) {
                self.reject_admission(command, "request progress could not be persisted", &error)
                    .await;
                return Err(error);
            }
        }
        if let Err(error) = self.save().await {
            self.reject_admission(command, "terminal registry could not be saved", &error)
                .await;
            return Err(error);
        }
        Ok(())
    }

    async fn reject_admission(
        &self,
        command: &Arc<AsyncMutex<Command>>,
        reason: &str,
        error: &BridgeError,
    ) {
        let mut guard = command.lock().await;
        if guard.state != CmdState::Queued {
            // An explicit close that published first keeps its verdict.
            return;
        }
        guard.state = CmdState::NotStarted;
        guard.error = Some(format!("{reason}: {}", error.message()));
        guard
            .rejection
            .insert("failure_stage".into(), json!("sender"));
        // Keep the failed command attached until a successful admission replaces it.
        // The command lock serializes publication with readers and that replacement.
        if let Err(persist_error) = guard.persist_verdict(&self.store, None) {
            tracing::warn!(result_id = %guard.result_id, %persist_error, "could not save terminal admission failure");
        }
    }

    pub async fn read(
        &self,
        session: &str,
        wait_ms: u64,
        max_bytes: usize,
        cursor: Option<&Value>,
    ) -> BridgeResult<Value> {
        self.read_with_wait(session, ReadWait::Output(wait_ms), max_bytes, cursor)
            .await
    }

    pub(crate) async fn read_with_wait(
        &self,
        session: &str,
        wait: ReadWait,
        max_bytes: usize,
        cursor: Option<&Value>,
    ) -> BridgeResult<Value> {
        let binding = self.binding(session).await?;
        if binding.lock().await.shell.is_closing() {
            binding.lock().await.shell.mark_lost();
        }
        let (command, closed, lost) = {
            let binding = binding.lock().await;
            (
                binding.command.clone(),
                binding.closed,
                binding.shell.is_closing(),
            )
        };
        let Some(command) = command else {
            return Ok(json!({
                "ok": true, "session": session,
                "state": if closed { "closed" } else { "idle" },
            }));
        };
        let _ = lost;
        self.read_command(session, &command, wait, max_bytes, cursor)
            .await
    }

    /// Read a command by its immutable ID, including after replacement or restart.
    /// This uses the same retained output access as read_result.
    pub async fn read_result(
        &self,
        session: &str,
        result_id: &str,
        wait_ms: u64,
        max_bytes: usize,
        cursor: Option<&Value>,
    ) -> BridgeResult<Value> {
        self.read_result_with_wait(
            session,
            result_id,
            ReadWait::Output(wait_ms),
            max_bytes,
            cursor,
        )
        .await
    }

    pub(crate) async fn read_result_with_wait(
        &self,
        session: &str,
        result_id: &str,
        wait: ReadWait,
        max_bytes: usize,
        cursor: Option<&Value>,
    ) -> BridgeResult<Value> {
        let explicit = json!({});
        let cursor = cursor.or(Some(&explicit));
        let binding = self.bindings.lock().await.get(session).cloned();
        if let Some(binding) = binding {
            let command = binding.lock().await.command.clone();
            if let Some(command) = command {
                // Retain this exact Arc across the wait, never re-lookup session.current.
                if command.lock().await.result_id == result_id {
                    terminal_result_metadata(&self.store, session, result_id)?;
                    return self
                        .read_command(session, &command, wait, max_bytes, cursor)
                        .await;
                }
            }
        }
        read_saved_terminal_result(&self.store, session, result_id, max_bytes, cursor)
    }

    /// Read one specific command's output, independent of what the session does next.
    async fn read_command(
        &self,
        session: &str,
        command: &Arc<AsyncMutex<Command>>,
        wait: ReadWait,
        max_bytes: usize,
        cursor: Option<&Value>,
    ) -> BridgeResult<Value> {
        read_command_state(&self.store, session, command, wait, max_bytes, cursor).await
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ReadWait {
    Output(u64),
    Completed(u64),
    Completion(Instant),
}

/// The read path as a free function: it only needs the store and the command, which
/// also makes the "does it block the worker" property testable.
async fn read_command_state(
    store: &ResultStore,
    session: &str,
    command: &Arc<AsyncMutex<Command>>,
    wait: ReadWait,
    max_bytes: usize,
    cursor: Option<&Value>,
) -> BridgeResult<Value> {
    let mut guard = command.lock().await;
    let mut positions = if cursor.is_some() {
        terminal_positions(cursor)
    } else {
        guard.cursor.clone()
    };
    {
        // The result id is copied out so the helper never borrows the lock guard.
        let result_id = guard.result_id.clone();
        let has_output = |store: &ResultStore, positions: &HashMap<String, u64>| -> bool {
            ["stdout", "stderr"].iter().any(|stream| {
                store
                    .path(&result_id, stream)
                    .ok()
                    .and_then(|path| std::fs::metadata(path).ok())
                    .map(|meta| meta.len() > positions.get(*stream).copied().unwrap_or(0))
                    .unwrap_or(false)
            })
        };
        let (deadline, stop_on_output) = match wait {
            ReadWait::Output(ms) => (Instant::now() + Duration::from_millis(ms.min(30_000)), true),
            ReadWait::Completed(ms) => (
                Instant::now() + Duration::from_millis(ms.min(30_000)),
                false,
            ),
            ReadWait::Completion(deadline) => (deadline, false),
        };
        if guard.is_busy() {
            let changed = guard.changed.clone();
            loop {
                // Subscribe while holding the lock, before checking the state, so a
                // completion or output notification cannot be lost between the check
                // and the wait. Release the lock before awaiting the worker.
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !guard.is_busy()
                    || (stop_on_output && has_output(store, &positions))
                    || remaining.is_zero()
                {
                    break;
                }
                drop(guard);
                let _ = tokio::time::timeout(remaining, &mut notified).await;
                guard = command.lock().await;
            }
        }
        let mut out = Map::new();
        out.insert("ok".into(), Value::Bool(true));
        out.insert("session".into(), Value::from(session));
        out.insert("result_id".into(), Value::from(guard.result_id.clone()));
        out.insert("state".into(), Value::from(guard.state.as_str()));
        append_terminal_page(store, &guard.result_id, max_bytes, &mut positions, &mut out)?;
        if cursor.is_none() {
            guard.cursor = positions;
        }
        if !guard.is_busy() {
            out.extend(guard.evidence());
        }
        Ok(Value::Object(out))
    }
}

fn terminal_positions(cursor: Option<&Value>) -> HashMap<String, u64> {
    ["stdout", "stderr"]
        .into_iter()
        .filter_map(|stream| {
            cursor?
                .get(stream)?
                .as_u64()
                .map(|offset| (stream.to_string(), offset))
        })
        .collect()
}

fn append_terminal_page(
    store: &ResultStore,
    result_id: &str,
    max_bytes: usize,
    positions: &mut HashMap<String, u64>,
    out: &mut Map<String, Value>,
) -> BridgeResult<()> {
    let mut budget = max_bytes;
    for stream in ["stderr", "stdout"] {
        let path = store.path(result_id, stream)?;
        let size = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
        let position = positions.get(stream).copied().unwrap_or(0);
        let limit = (budget as u64).min(size.saturating_sub(position));
        if limit > 0 {
            let page = store.read(result_id, stream, position, limit as usize, false, None)?;
            let text = page.get("text").and_then(Value::as_str).unwrap_or("");
            out.insert(stream.to_string(), Value::from(text));
            let next = page
                .get("next_offset")
                .and_then(Value::as_u64)
                .unwrap_or(position);
            positions.insert(stream.to_string(), next);
            budget = budget.saturating_sub(text.len());
        }
        if positions.get(stream).copied().unwrap_or(0) < size {
            out.insert("more".into(), Value::Bool(true));
        }
    }
    out.insert("cursor".into(), json!(positions));
    Ok(())
}

fn terminal_result_metadata(
    store: &ResultStore,
    session: &str,
    result_id: &str,
) -> BridgeResult<Map<String, Value>> {
    let meta = store.metadata(result_id)?;
    if meta.get("kind").and_then(Value::as_str) != Some("terminal")
        || meta.get("session_id").and_then(Value::as_str) != Some(session)
    {
        return Err(BridgeError::invalid(
            "result is not a command for this terminal session",
        ));
    }
    Ok(meta)
}

fn read_saved_terminal_result(
    store: &ResultStore,
    session: &str,
    result_id: &str,
    max_bytes: usize,
    cursor: Option<&Value>,
) -> BridgeResult<Value> {
    let meta = terminal_result_metadata(store, session, result_id)?;
    let state = match meta.get("execution_state").and_then(Value::as_str) {
        Some(state @ ("completed" | "not_started" | "unknown")) => state,
        _ => "unknown",
    };
    let mut result = json!({
        "session": session, "result_id": result_id, "state": state,
        "ok": state == "completed" && meta.get("ok").and_then(Value::as_bool) == Some(true),
        "completion_unknown": state == "unknown",
    });
    let out = result.as_object_mut().expect("object");
    for key in [
        "exit_code",
        "executed",
        "error",
        "failure_stage",
        "reason",
        "retryable",
        "queue",
        "queue_timed_out",
    ] {
        if let Some(value) = meta.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    let mut positions = terminal_positions(cursor);
    append_terminal_page(store, result_id, max_bytes, &mut positions, out)?;
    Ok(result)
}

impl Interactive {
    pub async fn write(
        &self,
        session: &str,
        input: Option<&str>,
        signal: Option<&str>,
        eof: bool,
        allow_dangerous: bool,
        wait_ms: u64,
        max_bytes: usize,
        cursor: Option<&Value>,
    ) -> BridgeResult<Value> {
        self.write_with_wait(
            session,
            input,
            signal,
            eof,
            allow_dangerous,
            ReadWait::Output(wait_ms),
            max_bytes,
            cursor,
        )
        .await
    }

    pub(crate) async fn write_with_wait(
        &self,
        session: &str,
        input: Option<&str>,
        signal: Option<&str>,
        eof: bool,
        allow_dangerous: bool,
        wait: ReadWait,
        max_bytes: usize,
        cursor: Option<&Value>,
    ) -> BridgeResult<Value> {
        let binding = self.binding(session).await?;
        let guard = binding.lock().await;
        self.permitted(&guard).await?;
        drop(guard);
        let count = usize::from(input.is_some()) + usize::from(signal.is_some()) + usize::from(eof);
        if count != 1 {
            return Err(BridgeError::invalid(
                "provide exactly one of input, signal or eof=true",
            ));
        }
        let (command, shell) = {
            let binding = binding.lock().await;
            (binding.command.clone(), binding.shell.clone())
        };
        let Some(command) = command else {
            return Err(BridgeError::invalid(
                "write needs an active foreground command; use exec for shell commands",
            ));
        };
        {
            let guard = command.lock().await;
            if shell.is_closing() {
                return Err(BridgeError::invalid(
                    "terminal shell was closed/lost; open a new session explicitly",
                ));
            }
            if !guard.is_busy() || guard.state != CmdState::Running {
                return Err(BridgeError::invalid(
                    "write needs an active foreground command; use exec for shell commands",
                ));
            }
        }
        if let Some(input) = input {
            self.check(input, allow_dangerous)?;
            shell.write_input(input).await?;
        } else if let Some(signal) = signal {
            shell.send_signal(signal).await?;
        } else {
            shell.write_eof().await;
        }
        // Observe the same command selected for the input even if the session
        // acquires a new foreground command before this read.
        let mut out = self
            .read_command(session, &command, wait, max_bytes, cursor)
            .await?;
        if let Some(map) = out.as_object_mut() {
            map.insert("input_sent".into(), Value::Bool(true));
        }
        Ok(out)
    }

    pub async fn close(&self, session: &str) -> BridgeResult<Value> {
        if self
            .lost
            .lock()
            .expect("lost lock")
            .remove(session)
            .is_some()
        {
            self.save().await?;
            return Ok(json!({"ok": true, "session": session, "state": "closed"}));
        }
        let binding = self.binding(session).await?;
        let (shell, command) = {
            let mut guard = binding.lock().await;
            guard.closed = true;
            guard.shell.mark_lost();
            (guard.shell.clone(), guard.command.clone())
        };
        let verdict = if let Some(command) = command {
            let mut guard = command.lock().await;
            if let Some(task) = guard.task.take() {
                if !task.is_finished() {
                    task.abort();
                }
            }
            // Closing is an explicit state transition: a queued command never ran, a
            // running one has no completion evidence, and a finished one keeps its
            // verdict. Without this the saved result would stay `running` forever.
            let final_state = close_final_state(guard.state);
            if let Some((state, failure_stage)) = final_state {
                guard.state = state;
                guard.error =
                    Some("terminal closed by the caller before the command finished".into());
                guard
                    .rejection
                    .insert("failure_stage".into(), json!(failure_stage));
                guard.persist_verdict(&self.store, None)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        };
        // Closing the old channel must still happen if the result store is down.
        shell.close().await;
        verdict?;
        self.bindings.lock().await.remove(session);
        self.save().await?;
        Ok(json!({"ok": true, "session": session, "state": "closed"}))
    }

    /// Close every shell before shutdown, leaving recovery records behind.
    pub async fn close_all(&self) {
        let sessions: Vec<String> = self.bindings.lock().await.keys().cloned().collect();
        for session in sessions {
            let _ = self.close(&session).await;
        }
        let _ = self.save().await;
    }

    pub async fn sessions(&self) -> Value {
        let mut rows: Vec<Value> = Vec::new();
        for (session, binding) in self.bindings.lock().await.iter() {
            let binding = binding.lock().await;
            // A shell with a command in flight is "running", not "idle": the state
            // shown here is what an operator uses to decide whether to reuse it.
            let busy = match &binding.command {
                Some(command) => command.try_lock().map(|c| c.is_busy()).unwrap_or(true),
                None => false,
            };
            rows.push(json!({
                "session": session,
                "host": binding.host.name,
                "asset_id": binding.host.asset_id,
                "state": if binding.closed { "closed" } else if binding.shell.is_closing() { "lost" } else if busy { "running" } else { "idle" },
            }));
        }
        json!({"sessions": rows})
    }
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Runs the command on the bound shell and records the durable outcome.
async fn run_terminal_command(
    runner: Arc<Runner>,
    store: Arc<ResultStore>,
    host: Host,
    shell: Arc<TerminalShell>,
    command: Arc<AsyncMutex<Command>>,
    script: String,
    _session: String,
) -> BridgeResult<()> {
    let key = host.connection_key()?;
    let _lease = match runner.recovery.enter(&key, runner.queue_timeout).await {
        Ok(lease) => lease,
        Err(error) => {
            let mut guard = command.lock().await;
            if guard.state == CmdState::Queued {
                guard.state = CmdState::NotStarted;
                guard.error = Some(error.message());
                guard.persist_verdict(&store, None)?;
            }
            return Ok(());
        }
    };
    let mut timings = Timings::default();
    let slot = runner
        .scheduler
        .acquire(
            Lane::General,
            Duration::from_secs_f64(runner.queue_timeout),
            &mut timings,
        )
        .await;
    // Keep the lease through command completion, even if the reader observes EOF
    // and releases the shell protection while we are recording an unknown result.
    let slot = match slot {
        Ok(slot) => slot,
        Err(wait) => {
            let mut guard = command.lock().await;
            persist_queue_rejection(&mut guard, &store, wait, &timings)?;
            return Ok(());
        }
    };
    // Commit to sending under the command lock only after scheduler admission
    // and checking the shell. The send itself cannot hold the lock across await.
    let plan = CommandPlan::new(&script);
    let (result_id, changed, started) = {
        let mut guard = command.lock().await;
        if !try_take_over(&mut guard, shell.is_closing(), &store) {
            return Ok(());
        }
        (
            guard.result_id.clone(),
            guard.changed.clone(),
            guard.started.clone(),
        )
    };
    if !send_terminal_packet(
        &shell,
        &command,
        &store,
        &plan.packet,
        Duration::from_secs(120),
        &timings,
    )
    .await?
    {
        return Ok(());
    }
    let out_path = store.path(&result_id, "stdout")?;
    let err_path = store.path(&result_id, "stderr")?;
    let outcome = shell
        .capture_after_send(
            &plan,
            &out_path,
            &err_path,
            &started,
            &changed,
            Duration::from_secs(86_400),
        )
        .await;
    let mut guard = command.lock().await;
    // A caller close that published first owns the verdict.
    if guard.state != CmdState::Running {
        return Ok(());
    }
    match outcome {
        Ok(code) => {
            guard.state = CmdState::Completed;
            guard.exit_code = Some(code);
        }
        Err(error) => {
            guard.state = if guard.sent {
                CmdState::Unknown
            } else {
                CmdState::NotStarted
            };
            guard.error = Some(error.message());
            if guard.sent {
                shell.mark_lost();
                shell.close().await;
            }
        }
    }
    guard.persist_verdict(&store, Some(&timings))?;
    drop(guard);
    drop(slot);
    Ok(())
}

fn persist_queue_rejection(
    guard: &mut Command,
    store: &ResultStore,
    wait: SlotWait,
    timings: &Timings,
) -> BridgeResult<()> {
    if guard.state != CmdState::Queued {
        return Ok(());
    }
    guard.state = CmdState::NotStarted;
    match wait {
        SlotWait::Full(full) => {
            guard.error = Some(full.message());
            guard.rejection = full.response();
            guard
                .rejection
                .insert("failure_stage".into(), json!("execution_queue"));
            guard
                .rejection
                .insert("queue_timed_out".into(), json!(false));
        }
        SlotWait::Timeout(timeout) => {
            guard.error = Some(timeout.message());
            guard
                .rejection
                .insert("failure_stage".into(), json!(timeout.stage));
            guard
                .rejection
                .insert("queue_timed_out".into(), json!(true));
        }
    }
    guard.persist_verdict(store, Some(timings))
}

async fn send_terminal_packet(
    shell: &TerminalShell,
    command: &AsyncMutex<Command>,
    store: &ResultStore,
    packet: &[u8],
    timeout: Duration,
    timings: &Timings,
) -> BridgeResult<bool> {
    // Do not hold the command lock across the write; caller close may abort it.
    let error = match tokio::time::timeout(timeout, shell.send_packet(packet)).await {
        Ok(Ok(())) => return Ok(true),
        Ok(Err(error)) => format!(
            "the command could not be written completely: {}",
            error.message()
        ),
        Err(_) => "writing the command to the terminal timed out".to_string(),
    };
    // A prefix may be buffered in the remote parser. Never admit another command to
    // this shell once the current command can be observed as no longer busy.
    shell.mark_lost();
    let persisted = {
        let mut guard = command.lock().await;
        if guard.state == CmdState::Running {
            // An incomplete write is not START evidence. Caller close, if it won,
            // still owns the verdict.
            guard.state = CmdState::Unknown;
            guard.error = Some(error);
            guard
                .rejection
                .insert("failure_stage".into(), json!("channel"));
            guard.persist_verdict(store, Some(timings))
        } else {
            Ok(())
        }
    };
    // Close even if recording the verdict fails. The binding remains readable.
    shell.close().await;
    persisted.map(|()| false)
}

/// Evidence copied from a finished terminal command into fan-out style rows.
pub fn command_rejection(meta: &Map<String, Value>) -> Map<String, Value> {
    queue_rejection(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn terminal_with_stalled_writer(
        directory: &std::path::Path,
        prefix_len: usize,
    ) -> (Interactive, Host, mpsc::Receiver<Option<Bytes>>) {
        use crate::config::{BastionConfig, BridgeSettings};
        use sha2::{Digest, Sha256};

        let settings = Arc::new(BridgeSettings {
            state_dir: directory.to_path_buf(),
            ..BridgeSettings::default()
        });
        let cfg = Arc::new(BastionConfig::default());
        let mut identity_parts = cfg.credential_identity();
        identity_parts.push(settings.preferred_account.clone());
        atomic_json(
            &directory.join("assets.json"),
            &json!({
                "identity": hex::encode(Sha256::digest(serde_json::to_vec(&identity_parts).unwrap())),
                "refreshed_at": crate::storage::results::now(),
                "assets": [{
                    "id":"11111111-1111-1111-1111-111111111111", "name":"test-host",
                    "active":true, "protocols":["ssh"], "login":"test", "account":"test"
                }],
            }),
        )
        .unwrap();
        let store = Arc::new(ResultStore::new(directory.join("results"), 3600.0, 3600.0).unwrap());
        let catalog = AssetCatalog::new(cfg.clone(), settings.clone()).unwrap();
        let runner = Runner::new(cfg, settings, store.clone()).unwrap();
        let host = catalog.inventory().hosts.pop().unwrap();
        let protection = Arc::new(runner.protect_terminal(&host.connection_key().unwrap()));
        let (frames, writer) = ChannelWriter::mock_stalled(prefix_len);
        let stream = || StreamSource {
            receiver: mpsc::channel(1).1,
            buffer: Vec::new(),
            closed: false,
        };
        let shell = Arc::new(TerminalShell {
            writer,
            streams: AsyncMutex::new(Streams {
                out: stream(),
                err: stream(),
            }),
            lost: Arc::new(AtomicBool::new(false)),
            protection,
            demux: Mutex::new(None),
        });
        let interactive = Interactive::new(catalog, runner, store);
        interactive.bindings.lock().await.insert(
            "s".into(),
            Arc::new(AsyncMutex::new(Binding {
                session: "s".into(),
                host: host.clone(),
                shell,
                command: None,
                closed: false,
            })),
        );
        (interactive, host, frames)
    }

    fn test_command(store: &ResultStore, kind: &str, session: &str, bytes: &[u8]) -> String {
        let id = store
            .create(
                json!({"kind": kind, "session_id": session})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap();
        std::fs::write(store.path(&id, "stdout").unwrap(), bytes).unwrap();
        id
    }

    #[test]
    fn retained_terminal_pages_are_bound_to_the_original_session_and_command() {
        let dir = tempfile::tempdir().unwrap();
        let result_id = {
            let store = ResultStore::new(dir.path().to_path_buf(), 3600.0, 3600.0).unwrap();
            let a = test_command(&store, "terminal", "s", b"abcdef");
            let b = test_command(&store, "terminal", "s", b"second command");
            let ordinary = test_command(&store, "run", "s", b"not a terminal");
            store
                .finish(
                    &a,
                    json!({"execution_state":"completed","exit_code":7,"ok":false})
                        .as_object()
                        .unwrap()
                        .clone(),
                )
                .unwrap();
            let page = read_saved_terminal_result(&store, "s", &a, 3, None).unwrap();
            assert_eq!(page["result_id"], a);
            assert_eq!(page["stdout"], "abc");
            assert_eq!(page["state"], "completed");
            assert_eq!(page["exit_code"], 7);
            assert_eq!(page["ok"], false);
            assert_eq!(page["more"], true);
            assert!(read_saved_terminal_result(&store, "wrong", &a, 8, None).is_err());
            assert!(read_saved_terminal_result(&store, "s", &ordinary, 8, None).is_err());
            assert_eq!(
                read_saved_terminal_result(&store, "s", &b, 16, None).unwrap()["state"],
                "unknown"
            );
            a
        };
        // New store instance; no live Session/Command needed for output.
        let store = ResultStore::new(dir.path().to_path_buf(), 3600.0, 3600.0).unwrap();
        let page =
            read_saved_terminal_result(&store, "s", &result_id, 3, Some(&json!({"stdout":3})))
                .unwrap();
        assert_eq!(page["stdout"], "def");
        std::fs::remove_file(store.directory(&result_id).unwrap().join("meta.json")).unwrap();
        assert!(read_saved_terminal_result(&store, "s", &result_id, 3, None).is_err());
    }

    #[tokio::test]
    async fn explicit_cursors_do_not_advance_or_rewind_implicit_terminal_reads() {
        let dir = tempfile::tempdir().unwrap();
        let store = ResultStore::new(dir.path().to_path_buf(), 3600.0, 3600.0).unwrap();
        let id = test_command(&store, "terminal", "s", b"abcdef");
        let command = Arc::new(AsyncMutex::new(Command::new(id)));
        let wait = ReadWait::Output(0);
        assert_eq!(
            read_command_state(&store, "s", &command, wait, 2, None)
                .await
                .unwrap()["stdout"],
            "ab"
        );
        for (offset, expected) in [(0, "ab"), (4, "ef"), (0, "ab")] {
            let page = read_command_state(
                &store,
                "s",
                &command,
                wait,
                2,
                Some(&json!({"stdout":offset})),
            )
            .await
            .unwrap();
            assert_eq!(page["stdout"], expected);
        }
        assert_eq!(
            read_command_state(&store, "s", &command, wait, 2, None)
                .await
                .unwrap()["stdout"],
            "cd"
        );
    }

    #[test]
    fn a_closed_stream_without_its_marker_ends_the_command() {
        // START then Close: neither stream ever produced an end marker.
        assert!(completion_impossible(true, false, true, false));
        // One END then Close: the other stream will never report.
        assert!(completion_impossible(true, true, true, false));
        // A stream that ended *with* its marker is not the problem: keep waiting for
        // the stream that is still open.
        assert!(!completion_impossible(false, false, true, true));
        assert!(!completion_impossible(true, true, false, false));
        // Both markers arrived: completion is decided by the codes, not by closure.
        assert!(!completion_impossible(true, true, true, true));
        // Still open on both sides: keep waiting.
        assert!(!completion_impossible(false, false, false, false));
    }

    /// A long-poll read must not hold the command lock: the worker needs it to publish
    /// `running` and to write output, so holding it would make a queued command wait for
    /// the whole poll window even with a slot available.
    #[tokio::test]
    async fn a_long_poll_read_does_not_block_the_worker() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            crate::storage::results::ResultStore::new(
                directory.path().to_path_buf(),
                3600.0,
                3600.0,
            )
            .unwrap(),
        );
        let result_id = store
            .create(
                json!({"kind": "terminal"})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            )
            .unwrap();
        let command = Arc::new(AsyncMutex::new(Command::new(result_id)));

        // The read starts while the command is queued and produces no output yet.
        let reader = {
            let store = store.clone();
            let command = command.clone();
            tokio::spawn(async move {
                read_command_state(&store, "s1", &command, ReadWait::Output(5_000), 4096, None)
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;

        // The worker side must get the lock immediately.
        let started = Instant::now();
        let mut guard = command.lock().await;
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_millis(100),
            "the reader held the command lock for {waited:?}"
        );
        guard.state = CmdState::Completed;
        guard.exit_code = Some(0);
        guard.changed.notify_waiters();
        drop(guard);

        let page = tokio::time::timeout(Duration::from_secs(2), reader)
            .await
            .expect("the read must return once the command finishes")
            .unwrap()
            .unwrap();
        assert_eq!(page["session"], "s1");
        assert_eq!(page["state"], "completed");
    }

    #[tokio::test]
    async fn a_long_poll_returns_when_a_prompt_arrives() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            Arc::new(ResultStore::new(directory.path().to_path_buf(), 3600.0, 3600.0).unwrap());
        let result_id = store.create(Map::new()).unwrap();
        let command = Arc::new(AsyncMutex::new(Command::new(result_id.clone())));
        let producer = {
            let store = store.clone();
            let command = command.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                std::fs::write(store.path(&result_id, "stdout").unwrap(), b"Input?").unwrap();
                command.lock().await.changed.notify_waiters();
            })
        };
        let page = tokio::time::timeout(
            Duration::from_secs(1),
            read_command_state(&store, "s1", &command, ReadWait::Output(5_000), 4096, None),
        )
        .await
        .expect("prompt should wake reader promptly")
        .unwrap();
        producer.await.unwrap();
        assert_eq!(page["stdout"], "Input?");
        assert_eq!(page["state"], "queued");
    }

    #[tokio::test]
    async fn setup_waits_past_output_for_a_separate_completion_event() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            Arc::new(ResultStore::new(directory.path().to_path_buf(), 3600.0, 3600.0).unwrap());
        let result_id = store.create(Map::new()).unwrap();
        let command = Arc::new(AsyncMutex::new(Command::new(result_id.clone())));
        let (events, mut input) = mpsc::channel(2);
        let (observed, initial_output) = tokio::sync::oneshot::channel();
        let producer = {
            let store = store.clone();
            let command = command.clone();
            tokio::spawn(async move {
                let output = input.recv().await.unwrap();
                std::fs::write(store.path(&result_id, "stdout").unwrap(), output).unwrap();
                command.lock().await.changed.notify_waiters();
                observed.send(()).unwrap();
                assert_eq!(input.recv().await, Some(b"<end>".as_slice()));
                let mut guard = command.lock().await;
                guard.state = CmdState::Completed;
                guard.exit_code = Some(0);
                guard.changed.notify_waiters();
            })
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut setup = Box::pin(read_command_state(
            &store,
            "s1",
            &command,
            ReadWait::Completion(deadline),
            4096,
            None,
        ));
        events.send(b"init warning".as_slice()).await.unwrap();
        tokio::select! {
            _ = initial_output => {}
            result = &mut setup => panic!("returned before observing setup output: {result:?}"),
        }
        assert!(futures::poll!(setup.as_mut()).is_pending());
        events.send(b"<end>".as_slice()).await.unwrap();
        let page = setup.await.unwrap();
        assert_eq!(page["state"], "completed");
        assert_eq!(page["exit_code"], 0);
        assert_eq!(page["stdout"], "init warning");
        producer.await.unwrap();
    }

    #[tokio::test]
    async fn completed_wait_keeps_the_command_and_unread_backlog() {
        let directory = tempfile::tempdir().unwrap();
        let store = ResultStore::new(directory.path().to_path_buf(), 3600.0, 3600.0).unwrap();
        let result_id = store.create(Map::new()).unwrap();
        let command = Arc::new(AsyncMutex::new(Command::new(result_id.clone())));
        let out_path = store.path(&result_id, "stdout").unwrap();
        std::fs::write(&out_path, b"prompt").unwrap();
        {
            let mut guard = command.lock().await;
            guard.state = CmdState::Running;
        }

        // Both zero and positive deadlines expose the same bounded page without
        // changing the state; output is not itself a completion event.
        let zero = read_command_state(
            &store,
            "s",
            &command,
            ReadWait::Completed(0),
            3,
            Some(&json!({})),
        )
        .await
        .unwrap();
        assert_eq!(zero["state"], "running");
        assert_eq!(zero["result_id"], result_id);
        assert_eq!(zero["stdout"], "pro");
        assert_eq!(zero["more"], true);

        let cursor = zero["cursor"].clone();
        let deadline = read_command_state(
            &store,
            "s",
            &command,
            ReadWait::Completed(20),
            3,
            Some(&cursor),
        )
        .await
        .unwrap();
        assert_eq!(deadline["state"], "running");
        assert_eq!(deadline["stdout"], "mpt");

        let cursor = deadline["cursor"].clone();
        let mut waiter = Box::pin(read_command_state(
            &store,
            "s",
            &command,
            ReadWait::Completed(1_000),
            4,
            Some(&cursor),
        ));
        assert!(futures::poll!(waiter.as_mut()).is_pending());
        std::fs::write(&out_path, b"promptabcdefgh").unwrap();
        command.lock().await.changed.notify_waiters();
        assert!(futures::poll!(waiter.as_mut()).is_pending());
        {
            let mut guard = command.lock().await;
            guard.state = CmdState::Completed;
            guard.exit_code = Some(0);
            guard.persist_verdict(&store, None).unwrap();
        }
        let page = waiter.await.unwrap();
        assert_eq!(page["state"], "completed");
        assert_eq!(page["exit_code"], 0);
        assert_eq!(page["result_id"], result_id);
        assert_eq!(page["stdout"], "abcd");
        assert_eq!(page["more"], true);
        let rest = read_command_state(
            &store,
            "s",
            &command,
            ReadWait::Completed(0),
            4,
            Some(&page["cursor"]),
        )
        .await
        .unwrap();
        assert_eq!(rest["stdout"], "efgh");
    }

    #[tokio::test]
    async fn completed_wait_observes_unsent_failure_without_waiting_for_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let store = ResultStore::new(directory.path().to_path_buf(), 3600.0, 3600.0).unwrap();
        let result_id = store.create(Map::new()).unwrap();
        let command = Arc::new(AsyncMutex::new(Command::new(result_id.clone())));
        let mut waiter = Box::pin(read_command_state(
            &store,
            "s",
            &command,
            ReadWait::Completed(30_000),
            4,
            None,
        ));
        assert!(futures::poll!(waiter.as_mut()).is_pending());
        {
            let mut guard = command.lock().await;
            assert!(!try_take_over(&mut guard, true, &store));
        }
        let page = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(page["state"], "not_started");
        assert_eq!(page["result_id"], result_id);
        assert_eq!(page["executed"], false);
    }

    #[tokio::test]
    async fn disconnect_while_queued_is_unsent_in_live_and_durable_results() {
        let directory = tempfile::tempdir().unwrap();
        let store = ResultStore::new(directory.path().to_path_buf(), 3600.0, 3600.0).unwrap();
        let result_id = store.create(Map::new()).unwrap();
        let command = Arc::new(AsyncMutex::new(Command::new(result_id.clone())));
        {
            let mut guard = command.lock().await;
            assert!(!try_take_over(&mut guard, true, &store));
            assert!(!guard.sent);
        }
        let live = read_command_state(&store, "s1", &command, ReadWait::Output(0), 4096, None)
            .await
            .unwrap();
        let durable = store.metadata(&result_id).unwrap();
        assert_eq!(live["state"], "not_started");
        assert_eq!(durable["execution_state"], live["state"]);
        assert_eq!(durable["executed"], live["executed"]);
        assert_eq!(durable["completion_unknown"], live["completion_unknown"]);
        assert_eq!(live["executed"], false);
    }

    #[tokio::test]
    async fn ssh_eof_closes_terminal_output_queues_without_waiting_for_channel_close() {
        let (out_tx, mut out_rx) = mpsc::channel(4);
        let (err_tx, mut err_rx) = mpsc::channel(4);
        let lost = AtomicBool::new(false);
        let events = futures::stream::iter([
            ShellEvent::Data(Bytes::from_static(b"stdout marker")),
            ShellEvent::ExtData(Bytes::from_static(b"stderr marker")),
            ShellEvent::Eof,
        ])
        .chain(futures::stream::pending());
        tokio::time::timeout(
            Duration::from_secs(1),
            demux_terminal_output(events, out_tx, err_tx, || {
                lost.store(true, Ordering::SeqCst)
            }),
        )
        .await
        .expect("EOF should terminate terminal capture before channel close");
        assert!(lost.load(Ordering::SeqCst));
        assert_eq!(out_rx.recv().await.unwrap(), "stdout marker");
        assert_eq!(err_rx.recv().await.unwrap(), "stderr marker");
        assert_eq!(out_rx.recv().await, None);
        assert_eq!(err_rx.recv().await, None);
    }

    #[tokio::test]
    async fn a_long_poll_times_out_without_output() {
        let directory = tempfile::tempdir().unwrap();
        let store = ResultStore::new(directory.path().to_path_buf(), 3600.0, 3600.0).unwrap();
        let result_id = store.create(Map::new()).unwrap();
        let command = Arc::new(AsyncMutex::new(Command::new(result_id)));
        let started = Instant::now();
        let page = tokio::time::timeout(
            Duration::from_secs(1),
            read_command_state(&store, "s1", &command, ReadWait::Output(50), 4096, None),
        )
        .await
        .expect("bounded wait must return")
        .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert_eq!(page["state"], "queued");
    }

    /// The close/worker race, stated as a state machine: whoever gets the lock first
    /// decides, and the loser never sends and never overwrites the verdict.
    #[tokio::test]
    async fn closing_before_the_worker_takes_over_sends_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let store = ResultStore::new(directory.path().to_path_buf(), 3600.0, 3600.0).unwrap();
        let command = Arc::new(AsyncMutex::new(Command::new("r1".to_string())));

        // `close` wins: it finalises the queued command as not_started.
        {
            let mut guard = command.lock().await;
            let (state, stage) =
                close_final_state(guard.state).expect("queued command is finalised");
            guard.state = state;
            assert_eq!(stage, "not_started");
            assert_eq!(guard.evidence()["executed"], false);
        }
        // The worker then reaches its takeover and must refuse.
        {
            let mut guard = command.lock().await;
            assert!(!try_take_over(&mut guard, false, &store));
            assert_eq!(guard.state, CmdState::NotStarted);
            assert!(!guard.sent, "a closed command must never be marked sent");
        }
    }

    #[tokio::test]
    async fn a_worker_that_took_over_first_is_reported_as_unknown_when_closed() {
        let directory = tempfile::tempdir().unwrap();
        let store = ResultStore::new(directory.path().to_path_buf(), 3600.0, 3600.0).unwrap();
        let command = Arc::new(AsyncMutex::new(Command::new("r2".to_string())));
        {
            let mut guard = command.lock().await;
            assert!(try_take_over(&mut guard, false, &store));
            assert_eq!(guard.state, CmdState::Running);
            assert!(guard.sent);
        }
        let mut guard = command.lock().await;
        let (state, stage) = close_final_state(guard.state).expect("running command is finalised");
        guard.state = state;
        assert_eq!(stage, "closed_by_caller");
        assert_eq!(guard.evidence()["executed"], Value::Null);
        assert_eq!(guard.evidence()["completion_unknown"], true);
        guard.started.store(true, Ordering::SeqCst);
        assert_eq!(guard.evidence()["executed"], true);
    }

    #[tokio::test]
    async fn stalled_partial_send_closes_the_channel_without_replacing_its_result() {
        let dir = tempfile::tempdir().unwrap();
        let (interactive, _, mut frames) = terminal_with_stalled_writer(dir.path(), 6).await;
        let store = &interactive.store;
        let id = test_command(store, "terminal", "s", b"");
        let command = Arc::new(AsyncMutex::new(Command::new(id.clone())));
        let binding = interactive.binding("s").await.unwrap();
        let shell = {
            let mut binding = binding.lock().await;
            binding.command = Some(command.clone());
            binding.shell.clone()
        };
        interactive.save().await.unwrap();
        {
            let mut guard = command.lock().await;
            assert!(try_take_over(&mut guard, shell.is_closing(), store));
        }
        let plan = CommandPlan::new(":");
        let timings = Timings::default();
        let mut sending = Box::pin(send_terminal_packet(
            &shell,
            &command,
            store,
            &plan.packet,
            Duration::from_millis(50),
            &timings,
        ));
        assert!(futures::poll!(sending.as_mut()).is_pending());
        assert_eq!(frames.try_recv().unwrap().unwrap(), &b"printf"[..]);
        assert!(
            !shell.is_closing(),
            "a stall does not itself flag the writer closed"
        );
        let mut reader = Box::pin(interactive.read("s", 30_000, 4096, None));
        assert!(futures::poll!(reader.as_mut()).is_pending());
        assert!(!sending.await.unwrap());
        assert_eq!(frames.try_recv().unwrap(), None, "old channel was closed");
        let live = tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(live["result_id"], id);
        assert_eq!(live["state"], "unknown");
        assert_eq!(live["executed"], Value::Null);
        assert_eq!(live["completion_unknown"], true);
        assert_eq!(
            live["error"],
            "writing the command to the terminal timed out"
        );
        let refusal = interactive
            .execute("s", ":", false, 0, 4096, None, None)
            .await
            .unwrap_err();
        assert!(refusal.message().contains("closed/lost"));
        assert_eq!(interactive.sessions().await["sessions"][0]["state"], "lost");
        assert_eq!(
            interactive.read("s", 0, 4096, None).await.unwrap()["result_id"],
            id
        );
        assert!(matches!(
            frames.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let archived = read_saved_terminal_result(store, "s", &id, 4096, None).unwrap();
        let restarted = ResultStore::new(store.root.clone(), 3600.0, 3600.0).unwrap();
        let replay = read_saved_terminal_result(&restarted, "s", &id, 4096, None).unwrap();
        for key in [
            "result_id",
            "state",
            "executed",
            "completion_unknown",
            "failure_stage",
            "error",
        ] {
            assert_eq!(live[key], archived[key], "{key}");
            assert_eq!(archived[key], replay[key], "{key}");
        }
    }

    #[tokio::test]
    async fn admission_checks_liveness_after_waiting_on_the_current_command() {
        let dir = tempfile::tempdir().unwrap();
        let (interactive, _, _frames) = terminal_with_stalled_writer(dir.path(), 1).await;
        let binding = interactive.binding("s").await.unwrap();
        let mut binding = binding.lock().await;
        let command = Arc::new(AsyncMutex::new(Command::new("a".into())));
        binding.command = Some(command.clone());
        let mut guard = command.lock().await;
        guard.state = CmdState::Running;
        let mut admission = Box::pin(binding.check_exec_admission());
        assert!(futures::poll!(admission.as_mut()).is_pending());
        binding.shell.mark_lost();
        guard.state = CmdState::Unknown;
        drop(guard);
        assert!(admission
            .await
            .unwrap_err()
            .message()
            .contains("closed/lost"));
    }

    struct FailingProgress;

    impl crate::storage::journal::ProgressSink for FailingProgress {
        fn record(&self, field: &str, value: Value) -> BridgeResult<()> {
            assert_eq!(field, "execution_results");
            assert!(value.get("result_id").and_then(Value::as_str).is_some());
            Err(BridgeError::storage("test receipt write failed"))
        }
    }

    #[tokio::test]
    async fn admission_failures_wake_readers_and_archive_the_same_unsent_verdict() {
        for (progress, phrase) in [
            (None, "terminal registry could not be saved"),
            (
                Some(&FailingProgress as &dyn crate::storage::journal::ProgressSink),
                "request progress could not be persisted",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (interactive, host, mut frames) = terminal_with_stalled_writer(dir.path(), 1).await;
            let id = test_command(&interactive.store, "terminal", "s", b"");
            let command = Arc::new(AsyncMutex::new(Command::new(id.clone())));
            interactive.binding("s").await.unwrap().lock().await.command = Some(command.clone());
            if progress.is_none() {
                std::fs::create_dir(&interactive.registry).unwrap();
            }
            let mut reader = Box::pin(interactive.read("s", 30_000, 4096, None));
            assert!(futures::poll!(reader.as_mut()).is_pending());
            assert!(interactive
                .persist_admission(&host, &id, &command, progress)
                .await
                .is_err());
            let live = tokio::time::timeout(Duration::from_secs(1), reader)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(live["result_id"], id);
            assert_eq!(live["state"], "not_started");
            assert_eq!(live["executed"], false);
            assert_eq!(live["completion_unknown"], false);
            assert_eq!(live["failure_stage"], "sender");
            assert!(live["error"].as_str().unwrap().starts_with(phrase));
            assert_eq!(
                interactive.store.metadata(&id).unwrap()["status"],
                "complete"
            );

            // The terminal can accept a later command, without losing the first failure.
            assert!(interactive
                .execute("s", ":", false, 0, 4096, None, Some(&FailingProgress))
                .await
                .is_err());
            assert_ne!(
                interactive.read("s", 0, 4096, None).await.unwrap()["result_id"],
                id
            );
            let archived = interactive
                .read_result("s", &id, 0, 4096, None)
                .await
                .unwrap();
            for key in [
                "state",
                "executed",
                "completion_unknown",
                "failure_stage",
                "error",
            ] {
                assert_eq!(live[key], archived[key], "{key}");
            }
            assert!(matches!(
                frames.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
    }

    #[tokio::test]
    async fn queue_rejection_is_persisted_before_slot_release_and_survives_archive() {
        let dir = tempfile::tempdir().unwrap();
        let store = ResultStore::new(dir.path().to_path_buf(), 3600.0, 3600.0).unwrap();
        let id = test_command(&store, "terminal", "s", b"");
        let command = Arc::new(AsyncMutex::new(Command::new(id.clone())));
        let scheduler = crate::scheduler::ExecutionSlots::new(1, 0, 0, 0).unwrap();
        let mut timing = Timings::default();
        let active = scheduler
            .acquire(Lane::General, Duration::from_secs(1), &mut timing)
            .await
            .unwrap();
        let rejection = match scheduler
            .acquire(Lane::General, Duration::from_secs(1), &mut timing)
            .await
        {
            Err(rejected @ SlotWait::Full(_)) => rejected,
            _ => panic!("the occupied lane has no queue slots"),
        };
        {
            let mut guard = command.lock().await;
            persist_queue_rejection(&mut guard, &store, rejection, &timing).unwrap();
            assert!(!guard.is_busy());
            assert_eq!(
                store.metadata(&id).unwrap()["execution_state"],
                "not_started"
            );
        }
        drop(active);
        let live = read_command_state(&store, "s", &command, ReadWait::Output(0), 4096, None)
            .await
            .unwrap();
        let archived = read_saved_terminal_result(&store, "s", &id, 4096, None).unwrap();
        for key in [
            "state",
            "executed",
            "completion_unknown",
            "failure_stage",
            "error",
            "reason",
            "queue",
            "retryable",
            "queue_timed_out",
        ] {
            assert_eq!(live[key], archived[key], "{key}");
        }
        assert_eq!(archived["reason"], "queue_full");
        assert_eq!(archived["retryable"], true);
        assert_eq!(archived["queue_timed_out"], false);
    }

    #[tokio::test]
    async fn a_single_closed_stream_is_reported_as_an_event_not_a_verdict() {
        let (out_tx, out_rx) = mpsc::channel(4);
        let (err_tx, err_rx) = mpsc::channel(4);
        let mut out = StreamSource {
            receiver: out_rx,
            buffer: Vec::new(),
            closed: false,
        };
        let mut err = StreamSource {
            receiver: err_rx,
            buffer: Vec::new(),
            closed: false,
        };
        out_tx.send(Bytes::from_static(b"hello")).await.unwrap();
        drop(out_tx);
        // A queued chunk is delivered before the end of the stream is reported.
        assert_eq!(wait_any_chunk(&mut out, &mut err).await, StreamEvent::Data);
        assert_eq!(out.buffer, b"hello");
        // One stream ended; the other is still open, so this is not "all closed".
        assert_eq!(
            wait_any_chunk(&mut out, &mut err).await,
            StreamEvent::StreamClosed
        );
        assert!(out.is_closed());
        assert!(!err.is_closed());
        // Closing the second stream is what ends the command.
        drop(err_tx);
        assert_eq!(
            wait_any_chunk(&mut out, &mut err).await,
            StreamEvent::StreamClosed
        );
        assert!(err.is_closed());
        // Both closed: callers get a definitive answer and no receiver is polled again.
        assert_eq!(
            wait_any_chunk(&mut out, &mut err).await,
            StreamEvent::AllClosed
        );
    }

    #[tokio::test]
    async fn an_admitted_command_makes_the_terminal_busy_before_its_worker_exists() {
        // This is the regression: a queued command without an installed JoinHandle used
        // to look idle, so two execs could both be admitted and overwrite each other.
        let mut command = Command::new("r1".to_string());
        assert_eq!(command.state, CmdState::Queued);
        assert!(command.task.is_none());
        assert!(command.is_busy());

        command.state = CmdState::Running;
        assert!(command.is_busy());

        command.state = CmdState::Completed;
        assert!(!command.is_busy());
        command.state = CmdState::Unknown;
        assert!(!command.is_busy());
        command.state = CmdState::NotStarted;
        assert!(!command.is_busy());
    }

    #[test]
    fn closing_a_terminal_records_the_right_command_state() {
        // A queued command never left the machine.
        assert_eq!(
            close_final_state(CmdState::Queued),
            Some((CmdState::NotStarted, "not_started"))
        );
        // A running command was already sent, so its completion is unknown.
        assert_eq!(
            close_final_state(CmdState::Running),
            Some((CmdState::Unknown, "closed_by_caller"))
        );
        // Finished work keeps its verdict.
        assert_eq!(close_final_state(CmdState::Completed), None);
        assert_eq!(close_final_state(CmdState::Unknown), None);
        assert_eq!(close_final_state(CmdState::NotStarted), None);
    }

    #[test]
    fn completion_needs_both_streams_and_matching_statuses() {
        // One stream alone is not evidence: stderr may still be in flight.
        assert!(resolve_completion(Some(0), None).is_none());
        assert!(resolve_completion(None, Some(0)).is_none());
        assert!(resolve_completion(None, None).is_none());
        assert!(matches!(resolve_completion(Some(0), Some(0)), Some(Ok(0))));
        match resolve_completion(Some(4), Some(0)) {
            Some(Err(error)) => assert!(error.message().contains("different statuses")),
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn capture_stream_handles_start_and_end_in_one_packet() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("out.log");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let nonce = "n1";
        let mut start = b"\x1eSTART".to_vec();
        start.extend_from_slice(nonce.as_bytes());
        start.push(MARKER_SUFFIX);
        let end = format!("\x1eEND{nonce}:").into_bytes();
        let mut buffer = start.clone();
        buffer.extend_from_slice(b"hi\n");
        buffer.extend_from_slice(&end);
        buffer.extend_from_slice(b"7");
        buffer.push(MARKER_SUFFIX);
        let mut state = CaptureState::default();
        let code = capture_stream(&mut buffer, &mut file, &start, &end, &mut state).unwrap();
        // The same packet must both mark the command started and finish it.
        assert!(
            state.started,
            "start marker in a combined packet must register"
        );
        assert_eq!(code, Some(7));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hi\n");
    }

    #[test]
    fn capture_stream_waits_for_the_second_stream() {
        // stdout finishes first; the caller must keep waiting for stderr rather than
        // returning a completion that silently drops the error output.
        let directory = tempfile::tempdir().unwrap();
        let out_path = directory.path().join("out.log");
        let err_path = directory.path().join("err.log");
        let mut out_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&out_path)
            .unwrap();
        let mut err_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&err_path)
            .unwrap();
        let nonce = "n1";
        let mut start = b"\x1eSTART".to_vec();
        start.extend_from_slice(nonce.as_bytes());
        start.push(MARKER_SUFFIX);
        let end = format!("\x1eEND{nonce}:").into_bytes();
        let complete = |body: &[u8]| {
            let mut buffer = start.clone();
            buffer.extend_from_slice(body);
            buffer.extend_from_slice(&end);
            buffer.extend_from_slice(b"0");
            buffer.push(MARKER_SUFFIX);
            buffer
        };
        let mut out_buffer = complete(b"ok\n");
        let mut err_buffer = complete(b"");
        let mut out_state = CaptureState::default();
        let mut err_state = CaptureState::default();
        let out_code =
            capture_stream(&mut out_buffer, &mut out_file, &start, &end, &mut out_state).unwrap();
        let err_code =
            capture_stream(&mut err_buffer, &mut err_file, &start, &end, &mut err_state).unwrap();
        assert_eq!(out_code, Some(0));
        assert_eq!(err_code, Some(0));
        assert!(matches!(
            resolve_completion(out_code, err_code),
            Some(Ok(0))
        ));
    }

    #[test]
    fn capture_stream_strips_markers_and_reports_the_status() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("out.log");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let nonce = "n1";
        let mut start = b"\x1eSTART".to_vec();
        start.extend_from_slice(nonce.as_bytes());
        start.push(MARKER_SUFFIX);
        let end = format!("\x1eEND{nonce}:").into_bytes();
        let mut buffer = b"banner\x1eSTARTn1\x1fhello\n\x1eENDn1:0\x1f".to_vec();
        let mut state = CaptureState::default();
        let code = capture_stream(&mut buffer, &mut file, &start, &end, &mut state).unwrap();
        assert_eq!(code, Some(0));
        assert!(state.started);
        assert_eq!(std::fs::read(&path).unwrap(), b"hello\n".to_vec());
        assert!(buffer.is_empty());
    }

    #[test]
    fn env_names_are_posix_identifiers() {
        assert!(valid_env_name("LC_ALL"));
        assert!(!valid_env_name("1X"));
    }

    #[test]
    fn guard_matches_the_shared_decision() {
        // Terminal input and scripts share one guard implementation.
        assert!(guard::is_dangerous("reboot"));
        assert!(!guard::is_dangerous("echo hi"));
    }
}
