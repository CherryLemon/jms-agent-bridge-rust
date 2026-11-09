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
use serde_json::{json, Map, Value};
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};

use crate::errors::{BridgeError, BridgeResult};
use crate::execution::Runner;
use crate::guard;
use crate::inventory::{shell_quote, Host};
use crate::rest::AssetCatalog;
use crate::scheduler::{queue_rejection, Lane, SlotWait, Timings};
use crate::storage::journal::ProgressSink;
use crate::storage::results::{atomic_json, ResultStore};
use crate::transport::session::{
    find, new_nonce, ready_marker, ready_packet, terminal_packet, MARKER_SUFFIX,
};
use crate::transport::ssh::{ChannelShell, ChannelWriter};

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
    started: bool,
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
            started: false,
            exit_code: None,
            error: None,
            rejection: Map::new(),
            cursor,
            changed: Arc::new(Notify::new()),
            task: None,
        }
    }

    fn is_running(&self) -> bool {
        matches!(self.state, CmdState::Queued | CmdState::Running) && self.task.is_some()
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
}

struct Streams {
    out: StreamSource,
    err: StreamSource,
}

/// A bound shell: a writer usable at any time plus the streams of its current command.
pub struct TerminalShell {
    writer: ChannelWriter,
    streams: AsyncMutex<Streams>,
    lost: AtomicBool,
    demux: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl TerminalShell {
    async fn open(runner: &Runner, host: &Host, command: &str) -> BridgeResult<Self> {
        let (shell, _reconnected) = runner.pool.open_process(host, command).await?;
        let ChannelShell { writer, mut reader } = shell;
        let (out_tx, out_rx) = mpsc::channel(64);
        let (err_tx, err_rx) = mpsc::channel(64);
        let demux = tokio::spawn(async move {
            loop {
                match reader.next().await {
                    Some(crate::transport::ssh::ShellEvent::Data(data)) => {
                        if out_tx.send(data).await.is_err() {
                            return;
                        }
                    }
                    Some(crate::transport::ssh::ShellEvent::ExtData(data)) => {
                        if err_tx.send(data).await.is_err() {
                            return;
                        }
                    }
                    Some(crate::transport::ssh::ShellEvent::ExecRejected) | None => {
                        drop(out_tx);
                        drop(err_tx);
                        return;
                    }
                    Some(_) => continue,
                }
            }
        });
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
            lost: AtomicBool::new(false),
            demux: Mutex::new(Some(demux)),
        };
        shell.prime(Duration::from_secs(10)).await?;
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
            let filled = tokio::time::timeout(remaining, async {
                tokio::select! {
                    _ = out.fill() => true,
                    _ = err.fill() => true,
                }
            })
            .await
            .map_err(|_| {
                BridgeError::ssh(
                    "remote shell did not acknowledge readiness in time; script was not sent",
                )
            })?;
            if !filled {
                self.lost.store(true, Ordering::SeqCst);
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
        self.lost.load(Ordering::SeqCst) || self.writer.is_closed()
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
        self.lost.store(true, Ordering::SeqCst);
        self.writer.close().await;
        if let Some(demux) = self.demux.lock().expect("demux lock").take() {
            demux.abort();
        }
    }

    /// Capture one command's output on both streams until both markers close it.
    async fn capture_command(
        &self,
        out_path: &std::path::Path,
        err_path: &std::path::Path,
        script: &str,
        started: &Arc<AtomicBool>,
        changed: &Arc<Notify>,
        deadline: Duration,
    ) -> BridgeResult<i32> {
        let nonce = new_nonce();
        let mut start = b"\x1eSTART".to_vec();
        start.extend_from_slice(nonce.as_bytes());
        start.push(MARKER_SUFFIX);
        let end = format!("\x1eEND{nonce}:").into_bytes();
        let packet = terminal_packet(&nonce, script);
        let mut streams = self.streams.lock().await;
        self.writer.write(&packet).await?;
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
        let began = Instant::now();
        loop {
            // Drain what is already buffered before waiting for the next packet.
            match capture_stream(
                &mut streams.out.buffer,
                &mut out_file,
                &start,
                &end,
                &mut out_state,
            )? {
                Some(code) => return finish_capture(code, &out_file),
                None => {}
            }
            match capture_stream(
                &mut streams.err.buffer,
                &mut err_file,
                &start,
                &end,
                &mut err_state,
            )? {
                Some(code) => return finish_capture(code, &err_file),
                None => {}
            }
            if out_state.started || err_state.started {
                started.store(true, Ordering::SeqCst);
                changed.notify_waiters();
            }
            let remaining = deadline.checked_sub(began.elapsed()).unwrap_or_default();
            if began.elapsed() >= deadline {
                return Err(BridgeError::ssh(
                    "terminal command timed out; completion is unknown",
                ));
            }
            let Streams { out, err } = &mut *streams;
            let filled = tokio::time::timeout(remaining, async {
                tokio::select! {
                    _ = out.fill() => true,
                    _ = err.fill() => true,
                }
            })
            .await;
            match filled {
                Ok(true) => continue,
                Ok(false) => {
                    self.lost.store(true, Ordering::SeqCst);
                    return Err(BridgeError::ssh(
                        "terminal shell closed before completion marker",
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

#[derive(Default)]
struct CaptureState {
    active: bool,
    started: bool,
    done: bool,
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

pub struct Interactive {
    catalog: Arc<AssetCatalog>,
    runner: Arc<Runner>,
    store: Arc<ResultStore>,
    requests: Arc<crate::storage::journal::RequestJournal>,
    bindings: AsyncMutex<HashMap<String, Arc<AsyncMutex<Binding>>>>,
    lost: Mutex<HashMap<String, Value>>,
    registry: PathBuf,
    save_lock: AsyncMutex<()>,
}

impl Interactive {
    pub fn new(
        catalog: Arc<AssetCatalog>,
        runner: Arc<Runner>,
        store: Arc<ResultStore>,
        requests: Arc<crate::storage::journal::RequestJournal>,
    ) -> Self {
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
            requests,
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
        let shell = TerminalShell::open(&self.runner, &host, &command).await;
        drop(slot);
        drop(lease);
        let shell = shell?;
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
        let value = self
            .execute(&session, &script, false, 10_000, 4096, None)
            .await?;
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

    pub async fn execute(
        &self,
        session: &str,
        script: &str,
        allow_dangerous: bool,
        wait_ms: u64,
        max_bytes: usize,
        cursor: Option<&Value>,
    ) -> BridgeResult<Value> {
        self.check(script, allow_dangerous)?;
        let binding = self.binding(session).await?;
        {
            let binding_guard = binding.lock().await;
            self.permitted(&binding_guard).await?;
            if binding_guard.closed || binding_guard.shell.is_closing() {
                return Err(BridgeError::invalid(
                    "terminal shell was closed/lost; open a new session explicitly",
                ));
            }
            if let Some(command) = &binding_guard.command {
                if command.lock().await.is_running() {
                    return Err(BridgeError::invalid(
                        "terminal is busy; read/write its active command first",
                    ));
                }
            }
        }
        let host = { binding.lock().await.host.clone() };
        let mut metadata = Map::new();
        metadata.insert("kind".into(), Value::from("terminal"));
        metadata.insert("host".into(), Value::from(host.name.clone()));
        if let Some(asset_id) = &host.asset_id {
            metadata.insert("asset_id".into(), Value::from(asset_id.clone()));
        }
        metadata.insert("session_id".into(), Value::from(session));
        let result_id = self.store.create(metadata)?;
        for stream in ["stdout", "stderr"] {
            let path = self.store.path(&result_id, stream)?;
            if !path.exists() {
                std::fs::File::create(&path)?;
            }
        }
        let command = Arc::new(AsyncMutex::new(Command::new(result_id.clone())));
        {
            let mut binding_guard = binding.lock().await;
            binding_guard.command = Some(command.clone());
        }
        if let Some(progress) = self.progress(session) {
            progress.record(
                "execution_results",
                json!({"host": host.name, "result_id": result_id}),
            );
        }
        self.save().await?;
        // The worker owns the shell for the duration of the command; the caller only
        // polls its files, so an MCP disconnect cannot cancel accepted work.
        let runner = self.runner.clone();
        let store = self.store.clone();
        let shell = { binding.lock().await.shell.clone() };
        let host_for_task = host.clone();
        let script = script.to_string();
        let command_for_task = command.clone();
        let session_id = session.to_string();
        let task = tokio::spawn(async move {
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
        if wait_ms > 0 {
            tokio::time::sleep(Duration::from_millis(wait_ms.min(30_000))).await;
        }
        self.read(session, 0, max_bytes, cursor).await
    }

    fn progress(&self, session: &str) -> Option<Arc<crate::storage::journal::RequestProgress>> {
        let _ = self.requests.active_tasks();
        let _ = session;
        None
    }

    pub async fn read(
        &self,
        session: &str,
        wait_ms: u64,
        max_bytes: usize,
        cursor: Option<&Value>,
    ) -> BridgeResult<Value> {
        let binding = self.binding(session).await?;
        if binding.lock().await.shell.is_closing() {
            binding
                .lock()
                .await
                .shell
                .lost
                .store(true, Ordering::SeqCst);
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
        let mut guard = command.lock().await;
        let mut positions: HashMap<String, u64> = guard.cursor.clone();
        if let Some(cursor) = cursor.and_then(Value::as_object) {
            for (stream, value) in cursor {
                if let Some(offset) = value.as_u64() {
                    positions.insert(stream.clone(), offset);
                }
            }
        }
        let available = |store: &ResultStore, positions: &HashMap<String, u64>| -> bool {
            ["stdout", "stderr"].iter().any(|stream| {
                store
                    .path(&guard_result(&guard), stream)
                    .ok()
                    .and_then(|path| std::fs::metadata(path).ok())
                    .map(|meta| meta.len() > positions.get(*stream).copied().unwrap_or(0))
                    .unwrap_or(false)
            })
        };
        if guard.is_running() && wait_ms > 0 && !available(&self.store, &positions) {
            let deadline = Duration::from_millis(wait_ms.min(30_000));
            let _ = tokio::time::timeout(deadline, guard.changed.notified()).await;
        }
        let mut out = Map::new();
        out.insert("ok".into(), Value::Bool(true));
        out.insert("session".into(), Value::from(session));
        out.insert("result_id".into(), Value::from(guard.result_id.clone()));
        out.insert("state".into(), Value::from(guard.state.as_str()));
        let mut budget = max_bytes;
        for stream in ["stderr", "stdout"] {
            let path = self.store.path(&guard.result_id, stream)?;
            let size = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
            let position = positions.get(stream).copied().unwrap_or(0);
            let available = size.saturating_sub(position);
            let limit = (budget as u64).min(available);
            if limit > 0 {
                let page = self.store.read(
                    &guard.result_id,
                    stream,
                    position,
                    limit as usize,
                    false,
                    None,
                )?;
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
        guard.cursor = positions.clone();
        let mut cursor_map = Map::new();
        for (stream, value) in &positions {
            cursor_map.insert(stream.clone(), json!(value));
        }
        out.insert("cursor".into(), Value::Object(cursor_map));
        if guard.state == CmdState::Completed {
            let exit_code = guard.exit_code.unwrap_or(255);
            out.insert("ok".into(), Value::Bool(exit_code == 0));
            out.insert("exit_code".into(), json!(exit_code));
        } else if matches!(guard.state, CmdState::Unknown | CmdState::NotStarted) {
            out.insert("ok".into(), Value::Bool(false));
            out.insert(
                "executed".into(),
                if guard.started {
                    Value::Bool(true)
                } else if guard.sent {
                    Value::Null
                } else {
                    Value::Bool(false)
                },
            );
            out.insert(
                "completion_unknown".into(),
                Value::Bool(guard.state == CmdState::Unknown),
            );
            out.insert(
                "error".into(),
                guard.error.clone().map(Value::from).unwrap_or(Value::Null),
            );
            for (key, value) in &guard.rejection {
                out.insert(key.clone(), value.clone());
            }
        }
        if closed {
            out.insert("session_state".into(), Value::from("closed"));
        } else if lost {
            out.insert("session_state".into(), Value::from("lost"));
        }
        Ok(Value::Object(out))
    }

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
            if !guard.is_running() || guard.state != CmdState::Running {
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
        let mut out = self.read(session, wait_ms, max_bytes, cursor).await?;
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
            (guard.shell.clone(), guard.command.clone())
        };
        if let Some(command) = command {
            let mut guard = command.lock().await;
            if let Some(task) = guard.task.take() {
                if !task.is_finished() {
                    task.abort();
                }
            }
            if guard.state == CmdState::Queued {
                guard.state = CmdState::NotStarted;
                let result_id = guard.result_id.clone();
                drop(guard);
                let mut values = Map::new();
                values.insert("ok".into(), Value::Bool(false));
                values.insert("executed".into(), Value::Bool(false));
                values.insert("execution_state".into(), Value::from("not_started"));
                values.insert("completion_unknown".into(), Value::Bool(false));
                let _ = self.store.finish(&result_id, values);
            }
        }
        shell.close().await;
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
            rows.push(json!({
                "session": session,
                "host": binding.host.name,
                "asset_id": binding.host.asset_id,
                "state": if binding.closed { "closed" } else if binding.shell.is_closing() { "lost" } else { "idle" },
            }));
        }
        json!({"sessions": rows})
    }
}

fn guard_result(command: &Command) -> &str {
    &command.result_id
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
    let lease = match runner.recovery.enter(&key, runner.queue_timeout).await {
        Ok(lease) => lease,
        Err(error) => {
            let mut guard = command.lock().await;
            guard.state = CmdState::NotStarted;
            guard.error = Some(error.message());
            let result_id = guard.result_id.clone();
            drop(guard);
            let mut values = Map::new();
            values.insert("ok".into(), Value::Bool(false));
            values.insert("executed".into(), Value::Bool(false));
            values.insert("execution_state".into(), Value::from("not_started"));
            values.insert("completion_unknown".into(), Value::Bool(false));
            let _ = store.finish(&result_id, values);
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
    drop(lease);
    let slot = match slot {
        Ok(slot) => slot,
        Err(wait) => {
            let mut guard = command.lock().await;
            guard.state = CmdState::NotStarted;
            match wait {
                SlotWait::Full(full) => {
                    guard.error = Some(full.message());
                    guard.rejection = full.response();
                    guard
                        .rejection
                        .insert("failure_stage".into(), Value::from(QueueFail::QUEUE));
                    guard
                        .rejection
                        .insert("queue_timed_out".into(), Value::Bool(false));
                }
                SlotWait::Timeout(timeout) => {
                    guard.error = Some(timeout.message());
                    guard
                        .rejection
                        .insert("failure_stage".into(), Value::from(timeout.stage));
                    guard
                        .rejection
                        .insert("queue_timed_out".into(), Value::Bool(true));
                }
            }
            let result_id = guard.result_id.clone();
            let rejection = guard.rejection.clone();
            drop(guard);
            let mut values = Map::new();
            values.insert("ok".into(), Value::Bool(false));
            values.insert("executed".into(), Value::Bool(false));
            values.insert("execution_state".into(), Value::from("not_started"));
            values.insert("completion_unknown".into(), Value::Bool(false));
            for (key, value) in rejection {
                values.insert(key, value);
            }
            let _ = store.finish(&result_id, values);
            return Ok(());
        }
    };
    let (result_id, changed, started) = {
        let mut guard = command.lock().await;
        guard.state = CmdState::Running;
        guard.sent = true;
        (
            guard.result_id.clone(),
            guard.changed.clone(),
            Arc::new(AtomicBool::new(false)),
        )
    };
    let out_path = store.path(&result_id, "stdout")?;
    let err_path = store.path(&result_id, "stderr")?;
    let outcome = shell
        .capture_command(
            &out_path,
            &err_path,
            &script,
            &started,
            &changed,
            Duration::from_secs(86_400),
        )
        .await;
    let mut guard = command.lock().await;
    guard.started = started.load(Ordering::SeqCst);
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
                shell.lost.store(true, Ordering::SeqCst);
                shell.close().await;
            }
        }
    }
    let mut values = Map::new();
    values.insert(
        "ok".into(),
        Value::Bool(guard.state == CmdState::Completed && guard.exit_code == Some(0)),
    );
    values.insert(
        "exit_code".into(),
        guard.exit_code.map_or(Value::Null, |code| json!(code)),
    );
    values.insert(
        "executed".into(),
        if guard.started {
            Value::Bool(true)
        } else if guard.sent {
            Value::Null
        } else {
            Value::Bool(false)
        },
    );
    values.insert("execution_state".into(), Value::from(guard.state.as_str()));
    values.insert(
        "completion_unknown".into(),
        Value::Bool(guard.state == CmdState::Unknown),
    );
    if let Some(error) = &guard.error {
        values.insert("error".into(), Value::from(error.clone()));
    }
    values.insert("timing".into(), timings.snapshot());
    for (key, value) in guard.rejection.clone() {
        values.insert(key, value);
    }
    let result_id = guard.result_id.clone();
    guard.changed.notify_waiters();
    drop(guard);
    drop(slot);
    let _ = store.finish(&result_id, values);
    Ok(())
}

struct QueueFail;
impl QueueFail {
    const QUEUE: &'static str = "execution_queue";
}

/// Evidence copied from a finished terminal command into fan-out style rows.
pub fn command_rejection(meta: &Map<String, Value>) -> Map<String, Value> {
    queue_rejection(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

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
