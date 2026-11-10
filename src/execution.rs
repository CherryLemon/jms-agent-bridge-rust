//! Isolated execution, persistent shells and the three execution states.
//!
//! Contract: `not_started` means evidence proves the script was never sent,
//! `completed` means reliable start *and* completion evidence exists, and `unknown`
//! means transmission happened (or was possible) without completion evidence. The
//! bridge never replays an `unknown` execution by itself.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use tokio::sync::Mutex as AsyncMutex;

use crate::config::{BastionConfig, BridgeSettings};
use crate::errors::{BridgeError, BridgeResult};
use crate::inventory::{shell_quote, wrap_command, Host};
use crate::scheduler::{queue_rejection, round, ExecutionSlots, Lane, SlotWait, Timings};
use crate::storage::journal::ProgressSink;
use crate::storage::results::{now, OutputPreview, ResultStore};
use crate::transport::recovery::ConnectionRecovery;
use crate::transport::session::{
    exec_end_marker, exec_packet, exec_start_marker, new_nonce, ShellSession,
};
use crate::transport::ssh::SshPool;

/// Everything that changes how one execution is launched.
#[derive(Debug, Clone)]
pub struct ExecSpec {
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub container: Option<String>,
    pub image: Option<String>,
    pub docker_args: Vec<String>,
    pub session_id: Option<String>,
    /// `wrapped` scripts already carry their own `set -euo pipefail`.
    pub wrapped: bool,
    pub lane: Lane,
    pub queue_timeout: Option<f64>,
    /// Private filesystem worker shells are never user sessions.
    pub internal_session: bool,
    pub startup_probe: bool,
}

impl Default for ExecSpec {
    fn default() -> Self {
        Self {
            cwd: None,
            env: Vec::new(),
            container: None,
            image: None,
            docker_args: Vec::new(),
            session_id: None,
            wrapped: false,
            lane: Lane::General,
            queue_timeout: None,
            internal_session: false,
            startup_probe: false,
        }
    }
}

impl ExecSpec {
    fn kind(&self) -> &'static str {
        if self.internal_session || self.startup_probe {
            "fs_worker"
        } else {
            "run"
        }
    }
}

/// One finished execution, as the fan-out layer and legacy operations consume it.
pub struct ExecOutcome {
    pub host: String,
    pub exit_code: i64,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub result_id: String,
    pub preview: Option<Arc<OutputPreview>>,
    pub rejection: Map<String, Value>,
    pub recovery: Map<String, Value>,
    pub meta: Map<String, Value>,
}

impl ExecOutcome {
    pub fn ok(&self) -> bool {
        self.exit_code == 0 && self.meta.get("executed") == Some(&Value::Bool(true))
    }

    pub fn failure(host: &str, message: &str) -> Self {
        let mut meta = Map::new();
        meta.insert("ok".into(), Value::Bool(false));
        meta.insert("exit_code".into(), json!(75));
        meta.insert("execution_state".into(), Value::from("unknown"));
        meta.insert("completion_unknown".into(), Value::Bool(true));
        meta.insert("warning".into(), Value::from(message));
        Self {
            host: host.to_string(),
            exit_code: 75,
            stdout: String::new(),
            stderr: message.to_string(),
            timed_out: false,
            result_id: String::new(),
            preview: None,
            rejection: Map::new(),
            recovery: Map::new(),
            meta,
        }
    }
}

/// An execution error that still carries what the sender saw.
///
/// A call that failed *after* the bytes left must never be reported as "not executed":
/// the caller would retry a completed side effect. The metadata captured here is exactly
/// what the success path would have stored.
#[derive(Debug)]
pub struct ExecFailure {
    pub error: BridgeError,
    pub meta: Map<String, Value>,
}

impl From<BridgeError> for ExecFailure {
    /// Safe default: an unclassified error has no transmission evidence.
    fn from(error: BridgeError) -> Self {
        Self::before_send("internal", error)
    }
}

impl ExecFailure {
    /// Nothing reached the remote side (validation, connection, queue, local store).
    pub fn before_send(stage: &str, error: BridgeError) -> Self {
        let mut meta = Map::new();
        meta.insert("ok".into(), Value::Bool(false));
        meta.insert("executed".into(), Value::Bool(false));
        meta.insert("execution_state".into(), Value::from("not_started"));
        meta.insert("completion_unknown".into(), Value::Bool(false));
        meta.insert("failure_stage".into(), Value::from(stage));
        Self { error, meta }
    }

    /// The attempt ran; `meta` is what the store would have written.
    pub fn after(meta: Map<String, Value>, error: BridgeError) -> Self {
        Self { error, meta }
    }

    pub fn result_id(&self) -> Option<&str> {
        self.meta.get("result_id").and_then(Value::as_str)
    }
}

/// Internal outcome of one attempt; always converted into result metadata.
struct Attempt {
    code: i64,
    executed: Option<bool>,
    timed_out: bool,
    warning: Option<String>,
    sent: bool,
    completed: bool,
    reconnected: bool,
    failure_stage: Option<&'static str>,
    queue_timed_out: bool,
    rejection: Map<String, Value>,
    session_state: Option<&'static str>,
}

impl Attempt {
    fn not_started(warning: Option<String>, stage: &'static str) -> Self {
        Self {
            code: 75,
            executed: Some(false),
            timed_out: false,
            warning,
            sent: false,
            completed: false,
            reconnected: false,
            failure_stage: Some(stage),
            queue_timed_out: false,
            rejection: Map::new(),
            session_state: None,
        }
    }
}

/// Write the session registry from the current in-memory set.
///
/// The save lock covers "take the snapshot" *and* "replace the file": two concurrent
/// saves can otherwise finish in the opposite order and leave the older snapshot.
fn persist_sessions(
    registry: &std::path::Path,
    known: &Mutex<std::collections::HashSet<(String, String)>>,
    save: &Mutex<()>,
) -> BridgeResult<()> {
    persist_sessions_with(registry, known, save, || ())
}

fn persist_sessions_with<F: FnOnce()>(
    registry: &std::path::Path,
    known: &Mutex<std::collections::HashSet<(String, String)>>,
    save: &Mutex<()>,
    after_snapshot: F,
) -> BridgeResult<()> {
    let _save = save.lock().expect("registry save lock");
    let rows: Vec<Value> = {
        let known = known.lock().expect("session lock").clone();
        after_snapshot();
        known
            .iter()
            .map(|(target, session_id)| {
                json!({"target": target.split('\u{1f}').collect::<Vec<_>>(), "session_id": session_id})
            })
            .collect()
    };
    let mut rows = rows;
    rows.sort_by_key(|row| row.to_string());
    crate::storage::results::atomic_json(registry, &Value::Array(rows))
}

/// Whether a live shell or terminal still depends on this connection.
fn connection_protected(
    shells: &Arc<AsyncMutex<HashMap<(String, String), Arc<AsyncMutex<ShellSession>>>>>,
    terminals: &Arc<std::sync::Mutex<HashMap<String, usize>>>,
    key: &str,
) -> bool {
    let shell_live = match shells.try_lock() {
        Ok(shells) => shells.keys().any(|(shell_key, _)| shell_key == key),
        // Busy means an operation is using the map right now: assume it is live.
        Err(_) => true,
    };
    if shell_live {
        return true;
    }
    let protections = terminals.lock().expect("terminal protection lock");
    protections.get(key).copied().unwrap_or(0) > 0
}

/// Keeps an interactive terminal counted as a protection until it is dropped.
pub struct TerminalProtection {
    registry: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    key: String,
}

impl Drop for TerminalProtection {
    fn drop(&mut self) {
        let mut protections = self.registry.lock().expect("terminal protection lock");
        if let Some(count) = protections.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                protections.remove(&self.key);
            }
        }
    }
}

pub struct Runner {
    pub cfg: Arc<BastionConfig>,
    pub settings: Arc<BridgeSettings>,
    pub store: Arc<ResultStore>,
    pub pool: Arc<SshPool>,
    pub recovery: Arc<ConnectionRecovery>,
    pub scheduler: Arc<ExecutionSlots>,
    pub queue_timeout: f64,
    pub rsync_binary: crate::transport::rsync::RsyncBinary,
    /// One slot per named shell. The map lock is only held for lookup/insert; each shell
    /// has its own lock so two targets never block on each other.
    shells: Arc<AsyncMutex<HashMap<(String, String), Arc<AsyncMutex<ShellSession>>>>>,
    /// Live interactive terminals per connection key: they keep the connection alive.
    terminal_protections: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    session_gates: Mutex<HashMap<(String, String), Arc<AsyncMutex<()>>>>,
    known_sessions: Mutex<HashSet<(String, String)>>,
    /// Serializes snapshot+write+rename: without it two sessions saved concurrently can
    /// rename in the opposite order and leave the older snapshot on disk.
    registry_lock: Mutex<()>,
    registry: std::path::PathBuf,
    closing: AtomicBool,
}

impl Runner {
    pub fn new(
        cfg: Arc<BastionConfig>,
        settings: Arc<BridgeSettings>,
        store: Arc<ResultStore>,
    ) -> BridgeResult<Arc<Self>> {
        let limit = settings.execution_limit.unwrap_or(cfg.max_parallel);
        let scheduler = ExecutionSlots::new(
            limit,
            settings.inspection_reserved,
            settings.queue_limit,
            settings.inspection_queue_limit,
        )
        .map_err(BridgeError::config)?;
        let registry = settings.state_dir.join("shell_sessions.json");
        let mut known: HashSet<(String, String)> = HashSet::new();
        if let Ok(text) = std::fs::read_to_string(&registry) {
            if let Ok(Value::Array(rows)) = serde_json::from_str::<Value>(&text) {
                for row in rows {
                    let target = row
                        .get("target")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect::<Vec<_>>()
                                .join("\u{1f}")
                        })
                        .unwrap_or_default();
                    if let Some(session_id) = row.get("session_id").and_then(Value::as_str) {
                        known.insert((target, session_id.to_string()));
                    }
                }
            }
        }
        let queue_timeout = settings.queue_timeout;
        Ok(Arc::new(Self {
            pool: SshPool::new(cfg.clone(), settings.clone()),
            recovery: ConnectionRecovery::new(60.0),
            scheduler,
            cfg,
            settings,
            store,
            queue_timeout,
            rsync_binary: crate::transport::rsync::RsyncBinary::default(),
            shells: Arc::new(AsyncMutex::new(HashMap::new())),
            terminal_protections: Arc::new(std::sync::Mutex::new(HashMap::new())),
            session_gates: Mutex::new(HashMap::new()),
            known_sessions: Mutex::new(known),
            registry: registry.clone(),
            registry_lock: Mutex::new(()),
            closing: AtomicBool::new(false),
        }))
    }

    fn save_sessions(&self) -> BridgeResult<()> {
        persist_sessions(&self.registry, &self.known_sessions, &self.registry_lock)
    }

    /// The remote command for a shell: isolated `bash -s` or a named persistent shell.
    pub fn command(
        &self,
        container: Option<&str>,
        image: Option<&str>,
        docker_args: &[String],
        persistent: bool,
    ) -> BridgeResult<String> {
        if container.is_some() && image.is_some() {
            return Err(BridgeError::invalid("choose container or image, not both"));
        }
        let shell: Vec<String> = if persistent {
            vec!["bash".into(), "--noprofile".into(), "--norc".into()]
        } else {
            vec!["bash".into(), "-s".into()]
        };
        if let Some(target) = container.or(image) {
            if target.is_empty() || target.starts_with('-') || target.contains('\0') {
                return Err(BridgeError::invalid("invalid Docker target"));
            }
            let mut argv: Vec<String> = Vec::new();
            if let Some(container) = container {
                argv.extend(["docker".into(), "exec".into(), "-i".into()]);
                argv.extend(docker_args.iter().cloned());
                argv.push(container.to_string());
                argv.extend(shell);
            } else {
                argv.extend(["docker".into(), "run".into(), "--rm".into(), "-i".into()]);
                argv.extend(docker_args.iter().cloned());
                argv.extend(["--entrypoint".into(), "bash".into(), target.to_string()]);
                if persistent {
                    argv.extend(["--noprofile".into(), "--norc".into()]);
                } else {
                    argv.push("-s".into());
                }
            }
            return Ok(crate::fsprobe::shlex_join(&argv));
        }
        if !docker_args.is_empty() {
            return Err(BridgeError::invalid(
                "docker_args requires container or image",
            ));
        }
        Ok(crate::fsprobe::shlex_join(&shell))
    }

    pub async fn connection_status(&self) -> Value {
        let mut status = self.pool.status();
        if let Some(map) = status.as_object_mut() {
            map.insert("recovery".into(), self.recovery.status());
        }
        status
    }

    /// Register one interactive terminal as a reason not to replace this connection.
    pub fn protect_terminal(&self, key: &str) -> TerminalProtection {
        {
            let mut protections = self
                .terminal_protections
                .lock()
                .expect("terminal protection lock");
            *protections.entry(key.to_string()).or_insert(0) += 1;
        }
        TerminalProtection {
            registry: self.terminal_protections.clone(),
            key: key.to_string(),
        }
    }

    /// Every registered named shell with its *live* state.
    ///
    /// A shell that is executing a command holds its own lock, and a status query must
    /// not queue behind it: `try_lock` reports such a shell as `running` instead.
    pub async fn sessions(&self) -> Vec<Value> {
        let known = self.known_sessions.lock().expect("session lock").clone();
        let live: HashMap<(String, String), Arc<AsyncMutex<ShellSession>>> = {
            let shells = self.shells.lock().await;
            shells
                .iter()
                .map(|(key, slot)| (key.clone(), slot.clone()))
                .collect()
        };
        let mut rows: Vec<Value> = Vec::new();
        for (target, session_id) in known.iter() {
            let asset_id = target.split('\u{1f}').last().unwrap_or("").to_string();
            let state = match live.get(&(target.clone(), session_id.clone())) {
                None => "lost",
                Some(slot) => match slot.try_lock() {
                    Ok(shell) => {
                        if shell.is_closing() {
                            "lost"
                        } else {
                            "active"
                        }
                    }
                    // Busy means a command is running right now.
                    Err(_) => "running",
                },
            };
            rows.push(json!({
                "asset_id": asset_id,
                "session_id": session_id,
                "state": state,
                "lost": state == "lost",
            }));
        }
        rows.sort_by_key(|row| row.to_string());
        rows
    }

    /// Best-effort shell state without waiting for a running command.
    async fn session_state_snapshot(&self, key: &(String, String)) -> Option<&'static str> {
        let slot = {
            let shells = self.shells.lock().await;
            shells.get(key).cloned()
        };
        let slot = slot?;
        let state = match slot.try_lock() {
            Ok(shell) => {
                if shell.is_closing() {
                    "lost"
                } else {
                    "active"
                }
            }
            // Busy: a command is running, so the shell is alive but not inspectable.
            Err(_) => "active",
        };
        Some(state)
    }

    /// Full execution lifecycle for one target; returns finished result metadata.
    pub async fn execute_to_store(
        &self,
        host: &Host,
        script: &str,
        timeout: f64,
        spec: &ExecSpec,
        progress: Option<&dyn ProgressSink>,
    ) -> Result<Map<String, Value>, ExecFailure> {
        if spec.env.iter().any(|(key, _)| !valid_env_name(key)) {
            return Err(ExecFailure::before_send(
                "validation",
                BridgeError::invalid("invalid environment variable name"),
            ));
        }
        if script.contains('\0')
            || spec.cwd.as_deref().unwrap_or("").contains('\0')
            || spec.env.iter().any(|(_, value)| value.contains('\0'))
            || spec.docker_args.iter().any(|value| value.contains('\0'))
        {
            return Err(ExecFailure::before_send(
                "validation",
                BridgeError::invalid("NUL bytes are not valid shell arguments"),
            ));
        }
        if spec.internal_session {
            let ok = spec
                .session_id
                .as_deref()
                .map(|value| {
                    value.len() == 36
                        && value.starts_with("_fs:")
                        && value[4..]
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                })
                .unwrap_or(false);
            if !ok {
                return Err(ExecFailure::before_send(
                    "validation",
                    BridgeError::invalid("invalid private filesystem worker ID"),
                ));
            }
        }
        if let (Some(session_id), false) = (&spec.session_id, spec.internal_session) {
            if session_id.is_empty()
                || session_id.len() > 64
                || !session_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            {
                return Err(ExecFailure::before_send(
                    "validation",
                    BridgeError::invalid(
                        "session_id must contain 1..64 letters, digits, dots, underscores, or hyphens",
                    ),
                ));
            }
        }
        let queue_timeout = spec.queue_timeout.unwrap_or(self.queue_timeout);
        if queue_timeout <= 0.0 {
            return Err(ExecFailure::before_send(
                "validation",
                BridgeError::invalid("queue_timeout must be positive"),
            ));
        }
        if self.closing.load(Ordering::SeqCst) {
            return Err(ExecFailure::before_send(
                "connection",
                BridgeError::invalid("SSH runner is closing"),
            ));
        }
        let isolated_retryable = spec.session_id.is_none()
            && spec.image.is_none()
            && !spec.startup_probe
            && !spec.internal_session;
        let mut meta = self
            .attempt_to_store(host, script, timeout, spec, queue_timeout, progress)
            .await?;
        if !isolated_retryable || !startup_failed(&meta) {
            return Ok(meta);
        }
        let first_result = meta
            .get("result_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let retry = self
            .attempt_to_store(host, script, timeout, spec, queue_timeout, progress)
            .await?;
        meta = retry;
        let mut annotations = Map::new();
        if let Some(first) = &first_result {
            annotations.insert("startup_retry_result_id".into(), Value::from(first.clone()));
        }
        if startup_failed(&meta) {
            let generation = meta
                .get("connection_generation")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let key = host.connection_key()?;
            let pool = self.pool.clone();
            let host_for_replace = host.clone();
            // A connection that still carries named shells or interactive terminals must
            // not be replaced underneath them: those sessions would be lost silently.
            let shells = self.shells.clone();
            let terminals = self.terminal_protections.clone();
            let protect_key = key.clone();
            let protected = std::sync::Arc::new(move || {
                connection_protected(&shells, &terminals, &protect_key)
            });
            let recovery = self
                .recovery
                .clone()
                .request(
                    &key,
                    generation,
                    Box::new(move || {
                        Box::pin(async move {
                            pool.replace(&host_for_replace).await?;
                            Ok(())
                        })
                    }),
                    protected,
                    false,
                    queue_timeout,
                )
                .await;
            let status = recovery.get("status").and_then(Value::as_str).unwrap_or("");
            if matches!(status, "reset" | "already_replaced") {
                let previous = meta.get("result_id").cloned().unwrap_or(Value::Null);
                meta = self
                    .attempt_to_store(host, script, timeout, spec, queue_timeout, progress)
                    .await?;
                let mut merged = recovery.clone();
                if let Some(map) = merged.as_object_mut() {
                    map.insert("previous_result_id".into(), previous);
                }
                annotations.insert("connection_recovery".into(), merged);
            } else {
                annotations.insert("connection_recovery".into(), recovery);
            }
        } else if let Some(existing) = meta.get("connection_recovery").cloned() {
            annotations.insert("connection_recovery".into(), existing);
        }
        if !annotations.is_empty() {
            if let Some(result_id) = meta.get("result_id").and_then(Value::as_str) {
                let updated = self.store.annotate(result_id, annotations.clone())?;
                meta = updated;
            }
        }
        Ok(meta)
    }

    async fn attempt_to_store(
        &self,
        host: &Host,
        script: &str,
        timeout: f64,
        spec: &ExecSpec,
        queue_timeout: f64,
        progress: Option<&dyn ProgressSink>,
    ) -> Result<Map<String, Value>, ExecFailure> {
        let command = self
            .command(
                spec.container.as_deref(),
                spec.image.as_deref(),
                &spec.docker_args,
                spec.session_id.is_some(),
            )
            .map_err(|error| ExecFailure::before_send("validation", error))?;
        let mut metadata = Map::new();
        metadata.insert("kind".into(), Value::from(spec.kind()));
        metadata.insert("host".into(), Value::from(host.name.clone()));
        if let Some(asset_id) = &host.asset_id {
            metadata.insert("asset_id".into(), Value::from(asset_id.clone()));
        }
        if let Some(container) = &spec.container {
            metadata.insert("container".into(), Value::from(container.clone()));
        }
        if let Some(image) = &spec.image {
            metadata.insert("image".into(), Value::from(image.clone()));
        }
        if let Some(session_id) = &spec.session_id {
            metadata.insert("session_id".into(), Value::from(session_id.clone()));
        }
        metadata.insert("lane".into(), Value::from(spec.lane.as_str()));
        let result_id = match self.store.create(metadata) {
            Ok(result_id) => result_id,
            Err(error) => return Err(ExecFailure::before_send("results", error)),
        };
        // From here until the verdict is stored, dropping this future (task abort,
        // timeout of the caller, panic) closes the result instead of leaking an active
        // "running" entry that cleanup would skip.
        let sent_flag = Arc::new(AtomicBool::new(false));
        let mut lease = crate::storage::results::ResultLease::new(
            self.store.clone(),
            result_id.clone(),
            sent_flag.clone(),
        );
        lease.arm();
        if let Some(progress) = progress {
            // Nothing may be transmitted until the caller can find this result after a
            // crash: a rejected write stops the run instead of losing the trail. The
            // result is closed as not_started so it does not linger as an active "run".
            if let Err(error) = progress.record(
                "execution_results",
                json!({"host": host.name, "result_id": result_id}),
            ) {
                let message = format!(
                    "request progress could not be persisted: {}",
                    error.message()
                );
                let _ = self.store.fail_before_send(&result_id, &message);
                lease.disarm();
                return Err(ExecFailure::before_send("results", error));
            }
        }
        let out_path = self.store.path(&result_id, "stdout")?;
        let err_path = self.store.path(&result_id, "stderr")?;
        let started_at = Instant::now();
        let mut prefix: Vec<String> = Vec::new();
        if spec.session_id.is_none() && !spec.wrapped {
            prefix.push("set -euo pipefail".into());
        }
        for (key, value) in &spec.env {
            prefix.push(format!("export {key}={}", shell_quote(value)));
        }
        prefix.push(script.to_string());
        let body_text = prefix.join("\n") + "\n";
        // Isolated runs execute in a subshell so `set -e` still stops the script while
        // the wrapper survives to report `$?`. A named shell must *not* do that: `cd`
        // and exports have to persist for the next call on the same session.
        let mut body = if spec.session_id.is_none() {
            format!("(\n{body_text})\n__jms_exec_rc=$?\n")
        } else {
            body_text
        };
        if let Some(cwd) = spec.cwd.as_deref().filter(|value| !value.is_empty()) {
            body = if spec.session_id.is_none() {
                format!(
                    "if builtin cd -- {}; then\n{body}else\n__jms_exec_rc=1\nfi\n",
                    shell_quote(cwd)
                )
            } else {
                format!(
                    "if builtin cd -- {}; then\n{body}else\nfalse\nfi\n",
                    shell_quote(cwd)
                )
            };
        }
        let mut timings = Timings::default();
        let attempt = self
            .attempt(
                host,
                &command,
                &body,
                timeout,
                spec,
                queue_timeout,
                &out_path,
                &err_path,
                &sent_flag,
                &mut timings,
            )
            .await;
        let elapsed = started_at.elapsed().as_secs_f64();
        // Every stored stream must exist even when the attempt failed early.
        for path in [&out_path, &err_path] {
            if !path.exists() {
                let _ = std::fs::File::create(path);
            }
        }
        let mut warning = attempt.warning.clone();
        let unknown = attempt.sent && !attempt.completed;
        if unknown {
            match &warning {
                Some(text) if !text.contains("unknown") => {
                    warning = Some(format!(
                        "{text}; remote completion is unknown; do not replay automatically"
                    ));
                }
                Some(_) => {}
                None => {
                    warning = Some(
                        "remote completion is unknown; do not replay automatically".to_string(),
                    );
                }
            }
        }
        if let Some(text) = &warning {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(&err_path) {
                let _ = writeln!(file, "\n{text}");
            }
        }
        let connection_state = if self
            .pool
            .connection(host)
            .await
            .map(|connection| !connection.is_closed())
            .unwrap_or(false)
        {
            "connected"
        } else {
            "disconnected"
        };
        // The attempt decides this while it owns the shell; re-locking here would make a
        // finished request wait behind the *next* command on that session. A registered
        // id is *not* evidence that the shell is alive, so there is no implicit default.
        let session_state = if spec.session_id.is_some() {
            attempt.session_state
        } else {
            None
        };
        let mut values = Map::new();
        values.insert("result_id".into(), Value::from(result_id.clone()));
        values.insert("host".into(), Value::from(host.name.clone()));
        values.insert(
            "ok".into(),
            Value::Bool(attempt.code == 0 && attempt.executed == Some(true)),
        );
        values.insert("exit_code".into(), json!(attempt.code));
        values.insert("timed_out".into(), Value::Bool(attempt.timed_out));
        values.insert(
            "executed".into(),
            match attempt.executed {
                Some(value) => Value::Bool(value),
                None => Value::Null,
            },
        );
        values.insert("completion_unknown".into(), Value::Bool(unknown));
        values.insert(
            "execution_state".into(),
            Value::from(if attempt.completed {
                "completed"
            } else if unknown {
                "unknown"
            } else {
                "not_started"
            }),
        );
        values.insert("reconnected".into(), Value::Bool(attempt.reconnected));
        values.insert("connection_state".into(), Value::from(connection_state));
        if let Some(state) = session_state {
            values.insert("session_state".into(), Value::from(state));
        }
        values.insert("elapsed_seconds".into(), json!(round(elapsed, 3)));
        if let Some(warning) = warning {
            values.insert("warning".into(), Value::from(warning));
        }
        values.insert("timing".into(), timings.snapshot());
        values.insert(
            "queue_timed_out".into(),
            Value::Bool(attempt.queue_timed_out),
        );
        values.insert("connection_timing".into(), timings.connection_snapshot());
        // Report the pool's real generation and mirror it into the recovery tracker,
        // which is what decides whether a replacement already happened.
        let generation = self.pool.generation(&host.connection_key()?);
        self.recovery
            .set_generation(&host.connection_key()?, generation);
        values.insert("connection_generation".into(), json!(generation));
        if attempt.warning.is_some()
            || attempt
                .failure_stage
                .is_some_and(|_| !attempt.completed && !unknown && attempt.executed != Some(true))
        {
            if let Some(stage) = attempt.failure_stage {
                if !attempt.completed {
                    values.insert("failure_stage".into(), Value::from(stage));
                }
            }
        }
        for (key, value) in attempt.rejection {
            values.insert(key, value);
        }
        let meta = match lease.complete(values.clone()) {
            Ok(meta) => meta,
            Err(error) => {
                // The remote side already ran: never turn a local write failure into
                // "not executed". Keep the values this call would have stored.
                let mut meta = values;
                meta.insert("result_id".into(), Value::from(result_id.clone()));
                meta.insert("error".into(), Value::from(error.message()));
                meta.insert("local_error".into(), Value::Bool(true));
                return Err(ExecFailure::after(meta, error));
            }
        };
        let finished_ok = meta
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let finished_code = meta
            .get("exit_code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-1);
        tracing::info!(
            result_id = result_id.as_str(),
            host = host.name.as_str(),
            ok = finished_ok,
            exit_code = finished_code,
            elapsed_seconds = round(elapsed, 3),
            "execution_finished"
        );
        Ok(meta)
    }

    #[allow(clippy::too_many_arguments)]
    async fn attempt(
        &self,
        host: &Host,
        command: &str,
        body: &str,
        timeout: f64,
        spec: &ExecSpec,
        queue_timeout: f64,
        out_path: &std::path::Path,
        err_path: &std::path::Path,
        sent: &AtomicBool,
        timings: &mut Timings,
    ) -> Attempt {
        let key = match host.connection_key() {
            Ok(key) => key,
            Err(error) => return Attempt::not_started(Some(error.message()), "connection"),
        };
        // Take the target lease before a session gate: a draining connection must not be
        // held by a request that is only waiting for an idle shell.
        let lease = match self.recovery.enter(&key, queue_timeout).await {
            Ok(lease) => lease,
            Err(error) => {
                return Attempt {
                    code: 124,
                    executed: Some(false),
                    timed_out: true,
                    warning: Some(error.message()),
                    sent: false,
                    completed: false,
                    reconnected: false,
                    failure_stage: Some("connection_recovery"),
                    queue_timed_out: true,
                    rejection: Map::new(),
                    session_state: None,
                }
            }
        };
        let session_gate = match &spec.session_id {
            Some(session_id) => {
                let gate = {
                    let mut gates = self.session_gates.lock().expect("gate lock");
                    gates
                        .entry((key.clone(), session_id.clone()))
                        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                        .clone()
                };
                match tokio::time::timeout(
                    Duration::from_secs_f64(queue_timeout),
                    gate.lock_owned(),
                )
                .await
                {
                    Ok(guard) => Some(guard),
                    Err(_) => {
                        return Attempt {
                            code: 124,
                            executed: Some(false),
                            timed_out: true,
                            warning: Some(
                                "session_queue timed out; command was not sent".to_string(),
                            ),
                            sent: false,
                            completed: false,
                            reconnected: false,
                            failure_stage: Some("session_queue"),
                            queue_timed_out: true,
                            rejection: Map::new(),
                            // Nothing was taken over; a non-blocking snapshot says
                            // whether the shell is still there without queueing behind
                            // the command that holds it.
                            session_state: self
                                .session_state_snapshot(&(
                                    key.clone(),
                                    spec.session_id.clone().unwrap_or_default(),
                                ))
                                .await,
                        };
                    }
                }
            }
            None => None,
        };
        let previous = self.pool.status();
        let _ = previous;
        let connection_started = Instant::now();
        // Warm (or reuse) the pooled connection before waiting for a slot: a login
        // failure must be reported as unsent, and a slot must not be held idle.
        match self.pool.connection(host).await {
            Ok(_) => {}
            Err(error) => {
                timings.connection_seconds += connection_started.elapsed().as_secs_f64();
                return Attempt::not_started(Some(error.message()), "connection");
            }
        };
        timings.connection_seconds += connection_started.elapsed().as_secs_f64();
        let remaining_queue = (queue_timeout - timings.queue_seconds).max(0.001);
        let slot = self
            .scheduler
            .acquire(spec.lane, Duration::from_secs_f64(remaining_queue), timings)
            .await;
        let _slot = match slot {
            Ok(slot) => slot,
            Err(SlotWait::Full(full)) => {
                let mut attempt = Attempt::not_started(Some(full.message()), "execution_queue");
                attempt.code = 75;
                attempt.rejection = full.response();
                attempt
                    .rejection
                    .insert("executed".into(), Value::Bool(false));
                attempt
                    .rejection
                    .insert("execution_state".into(), Value::from("not_started"));
                attempt
                    .rejection
                    .insert("completion_unknown".into(), Value::Bool(false));
                attempt
                    .rejection
                    .insert("queue_timed_out".into(), Value::Bool(false));
                attempt
                    .rejection
                    .insert("failure_stage".into(), Value::from("execution_queue"));
                return attempt;
            }
            Err(SlotWait::Timeout(timeout_error)) => {
                return Attempt {
                    code: 124,
                    executed: Some(false),
                    timed_out: true,
                    warning: Some(timeout_error.message()),
                    sent: false,
                    completed: false,
                    reconnected: false,
                    failure_stage: Some("execution_queue"),
                    queue_timed_out: true,
                    rejection: Map::new(),
                    session_state: None,
                }
            }
        };
        // The lease stays held across the whole remote exchange: a replacement triggered
        // by another channel on this connection must wait until this one is finished.
        let _lease = lease;
        let deadline = Duration::from_secs_f64(timeout);
        let mut attempt = if let Some(session_id) = &spec.session_id {
            self.run_on_session(
                host, command, body, deadline, spec, session_id, &key, out_path, err_path, sent,
                timings,
            )
            .await
        } else {
            self.run_isolated(
                host, command, body, deadline, out_path, err_path, sent, timings,
            )
            .await
        };
        if spec.session_id.is_some() {
            attempt.session_state = attempt.session_state.or(Some("active"));
        }
        drop(session_gate);
        attempt
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_isolated(
        &self,
        host: &Host,
        command: &str,
        body: &str,
        deadline: Duration,
        out_path: &std::path::Path,
        err_path: &std::path::Path,
        sent: &AtomicBool,
        timings: &mut Timings,
    ) -> Attempt {
        let channel_started = Instant::now();
        let (shell, reconnected) = match self.pool.open_process(host, command).await {
            Ok(value) => value,
            Err(error) => {
                timings.channel_seconds += channel_started.elapsed().as_secs_f64();
                return Attempt::not_started(Some(error.message()), "channel");
            }
        };
        let mut session = ShellSession::new(shell);
        if let Err(error) = session
            .prime(Duration::from_secs_f64(deadline.as_secs_f64().min(10.0)))
            .await
        {
            let _ = session.save_startup_output(out_path, err_path);
            session.lost = true;
            session.close().await;
            timings.channel_seconds += channel_started.elapsed().as_secs_f64();
            return Attempt::not_started(Some(error.message()), "shell_startup");
        }
        timings.channel_seconds += channel_started.elapsed().as_secs_f64();
        let nonce = new_nonce();
        let start = crate::transport::session::exec_start_marker(&nonce);
        let end = crate::transport::session::exec_end_marker(&nonce);
        let mut packet = Vec::new();
        packet.extend_from_slice(
            format!("printf '\\036START{nonce}\\037'; printf '\\036START{nonce}\\037' >&2\n")
                .as_bytes(),
        );
        packet.extend_from_slice(body.as_bytes());
        packet.extend_from_slice(
            format!(
                "printf '\\036END{nonce}:%s\\037' \"$__jms_exec_rc\"; \
printf '\\036END{nonce}:%s\\037' \"$__jms_exec_rc\" >&2\n"
            )
            .as_bytes(),
        );
        let execution_started = Instant::now();
        sent.store(true, Ordering::SeqCst);
        let write = session.writer.write(&packet).await;
        session.writer.write_eof().await;
        let pump = match write {
            Ok(()) => {
                session
                    .pump(out_path, err_path, Some(start), Some(end), Some(deadline))
                    .await
            }
            Err(error) => Err(error),
        };
        timings.execution_seconds += execution_started.elapsed().as_secs_f64();
        let channel_exit = session.exit_code();
        session.close().await;
        match pump {
            Ok(outcome) => {
                if outcome.rejected {
                    return Attempt::not_started(
                        Some("SSH channel rejected the execution request".to_string()),
                        "channel",
                    );
                }
                let started = outcome.started;
                // Completion needs real evidence: the script's own end marker, or the
                // transport's exit status. A missing status is `unknown`, never a
                // synthetic 255 that looks like a finished run.
                let end_code = outcome.end_code;
                let evidence = end_code.or(channel_exit.or(outcome.exit_status));
                let completed = started && evidence.is_some();
                let code = evidence.unwrap_or(255) as i64;
                let warning = if !started {
                    Some(
                        "SSH channel ended without the script start acknowledgment after transmission; remote completion is unknown; do not replay automatically.".to_string(),
                    )
                } else if !completed {
                    Some(
                        "SSH channel ended without a completion status; remote completion is unknown; inspect before rerunning."
                            .to_string(),
                    )
                } else {
                    None
                };
                Attempt {
                    code: if !started { 75 } else { code },
                    executed: Some(started),
                    timed_out: false,
                    warning,
                    sent: true,
                    completed,
                    reconnected,
                    failure_stage: if !started {
                        Some("execution_ack")
                    } else {
                        None
                    },
                    queue_timed_out: false,
                    rejection: Map::new(),
                    session_state: None,
                }
            }
            Err(error) if error.message().contains("timed out") => Attempt {
                code: 124,
                executed: Some(true),
                timed_out: true,
                warning: Some(
                    "Execution timed out; remote completion is unknown. Inspect before rerunning."
                        .to_string(),
                ),
                sent: true,
                completed: false,
                reconnected,
                failure_stage: Some("execution"),
                queue_timed_out: false,
                rejection: Map::new(),
                session_state: None,
            },
            Err(error) => Attempt {
                code: 255,
                executed: Some(true),
                timed_out: false,
                warning: Some(error.message()),
                sent: true,
                completed: false,
                reconnected,
                failure_stage: Some("execution"),
                queue_timed_out: false,
                rejection: Map::new(),
                session_state: None,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_on_session(
        &self,
        host: &Host,
        command: &str,
        body: &str,
        deadline: Duration,
        spec: &ExecSpec,
        session_id: &str,
        key: &str,
        out_path: &std::path::Path,
        err_path: &std::path::Path,
        sent: &AtomicBool,
        timings: &mut Timings,
    ) -> Attempt {
        let session_key = (key.to_string(), session_id.to_string());
        if spec.internal_session {
            // A private worker whose shell died is replaced silently; user sessions are not.
            let stale = {
                let shells = self.shells.lock().await;
                match shells.get(&session_key).cloned() {
                    Some(shell) => {
                        let guard = shell.lock().await;
                        guard.is_closing()
                    }
                    None => false,
                }
            };
            if stale {
                let mut shells = self.shells.lock().await;
                shells.remove(&session_key);
            }
        }
        // A session that was already registered but has no live shell lost its state
        // (restart, dropped connection). A session seen for the first time is simply new
        // and only joins the registry once its shell really exists.
        let resumed = self
            .known_sessions
            .lock()
            .expect("session lock")
            .contains(&session_key);
        // Look the shell up under the map lock, then work with its own lock: opening and
        // priming a shell must never block other targets' sessions.
        let existing = {
            let shells = self.shells.lock().await;
            shells.get(&session_key).cloned()
        };
        let shell_slot = match existing {
            Some(shell) => shell,
            None => {
                if !spec.internal_session && resumed {
                    return Attempt::not_started(
                    Some(
                        "session state was lost after service restart; use a new session_id or call session_close to reset it"
                            .to_string(),
                    ),
                    "session",
                );
                }
                let channel_started = Instant::now();
                let (shell, _reconnected) = match self.pool.open_process(host, command).await {
                    Ok(value) => value,
                    Err(error) => {
                        timings.channel_seconds += channel_started.elapsed().as_secs_f64();
                        return Attempt::not_started(Some(error.message()), "channel");
                    }
                };
                let mut session_shell = ShellSession::new(shell);
                session_shell.launch = Some(command.to_string());
                let slot = Arc::new(AsyncMutex::new(session_shell));
                {
                    let mut shells = self.shells.lock().await;
                    shells.insert(session_key.clone(), slot.clone());
                }
                if !spec.internal_session {
                    self.known_sessions
                        .lock()
                        .expect("session lock")
                        .insert(session_key.clone());
                    if let Err(error) = self.save_sessions() {
                        let mut shells = self.shells.lock().await;
                        shells.remove(&session_key);
                        return Attempt::not_started(Some(error.message()), "session_registry");
                    }
                }
                timings.channel_seconds += channel_started.elapsed().as_secs_f64();
                slot
            }
        };
        let mut shell_guard = shell_slot.lock().await;
        let shell = &mut *shell_guard;
        // A shell keeps the container/image/docker arguments it was opened with: a
        // later call cannot silently run somewhere else than its metadata claims.
        if let Some(launch) = &shell.launch {
            if launch != command {
                return Attempt::not_started(
                    Some(
                        "session was opened with a different container/image/docker_args; \
close it or use a new session_id"
                            .to_string(),
                    ),
                    "session",
                );
            }
        }
        if shell.is_closing() {
            drop(shell_guard);
            {
                let mut shells = self.shells.lock().await;
                shells.remove(&session_key);
            }
            return Attempt::not_started(
                Some(
                    "session state was lost; inspect prior result, then use a new session_id"
                        .to_string(),
                ),
                "session",
            );
        }
        if !shell.ready {
            let prime_started = Instant::now();
            if let Err(error) = shell
                .prime(Duration::from_secs_f64(deadline.as_secs_f64().min(10.0)))
                .await
            {
                let _ = shell.save_startup_output(out_path, err_path);
                shell.lost = true;
                shell.close().await;
                drop(shell_guard);
                {
                    let mut shells = self.shells.lock().await;
                    shells.remove(&session_key);
                }
                timings.channel_seconds += prime_started.elapsed().as_secs_f64();
                return Attempt::not_started(Some(error.message()), "shell_startup");
            }
            timings.channel_seconds += prime_started.elapsed().as_secs_f64();
        }
        let nonce = new_nonce();
        let start = exec_start_marker(&nonce);
        let end = exec_end_marker(&nonce);
        let packet = exec_packet(&nonce, body);
        sent.store(true, Ordering::SeqCst);
        let execution_started = Instant::now();
        let capture = async {
            shell.writer.write(&packet).await?;
            shell
                .capture(out_path, err_path, &start, &end, deadline)
                .await
        }
        .await;
        timings.execution_seconds += execution_started.elapsed().as_secs_f64();
        match capture {
            Ok(result) => {
                let completed = result.out_code == result.err_code;
                Attempt {
                    code: result.out_code as i64,
                    executed: Some(true),
                    timed_out: false,
                    warning: None,
                    sent: true,
                    completed,
                    reconnected: false,
                    failure_stage: None,
                    queue_timed_out: false,
                    rejection: Map::new(),
                    session_state: Some("active"),
                }
            }
            Err(error) if error.message().contains("timed out") => {
                // The shell still has an unknown command in flight. Close its channel and
                // stop reusing it, but keep the registry entry so a later call reports the
                // loss instead of silently rebuilding a fresh shell behind the same id.
                shell.lost = true;
                shell.close().await;
                drop(shell_guard);
                {
                    let mut shells = self.shells.lock().await;
                    shells.remove(&session_key);
                }
                Attempt {
                    code: 124,
                    executed: Some(true),
                    timed_out: true,
                    warning: Some(
                        "Execution timed out; remote completion is unknown. This session_id was \
closed and must not be reused. Inspect before rerunning."
                            .to_string(),
                    ),
                    sent: true,
                    completed: false,
                    reconnected: false,
                    failure_stage: Some("execution"),
                    queue_timed_out: false,
                    rejection: Map::new(),
                    session_state: Some("lost"),
                }
            }
            Err(error) => {
                shell.lost = true;
                shell.close().await;
                drop(shell_guard);
                {
                    let mut shells = self.shells.lock().await;
                    shells.remove(&session_key);
                }
                Attempt {
                    code: 255,
                    executed: None,
                    timed_out: false,
                    warning: Some(error.message()),
                    sent: true,
                    completed: false,
                    reconnected: false,
                    failure_stage: Some("execution"),
                    queue_timed_out: false,
                    rejection: Map::new(),
                    session_state: Some("lost"),
                }
            }
        }
    }

    /// One rsync transfer through the pooled connection, stored like any execution.
    #[allow(clippy::too_many_arguments)]
    pub async fn rsync(
        &self,
        host: &Host,
        local: &str,
        remote: &str,
        direction: &str,
        excludes: &[String],
        delete: bool,
        timeout: f64,
        container: Option<&str>,
        overwrite: bool,
        progress: Option<&dyn ProgressSink>,
    ) -> BridgeResult<ExecOutcome> {
        let direction = match direction {
            "push" => crate::transport::rsync::Direction::Push,
            "pull" => crate::transport::rsync::Direction::Pull,
            other => {
                return Err(BridgeError::invalid(format!(
                    "direction must be push or pull, got {other:?}"
                )))
            }
        };
        let key = host.connection_key()?;
        // The lease covers the transfer itself, not just the local preparation: a
        // reconnect triggered elsewhere must not kill a running rsync.
        let _lease = self.recovery.enter(&key, self.queue_timeout).await?;
        let binary = self.rsync_binary.resolve().await?;
        let mut metadata = Map::new();
        metadata.insert("kind".into(), Value::from("rsync"));
        metadata.insert("host".into(), Value::from(host.name.clone()));
        metadata.insert(
            "operation".into(),
            Value::from(direction.as_str().to_string()),
        );
        if let Some(container) = container {
            metadata.insert("container".into(), Value::from(container));
        }
        let result_id = self.store.create(metadata)?;
        let sent_flag = Arc::new(AtomicBool::new(false));
        let mut lease = crate::storage::results::ResultLease::new(
            self.store.clone(),
            result_id.clone(),
            sent_flag.clone(),
        );
        lease.arm();
        if let Some(progress) = progress {
            // Announce before a single byte moves: a transfer that is killed halfway
            // must still be addressable from the original request id.
            if let Err(error) = progress.record(
                "execution_results",
                json!({"host": host.name, "result_id": result_id, "kind": "transfer"}),
            ) {
                let _ = self.store.fail_before_send(
                    &result_id,
                    &format!(
                        "request progress could not be persisted: {}",
                        error.message()
                    ),
                );
                lease.disarm();
                return Err(error);
            }
        }
        let out_path = self.store.path(&result_id, "stdout")?;
        let err_path = self.store.path(&result_id, "stderr")?;
        let started = Instant::now();
        let transfer = crate::transport::rsync::transfer(
            &self.pool, &binary, host, local, remote, direction, excludes, delete, timeout,
            container, overwrite, &out_path, &err_path,
        )
        .await;
        let mut values = Map::new();
        match transfer {
            Ok(outcome) => {
                let unknown = outcome.sent && !outcome.completed;
                values.insert("ok".into(), Value::Bool(outcome.exit_code == 0));
                values.insert("exit_code".into(), json!(outcome.exit_code));
                values.insert("executed".into(), Value::Bool(outcome.sent));
                values.insert("timed_out".into(), Value::Bool(outcome.timed_out));
                values.insert("completion_unknown".into(), Value::Bool(unknown));
                values.insert(
                    "execution_state".into(),
                    Value::from(if outcome.completed {
                        "completed"
                    } else if outcome.sent {
                        "unknown"
                    } else {
                        "not_started"
                    }),
                );
                if outcome.timed_out {
                    values.insert("warning".into(), Value::from(
                        "Transfer timed out; remote completion is unknown. Inspect before rerunning.",
                    ));
                    values.insert("failure_stage".into(), Value::from("transfer"));
                }
            }
            Err(error) => {
                // A local capability failure happened before any byte was sent.
                values.insert("ok".into(), Value::Bool(false));
                values.insert("exit_code".into(), json!(1));
                values.insert("executed".into(), Value::Bool(false));
                values.insert("timed_out".into(), Value::Bool(false));
                values.insert("completion_unknown".into(), Value::Bool(false));
                values.insert("execution_state".into(), Value::from("not_started"));
                values.insert("failure_stage".into(), Value::from("transfer_setup"));
                values.insert("warning".into(), Value::from(error.message()));
            }
        }
        values.insert(
            "elapsed_seconds".into(),
            json!(round(started.elapsed().as_secs_f64(), 3)),
        );
        values.insert("session_state".into(), Value::Null);
        sent_flag.store(
            values.get("executed") == Some(&Value::Bool(true)),
            Ordering::SeqCst,
        );
        let meta = lease.complete(values)?;
        Ok(self.outcome_from_meta(host, meta, true))
    }

    pub async fn close_session(
        &self,
        host: &Host,
        session_id: &str,
        internal: bool,
    ) -> BridgeResult<Value> {
        if session_id.starts_with("_fs:") && !internal {
            return Err(BridgeError::invalid(
                "private filesystem worker is not a user session",
            ));
        }
        let key = host.connection_key()?;
        let session_key = (key.clone(), session_id.to_string());
        {
            let gates = self.session_gates.lock().expect("gate lock");
            if let Some(gate) = gates.get(&session_key) {
                if gate.try_lock().is_err() {
                    return Err(BridgeError::invalid(
                        "session is executing; wait for its result before closing",
                    ));
                }
            }
        }
        let slot = {
            let mut shells = self.shells.lock().await;
            shells.remove(&session_key)
        };
        if let Some(slot) = slot {
            let mut shell = slot.lock().await;
            shell.close().await;
        }
        let existed = self
            .known_sessions
            .lock()
            .expect("session lock")
            .remove(&session_key);
        if internal {
            self.session_gates
                .lock()
                .expect("gate lock")
                .remove(&session_key);
        } else {
            let _ = self.save_sessions();
        }
        self.recovery.notify(&key);
        Ok(json!({"ok": true, "closed": existed}))
    }

    /// Full output by default; presentation-only callers opt into a bounded preview.
    pub async fn exec_on(
        &self,
        host: &Host,
        command: &str,
        timeout: f64,
        workdir: bool,
        env_setup: bool,
        preview_only: bool,
    ) -> BridgeResult<ExecOutcome> {
        let script = wrap_command(
            if env_setup {
                host.env_setup.as_deref()
            } else {
                None
            },
            if workdir {
                host.workdir.as_deref()
            } else {
                None
            },
            command,
        );
        let spec = ExecSpec {
            wrapped: true,
            ..Default::default()
        };
        let meta = self
            .execute_to_store(host, &script, timeout, &spec, None)
            .await
            .map_err(|failure| failure.error)?;
        Ok(self.outcome_from_meta(host, meta, preview_only))
    }

    pub fn outcome_from_meta(
        &self,
        host: &Host,
        meta: Map<String, Value>,
        preview_only: bool,
    ) -> ExecOutcome {
        let result_id = meta
            .get("result_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut preview = None;
        let (stdout, stderr) = if preview_only {
            match self.store.preview_snapshot(&result_id, 16384) {
                Ok(snapshot) => {
                    let out = String::from_utf8_lossy(&snapshot.stdout_head).to_string();
                    let err = String::from_utf8_lossy(&snapshot.stderr_head).to_string();
                    preview = Some(Arc::new(snapshot));
                    (out, err)
                }
                Err(_) => (String::new(), String::new()),
            }
        } else {
            let read = |stream: &str| -> String {
                self.store
                    .path(&result_id, stream)
                    .ok()
                    .and_then(|path| std::fs::read(path).ok())
                    .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                    .unwrap_or_default()
            };
            (read("stdout"), read("stderr"))
        };
        let mut recovery = Map::new();
        for key in ["startup_retry_result_id", "connection_recovery"] {
            if let Some(value) = meta.get(key) {
                recovery.insert(key.to_string(), value.clone());
            }
        }
        ExecOutcome {
            host: host.name.clone(),
            exit_code: meta.get("exit_code").and_then(Value::as_i64).unwrap_or(255),
            stdout,
            stderr,
            timed_out: meta
                .get("timed_out")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            result_id,
            preview,
            rejection: queue_rejection(&meta),
            recovery,
            meta,
        }
    }

    pub async fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.recovery.close();
        let slots: Vec<_> = {
            let mut shells = self.shells.lock().await;
            shells.drain().map(|(_key, slot)| slot).collect()
        };
        for slot in slots {
            let mut shell = slot.lock().await;
            shell.close().await;
        }
        self.pool.close().await;
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

pub fn startup_failed(meta: &Map<String, Value>) -> bool {
    meta.get("failure_stage").and_then(Value::as_str) == Some("shell_startup")
        && meta.get("execution_state").and_then(Value::as_str) == Some("not_started")
        && meta.get("completion_unknown") != Some(&Value::Bool(true))
        && meta.get("timed_out") != Some(&Value::Bool(true))
        && meta.get("exit_code").and_then(Value::as_i64) == Some(75)
}

/// Execution rows for a fan-out, each with its own preview budget.
pub fn fanout_rows(
    store: &ResultStore,
    metas: &[Map<String, Value>],
    budget_total: usize,
) -> BridgeResult<Vec<Value>> {
    let budget = budget_total / metas.len().max(1);
    let mut rows = Vec::new();
    for meta in metas {
        let result_id = meta
            .get("result_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut row = Map::new();
        for key in [
            "host",
            "result_id",
            "ok",
            "exit_code",
            "executed",
            "timed_out",
            "elapsed_seconds",
            "session_id",
            "bytes",
            "execution_state",
            "completion_unknown",
            "connection_state",
            "session_state",
            "reconnected",
            "timing",
            "queue_timed_out",
            "failure_stage",
            "warning",
            "startup_retry_result_id",
            "connection_recovery",
            "error",
            "local_error",
        ] {
            if let Some(value) = meta.get(key) {
                row.insert(key.to_string(), value.clone());
            }
        }
        if !result_id.is_empty() {
            // A result whose metadata never landed cannot be read back; that must not
            // hide the other targets' rows.
            if let Ok(preview) = store.preview(&result_id, budget) {
                for (key, value) in preview {
                    row.insert(key, value);
                }
            }
        }
        for (key, value) in queue_rejection(meta) {
            row.insert(key, value);
        }
        rows.push(Value::Object(row));
    }
    Ok(rows)
}

/// A compact proof that a result exists without reading it.
pub fn result_reference(meta: &Map<String, Value>) -> Value {
    let mut row = Map::new();
    for key in ["host", "result_id", "ok", "exit_code", "execution_state"] {
        if let Some(value) = meta.get(key) {
            row.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(row)
}

/// Age of a result in seconds, used by diagnostics only.
pub fn age_seconds(meta: &Map<String, Value>) -> f64 {
    meta.get("created_at")
        .and_then(Value::as_f64)
        .map(|created| round(now() - created, 3))
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    /// Two saves racing in the "wrong" order must not leave the older snapshot behind.
    #[test]
    fn a_concurrent_save_cannot_overwrite_a_newer_snapshot() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::sync::{mpsc, Arc};

        let directory = tempfile::tempdir().unwrap();
        let registry = directory.path().join("shell_sessions.json");
        let known: Arc<Mutex<HashSet<(String, String)>>> = Arc::new(Mutex::new(HashSet::new()));
        let save: Arc<Mutex<()>> = Arc::new(Mutex::new(()));

        known
            .lock()
            .unwrap()
            .insert(("key-a".to_string(), "session-a".to_string()));

        // A snapshots the registry, then waits until B has finished writing.
        let (snapshot_taken, snapshot_wait) = mpsc::channel::<()>();
        let b_done = Arc::new(AtomicBool::new(false));
        let known_a = known.clone();
        let save_a = save.clone();
        let registry_a = registry.clone();
        let gate = b_done.clone();
        let a = std::thread::spawn(move || {
            persist_sessions_with(&registry_a, &known_a, &save_a, || {
                snapshot_taken.send(()).unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
                while !gate.load(AtomicOrdering::SeqCst) {
                    if std::time::Instant::now() > deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            })
        });

        // Only now does B add its session and save: A's snapshot is provably older.
        snapshot_wait.recv().unwrap();
        known
            .lock()
            .unwrap()
            .insert(("key-b".to_string(), "session-b".to_string()));
        let written = persist_sessions(&registry, &known, &save);
        b_done.store(true, AtomicOrdering::SeqCst);
        written.unwrap();
        a.join().unwrap().unwrap();

        let text = std::fs::read_to_string(&registry).unwrap();
        let rows: Value = serde_json::from_str(&text).unwrap();
        let names: Vec<&str> = rows
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row.get("session_id").and_then(Value::as_str))
            .collect();
        assert!(
            names.contains(&"session-a") && names.contains(&"session-b"),
            "registry lost a session: {text}"
        );
    }

    /// An idle interactive terminal keeps its connection: it holds the cwd and env of a
    /// bound shell, so a reconnect triggered elsewhere must not replace it.
    #[test]
    fn an_open_terminal_protects_its_connection() {
        let shells: Arc<AsyncMutex<HashMap<(String, String), Arc<AsyncMutex<ShellSession>>>>> =
            Arc::new(AsyncMutex::new(HashMap::new()));
        let terminals: Arc<std::sync::Mutex<HashMap<String, usize>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        assert!(!connection_protected(&shells, &terminals, "key-1"));

        let guard = {
            let mut registry = terminals.lock().expect("lock");
            *registry.entry("key-1".to_string()).or_insert(0) += 1;
            TerminalProtection {
                registry: terminals.clone(),
                key: "key-1".to_string(),
            }
        };
        assert!(connection_protected(&shells, &terminals, "key-1"));
        // A different connection is unaffected.
        assert!(!connection_protected(&shells, &terminals, "key-2"));

        drop(guard);
        assert!(!connection_protected(&shells, &terminals, "key-1"));
    }

    use super::*;

    #[test]
    fn env_names_are_posix_identifiers() {
        assert!(valid_env_name("PATH"));
        assert!(valid_env_name("_x1"));
        assert!(!valid_env_name("1PATH"));
        assert!(!valid_env_name("A-B"));
        assert!(!valid_env_name(""));
    }

    #[test]
    fn startup_failure_requires_the_full_evidence_set() {
        let mut meta = Map::new();
        meta.insert("failure_stage".into(), json!("shell_startup"));
        meta.insert("execution_state".into(), json!("not_started"));
        meta.insert("completion_unknown".into(), json!(false));
        meta.insert("timed_out".into(), json!(false));
        meta.insert("exit_code".into(), json!(75));
        assert!(startup_failed(&meta));
        meta.insert("exit_code".into(), json!(0));
        assert!(!startup_failed(&meta));
    }

    #[test]
    fn command_rejects_both_container_and_image() {
        let cfg = Arc::new(BastionConfig::default());
        let settings = Arc::new(BridgeSettings {
            state_dir: std::env::temp_dir().join("jms-test-runner"),
            ..Default::default()
        });
        let store =
            Arc::new(ResultStore::new(settings.state_dir.join("results"), 60.0, 60.0).unwrap());
        let runner = Runner::new(cfg, settings, store).unwrap();
        assert!(runner
            .command(Some("c1"), Some("img"), &[], false)
            .unwrap_err()
            .message()
            .contains("choose container or image"));
        assert!(runner
            .command(None, None, &["--x".into()], false)
            .unwrap_err()
            .message()
            .contains("docker_args requires"));
        assert_eq!(runner.command(None, None, &[], false).unwrap(), "bash -s");
        assert_eq!(
            runner
                .command(Some("c1"), None, &["--env".into(), "A=1".into()], true)
                .unwrap(),
            "docker exec -i --env A=1 c1 bash --noprofile --norc"
        );
    }
}
