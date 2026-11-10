//! Remote job lifecycle: submit / status / logs / cancel / bounded wait.
//!
//! A call that *starts* work never blocks on it. The job is launched detached (tmux,
//! or setsid where tmux is missing), writes `status` / `exit_code` / `pid` files plus
//! a `stdout.log` next to its runner, and is addressed by an 8-hex id afterwards.
//! `jms_job_wait` only stops *watching*; a timeout cancels nothing.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::errors::{BridgeError, BridgeResult};
use crate::execution::{ExecOutcome, Runner};
use crate::inventory::{shell_quote, Host};
use crate::scheduler::queue_rejection;
use crate::storage::journal::ProgressSink;

/// Where job state lives on each remote host, relative to the host workdir.
pub const JOB_DIR: &str = ".jms-bridge/jobs";

pub fn validate_job_id(job_id: &str) -> Option<String> {
    let valid = job_id.len() == 8
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if valid {
        None
    } else {
        Some(format!("invalid job id {job_id:?} (expected 8 hex chars)"))
    }
}

pub fn new_job_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

fn launcher_of(stdout: &str) -> String {
    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix("LAUNCHER=") {
            let value = value.trim();
            return if value.is_empty() {
                "unknown".to_string()
            } else {
                value.to_string()
            };
        }
    }
    "unknown".to_string()
}

/// A *shell expression* for the remote job directory — use it unquoted.
pub fn job_root(host: &Host, job_id: &str) -> String {
    let base = host.workdir.clone().unwrap_or_else(|| "~".to_string());
    if let Some(rest) = base.strip_prefix('~') {
        let rest = rest.trim_start_matches('/');
        let tail = if rest.is_empty() {
            format!("{JOB_DIR}/{job_id}")
        } else {
            format!("{rest}/{JOB_DIR}/{job_id}")
        };
        format!("\"$HOME\"/{tail}")
    } else {
        shell_quote(&format!(
            "{}/{JOB_DIR}/{job_id}",
            base.trim_end_matches('/')
        ))
    }
}

fn workdir_expr(workdir: Option<&str>) -> Option<String> {
    let workdir = workdir?;
    if let Some(rest) = workdir.strip_prefix('~') {
        let rest = rest.trim_start_matches('/');
        return Some(if rest.is_empty() {
            "\"$HOME\"".to_string()
        } else {
            format!("\"$HOME\"/{rest}")
        });
    }
    Some(shell_quote(workdir))
}

/// The remote bash script that wraps one job.
pub fn build_runner_script(
    job_id: &str,
    command: &str,
    env_setup: Option<&str>,
    workdir: Option<&str>,
) -> String {
    let mut lines = vec![
        "set -uo pipefail".to_string(),
        // The launcher passes the job root explicitly; the fallback keeps the script
        // usable when run by hand.
        "R=\"${1-}\"".to_string(),
        "[ -n \"$R\" ] || R=\"$(cd \"$(dirname \"$0\")\" && pwd)\"".to_string(),
    ];
    if let Some(env_setup) = env_setup.filter(|value| !value.is_empty()) {
        // Vendor env scripts reference variables that may be unset.
        lines.push("set +u".into());
        lines.push(env_setup.to_string());
        lines.push("set -u".into());
    }
    if let Some(workdir) = workdir_expr(workdir) {
        lines.push(format!("cd {workdir} 2>/dev/null || cd \"$R\""));
    }
    lines.extend([
        "echo \"$$\" > \"$R/pid\"".to_string(),
        "echo running > \"$R/status\"".to_string(),
        "set +e".to_string(),
        // The command runs in a subshell: `exit N` must not skip the status write.
        "(".to_string(),
        command.to_string(),
        ")".to_string(),
        "code=$?".to_string(),
        "echo \"$code\" > \"$R/exit_code\"".to_string(),
        "if [ \"$code\" -eq 0 ]; then echo done > \"$R/status\"; else echo failed > \"$R/status\"; fi"
            .to_string(),
        "exit \"$code\"".to_string(),
        String::new(),
    ]);
    let _ = job_id;
    lines.join("\n")
}

/// The remote script that stages and launches one detached job.
pub fn launch_script(
    root: &str,
    session: &str,
    job_id: &str,
    body: &str,
    env_setup: Option<&str>,
    workdir: Option<&str>,
) -> String {
    let runner = build_runner_script(job_id, body, env_setup, workdir);
    // `root` is a shell expression such as "$HOME"/jobs/abcd1234: it is expanded here,
    // in the launcher shell, so the detached command never depends on inherited
    // environment (a tmux server keeps its own).
    [
        "set -eu".to_string(),
        format!("R={root}"),
        "export R".to_string(),
        "mkdir -p \"$R\"".to_string(),
        format!("cat > \"$R/run.sh\" <<'JMS_RUNNER_EOF'\n{runner}JMS_RUNNER_EOF"),
        // Ack means "the job wrote its own pid or status", which also covers jobs that
        // finished before the launcher looked at them.
        "wait_started() { i=0; while [ \"$i\" -lt 15 ]; do [ -f \"$R/pid\" ] || \
[ -f \"$R/status\" ] && return 0; i=$((i + 1)); sleep 1; done; return 1; }".to_string(),
        "if command -v tmux >/dev/null 2>&1; then".to_string(),
        format!(
            "  tmux new-session -d -s {} \"bash \\\"$R/run.sh\\\" \\\"$R\\\" > \
\\\"$R/stdout.log\\\" 2>&1; echo \\$? > \\\"$R/tmux_exit\\\"\" || \
{{ echo 'tmux refused the session' >&2; exit 4; }}",
            shell_quote(session)
        ),
        "  if wait_started; then echo LAUNCHER=tmux; else echo 'job did not start' >&2; exit 5; fi"
            .to_string(),
        "else".to_string(),
        "  command -v setsid >/dev/null 2>&1 || { echo 'no tmux and no setsid' >&2; exit 3; }"
            .to_string(),
        "  setsid bash \"$R/run.sh\" \"$R\" > \"$R/stdout.log\" 2>&1 < /dev/null &".to_string(),
        "  echo \"$!\" > \"$R/launcher_pid\"".to_string(),
        // A job that already finished has no live pid; its own status file is the ack.
        "  if wait_started; then echo LAUNCHER=setsid; else echo 'job did not start' >&2; exit 5; fi"
            .to_string(),
        "fi".to_string(),
    ]
    .join("\n")
}

/// Whether the detached launcher actually confirmed the job.
///
/// A tracked job id is not the same thing as a started job: the id is kept even when
/// the launcher was refused or its answer was lost, so the caller can reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchState {
    /// The runner wrote its pid/status: the job is really running (or already done).
    Acknowledged,
    /// The launcher answered that it did not start anything (nothing ran).
    Rejected,
    /// The launcher was transmitted but its verdict is missing.
    Unknown,
}

impl LaunchState {
    pub fn as_str(self) -> &'static str {
        match self {
            LaunchState::Acknowledged => "acknowledged",
            LaunchState::Rejected => "rejected",
            LaunchState::Unknown => "unknown",
        }
    }
}

pub struct JobHandle {
    pub job_id: String,
    pub host: String,
    pub session: String,
    pub launcher: String,
    pub state: LaunchState,
}

impl JobHandle {
    pub fn to_json(&self) -> Value {
        json!({"job_id": self.job_id, "host": self.host,
               "session": self.session, "launcher": self.launcher,
               "launch_state": self.state.as_str()})
    }
}

/// Stages that provably end before any remote byte of the job is written.
///
/// `executed: false` only means "nothing ran" when the attempt never left the sender.
const PRE_SEND_STAGES: [&str; 8] = [
    "validation",
    "connection",
    "connection_recovery",
    "execution_queue",
    "session_queue",
    "session",
    "session_registry",
    "channel",
];

/// Decide the launch state from the launcher's own evidence.
///
/// * acknowledged            -> the runner wrote its pid/status: the job runs.
/// * unknown execution state -> the bytes may have arrived; never call that a refusal.
/// * launcher exit 3/4       -> its two "I did not start anything" paths.
/// * `executed: false` before sending -> nothing was transmitted.
/// * everything else         -> unknown; exit 5 is a *wait* timeout, and the detached
///   runner may still start the job after the launcher gave up, so it stays unknown.
pub fn derive_launch_state(acknowledged: bool, meta: &Map<String, Value>) -> LaunchState {
    if acknowledged {
        return LaunchState::Acknowledged;
    }
    let unknown_evidence = meta
        .get("completion_unknown")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || meta
            .get("execution_state")
            .and_then(Value::as_str)
            .map(|state| state == "unknown")
            .unwrap_or(false);
    if unknown_evidence {
        return LaunchState::Unknown;
    }
    let executed = meta.get("executed");
    let stage = meta.get("failure_stage").and_then(Value::as_str);
    if executed == Some(&Value::Bool(true)) {
        // The launcher script itself ran: 3 (no tmux/setsid) and 4 (tmux refused) are
        // its explicit refusals. Exit 5 is only "the runner was not observed yet".
        return match meta.get("exit_code").and_then(Value::as_i64) {
            Some(3) | Some(4) => LaunchState::Rejected,
            _ => LaunchState::Unknown,
        };
    }
    if executed == Some(&Value::Bool(false))
        && stage
            .map(|stage| PRE_SEND_STAGES.contains(&stage))
            .unwrap_or(false)
    {
        return LaunchState::Rejected;
    }
    // No transmission evidence either way: be conservative rather than optimistic.
    LaunchState::Unknown
}

/// One row per requested pair, using the latest observation and marking the pairs that
/// were never observed (`watch_timeout`) instead of inventing a status for them.
fn collect_rows(
    pairs: &[(Host, String)],
    last: &std::collections::HashMap<(String, String), Value>,
    watch_timeout: bool,
) -> Vec<Value> {
    pairs
        .iter()
        .map(
            |(host, job_id)| match last.get(&(host.name.clone(), job_id.clone())) {
                Some(row) => {
                    let mut row = row.clone();
                    if watch_timeout && !is_terminal_status(&row) && is_unfinished_status(&row) {
                        if let Some(map) = row.as_object_mut() {
                            map.insert("watch_timeout".into(), Value::Bool(true));
                        }
                    }
                    row
                }
                None => json!({
                    "host": host.name,
                    "job_id": job_id,
                    "status": "unknown",
                    "ok": false,
                    "watch_timeout": true,
                    "note": "the status scan ran out of budget before this host answered",
                }),
            },
        )
        .collect()
}

/// A row that may still change (as opposed to a terminal one).
fn is_unfinished_status(row: &Value) -> bool {
    row.get("status")
        .and_then(Value::as_str)
        .map(|status| status != "missing")
        .unwrap_or(true)
}

/// Terminal job states for `wait`: nothing may change after them.
const TERMINAL_STATUSES: [&str; 4] = ["done", "failed", "cancelled", "missing"];

fn is_terminal_status(row: &Value) -> bool {
    row.get("status")
        .and_then(Value::as_str)
        .map(|status| TERMINAL_STATUSES.contains(&status))
        .unwrap_or(false)
}

pub struct Jobs {
    runner: Arc<Runner>,
}

impl Jobs {
    pub fn new(runner: Arc<Runner>) -> Self {
        Self { runner }
    }

    /// Launch a detached job; the receipt is durable before any remote byte is sent.
    pub async fn submit(
        &self,
        host: &Host,
        command: &str,
        progress: Option<&dyn ProgressSink>,
    ) -> BridgeResult<(JobHandle, ExecOutcome)> {
        let job_id = new_job_id();
        let session = format!("jms-{job_id}");
        let launch = launch_script(
            &job_root(host, &job_id),
            &session,
            &job_id,
            command,
            host.env_setup.as_deref(),
            host.workdir.as_deref(),
        );
        let mut receipt = Map::new();
        receipt.insert("host".into(), Value::from(host.name.clone()));
        receipt.insert("job_id".into(), Value::from(job_id.clone()));
        receipt.insert("session".into(), Value::from(session.clone()));
        receipt.insert("launch_acknowledged".into(), Value::Bool(false));
        receipt.insert("submission_state".into(), Value::from("prepared"));
        // This write must succeed before any remote bytes may be transmitted.
        if let Some(progress) = progress {
            progress.record("submission_receipts", Value::Object(receipt.clone()))?;
        }
        let outcome = match self
            .runner
            .exec_on(host, &launch, 90.0, false, false, false)
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                ExecOutcome::failure(&host.name, &format!("launch failed: {}", error.message()))
            }
        };
        let acknowledged = outcome.ok() && outcome.stdout.contains("LAUNCHER=");
        // The classification lives in one place so the receipt and the response cannot
        // disagree; it is derived from the execution evidence, never from "we have an id".
        let state = derive_launch_state(acknowledged, &outcome.meta);
        let launcher = launcher_of(&outcome.stdout);
        let metadata = &outcome.meta;
        receipt.insert("result_id".into(), Value::from(outcome.result_id.clone()));
        receipt.insert("launch_acknowledged".into(), Value::Bool(acknowledged));
        receipt.insert("launch_state".into(), Value::from(state.as_str()));
        receipt.insert(
            "completion_unknown".into(),
            Value::Bool(state == LaunchState::Unknown),
        );
        receipt.insert(
            "submission_state".into(),
            Value::from(match state {
                LaunchState::Acknowledged => "acknowledged".to_string(),
                LaunchState::Rejected => "rejected".to_string(),
                LaunchState::Unknown => metadata
                    .get("execution_state")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            }),
        );
        for (key, value) in queue_rejection(metadata) {
            receipt.insert(key, value);
        }
        if let Some(progress) = progress {
            let _ = progress.record("submission_receipts", Value::Object(receipt));
        }
        Ok((
            JobHandle {
                job_id,
                host: host.name.clone(),
                session,
                launcher,
                state,
            },
            outcome,
        ))
    }

    pub async fn status(&self, host: &Host, job_id: &str) -> BridgeResult<Value> {
        if let Some(error) = validate_job_id(job_id) {
            return Err(BridgeError::invalid(error));
        }
        let root = job_root(host, job_id);
        let q = &root;
        let alive_probe = format!(
            "if tmux has-session -t jms-{job_id} 2>/dev/null; then echo yes; \
elif [ -f {q}/pid ] && kill -0 \"$(cat {q}/pid)\" 2>/dev/null; then echo yes; \
else echo no; fi"
        );
        let command = format!(
            "if [ -d {q} ]; then \
echo \"status=$(cat {q}/status 2>/dev/null || echo unknown)\"; \
echo \"exit_code=$(cat {q}/exit_code 2>/dev/null || echo '')\"; \
echo \"pid=$(cat {q}/pid 2>/dev/null || echo '')\"; \
echo \"log_bytes=$(stat -c %s {q}/stdout.log 2>/dev/null || echo 0)\"; \
echo \"alive=$({alive_probe})\"; \
else echo 'status=missing'; fi"
        );
        let outcome = self
            .runner
            .exec_on(host, &command, 60.0, false, false, false)
            .await?;
        let mut parsed = Map::new();
        parsed.insert("host".into(), Value::from(host.name.clone()));
        parsed.insert("job_id".into(), Value::from(job_id));
        for line in outcome.stdout.lines() {
            if let Some((key, value)) = line.split_once('=') {
                parsed.insert(key.trim().to_string(), Value::from(value.trim()));
            }
        }
        parsed.insert("ok".into(), Value::Bool(outcome.ok()));
        Ok(Value::Object(parsed))
    }

    /// Status for several (host, job) pairs with bounded concurrency.
    ///
    /// Sequential probing made a multi-host watch cost the sum of every target's
    /// latency; independent targets now run side by side, capped so a large fan-out
    /// cannot open an unbounded number of channels.
    pub async fn status_many(&self, pairs: &[(Host, String)]) -> Vec<Value> {
        const MAX_IN_FLIGHT: usize = 4;
        let mut set = tokio::task::JoinSet::new();
        let limit = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        for (index, (host, job_id)) in pairs.iter().enumerate() {
            let runner = self.runner.clone();
            let host = host.clone();
            let job_id = job_id.clone();
            let permit = limit.clone();
            let jobs = Jobs { runner };
            set.spawn(async move {
                let _permit = permit.acquire_owned().await;
                let row = match jobs.status(&host, &job_id).await {
                    Ok(value) => value,
                    Err(error) => json!({"host": host.name, "job_id": job_id,
                                         "ok": false, "error": error.message()}),
                };
                (index, row)
            });
        }
        let mut rows: Vec<(usize, Value)> = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(entry) => rows.push(entry),
                Err(error) => rows.push((
                    usize::MAX,
                    json!({"ok": false,
                    "error": format!("status task failed: {error}")}),
                )),
            }
        }
        // Keep the caller's order so pairing rows with inputs stays trivial.
        rows.sort_by_key(|(index, _)| *index);
        rows.into_iter().map(|(_, row)| row).collect()
    }

    /// Report each target's status as soon as it is known.
    ///
    /// `wait` uses this so a finished host is recorded even when another host never
    /// answers and the overall scan has to be abandoned.
    async fn status_incremental(
        &self,
        pairs: &[(Host, String)],
    ) -> tokio::sync::mpsc::Receiver<(usize, Value)> {
        const MAX_IN_FLIGHT: usize = 4;
        let limit = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        let (sender, receiver) = tokio::sync::mpsc::channel(pairs.len().max(1));
        for (index, (host, job_id)) in pairs.iter().enumerate() {
            let runner = self.runner.clone();
            let host = host.clone();
            let job_id = job_id.clone();
            let permit = limit.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                let _permit = permit.acquire_owned().await;
                let jobs = Jobs { runner };
                let row = match jobs.status(&host, &job_id).await {
                    Ok(value) => value,
                    Err(error) => json!({"host": host.name, "job_id": job_id,
                                         "ok": false, "error": error.message()}),
                };
                let _ = sender.send((index, row)).await;
            });
        }
        drop(sender);
        receiver
    }

    pub async fn logs(
        &self,
        host: &Host,
        job_id: &str,
        offset: u64,
        max_bytes: u64,
    ) -> BridgeResult<Value> {
        if let Some(error) = validate_job_id(job_id) {
            return Err(BridgeError::invalid(error));
        }
        let log_path = format!("{}/stdout.log", job_root(host, job_id));
        let command = format!(
            "if [ -f {log_path} ]; then size=$(stat -c %s {log_path}); echo \"size=$size\"; \
tail -c +{} {log_path} | head -c {max_bytes}; else echo 'size=0'; fi",
            offset + 1
        );
        let outcome = self
            .runner
            .exec_on(host, &command, 60.0, false, false, false)
            .await?;
        let mut size = 0u64;
        let mut body = outcome.stdout.clone();
        if let Some(rest) = body.strip_prefix("size=") {
            let (first, remainder) = match rest.split_once('\n') {
                Some(parts) => parts,
                None => (rest, ""),
            };
            size = first.parse().unwrap_or(0);
            body = remainder.to_string();
        }
        // Bytes this read actually delivered — never a re-encoded length, which can
        // overshoot on a mid-UTF-8 clip and skip data on the next poll.
        let consumed = max_bytes.min(size.saturating_sub(offset));
        Ok(json!({
            "ok": outcome.ok(),
            "host": host.name,
            "job_id": job_id,
            "offset": offset,
            "size": size,
            "next_offset": offset + consumed,
            "log": body,
            "exit_code": outcome.exit_code,
            "error": if outcome.ok() { String::new() } else {
                outcome.stderr.trim().chars().take(400).collect::<String>()
            },
        }))
    }

    pub async fn cancel(&self, host: &Host, job_id: &str) -> BridgeResult<Value> {
        if let Some(error) = validate_job_id(job_id) {
            return Err(BridgeError::invalid(error));
        }
        let root = job_root(host, job_id);
        let command = format!(
            "killed=no; \
status_before=$(cat {root}/status 2>/dev/null || echo missing); \
if tmux has-session -t jms-{job_id} 2>/dev/null; then \
tmux kill-session -t jms-{job_id} 2>/dev/null && killed=yes; fi; \
if [ -f {root}/pid ]; then pid=$(cat {root}/pid); \
if kill -TERM \"-$pid\" 2>/dev/null || kill -TERM \"$pid\" 2>/dev/null; then killed=yes; fi; fi; \
if [ \"$killed\" = yes ]; then echo cancelled > {root}/status 2>/dev/null || true; fi; \
echo \"killed=$killed\"; \
echo \"status_before=$status_before\""
        );
        let outcome = self
            .runner
            .exec_on(host, &command, 60.0, false, false, false)
            .await?;
        let killed = outcome.stdout.contains("killed=yes");
        let status_before = outcome
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("status_before="))
            .unwrap_or("missing")
            .trim()
            .to_string();
        let already_finished = matches!(status_before.as_str(), "done" | "failed" | "cancelled");
        Ok(json!({
            "host": host.name,
            "job_id": job_id,
            "killed": killed,
            "cancelled": killed,
            "status_before": status_before,
            "already_finished": already_finished,
            "ok": outcome.ok(),
            "result_id": outcome.result_id,
            "execution_state": outcome.meta.get("execution_state").cloned().unwrap_or(Value::Null),
            "completion_unknown": outcome.meta.get("completion_unknown").cloned().unwrap_or(Value::Null),
        }))
    }

    pub async fn list_jobs(&self, host: &Host) -> BridgeResult<Vec<String>> {
        let command = "tmux ls 2>/dev/null | grep -o '^jms-[0-9a-f]\\{8\\}' || true";
        let outcome = self
            .runner
            .exec_on(host, command, 60.0, false, false, false)
            .await?;
        Ok(outcome
            .stdout
            .lines()
            .filter_map(|line| line.trim().strip_prefix("jms-").map(str::to_string))
            .collect())
    }

    /// Poll until every job is terminal or the deadline passes; cancels nothing.
    pub async fn wait(
        &self,
        pairs: &[(Host, String)],
        timeout: f64,
        interval: f64,
    ) -> (Vec<Value>, bool) {
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs_f64(timeout.max(0.0));
        // Rows are recorded the moment they arrive, so a host that answered in the current
        // round keeps its verdict even if another host never answers.
        let mut last: std::collections::HashMap<(String, String), Value> =
            std::collections::HashMap::new();
        // Targets that reached a terminal state are not probed again.
        let mut pending: Vec<(Host, String)> = pairs.to_vec();
        loop {
            if pending.is_empty() {
                return (collect_rows(pairs, &last, false), true);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return (collect_rows(pairs, &last, true), false);
            }
            let mut stream = self.status_incremental(&pending).await;
            let scan_deadline = tokio::time::Instant::now() + remaining;
            let mut answered: Vec<(String, String, bool)> = Vec::new();
            loop {
                match tokio::time::timeout_at(scan_deadline, stream.recv()).await {
                    Ok(Some((_, row))) => {
                        let key = (
                            row.get("host")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                            row.get("job_id")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                        );
                        let terminal = is_terminal_status(&row);
                        answered.push((key.0.clone(), key.1.clone(), terminal));
                        last.insert(key, row);
                    }
                    // Every answer of this round arrived.
                    Ok(None) => break,
                    // Out of budget: keep what was already recorded, flag the rest.
                    Err(_) => return (collect_rows(pairs, &last, true), false),
                }
            }
            pending.retain(|(host, job_id)| {
                !answered
                    .iter()
                    .any(|(name, id, terminal)| *terminal && name == &host.name && id == job_id)
            });
            if pending.is_empty() {
                return (collect_rows(pairs, &last, false), true);
            }
            let sleep = std::time::Duration::from_secs_f64(interval.max(0.1));
            let sleep = sleep.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            if sleep.is_zero() {
                return (collect_rows(pairs, &last, true), false);
            }
            tokio::time::sleep(sleep).await;
        }
    }

    pub async fn cancel_many(&self, pairs: &[(Host, String)]) -> Vec<Value> {
        let mut out = Vec::new();
        for (host, job_id) in pairs {
            match self.cancel(host, job_id).await {
                Ok(value) => out.push(value),
                Err(error) => out.push(json!({
                    "host": host.name, "job_id": job_id, "killed": false, "ok": false,
                    "error": error.message(),
                })),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(workdir: Option<&str>) -> Host {
        Host {
            name: "asset-1".into(),
            workdir: workdir.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn job_ids_are_eight_lowercase_hex_characters() {
        let job_id = new_job_id();
        assert_eq!(job_id.len(), 8);
        assert!(validate_job_id(&job_id).is_none());
        assert!(validate_job_id("ABCD1234").is_some());
        assert_eq!(
            validate_job_id("nope").unwrap(),
            "invalid job id \"nope\" (expected 8 hex chars)"
        );
    }

    #[test]
    fn job_root_expands_home_without_double_quoting() {
        assert_eq!(
            job_root(&host(None), "abcd1234"),
            "\"$HOME\"/.jms-bridge/jobs/abcd1234"
        );
        assert_eq!(
            job_root(&host(Some("~/work")), "abcd1234"),
            "\"$HOME\"/work/.jms-bridge/jobs/abcd1234"
        );
        assert_eq!(
            job_root(&host(Some("/data/run")), "abcd1234"),
            "'/data/run/.jms-bridge/jobs/abcd1234'"
        );
    }

    #[test]
    fn runner_records_status_even_when_the_command_exits() {
        let script = build_runner_script("abcd1234", "exit 7", Some("source env.sh"), Some("/w"));
        // The command runs in a subshell so the wrapper still records the exit code.
        assert!(script.contains("\n(\nexit 7\n)\ncode=$?"));
        assert!(script.contains("echo \"$code\" > \"$R/exit_code\""));
        assert!(script.contains("> \"$R/status\""));
        assert!(script.contains("set +u\nsource env.sh\nset -u"));
        assert!(script.contains("cd '/w' 2>/dev/null || cd \"$R\""));
    }

    #[test]
    fn launch_prefers_tmux_and_falls_back_to_setsid() {
        let script = launch_script(
            "\"$HOME\"/jobs/abcd1234",
            "jms-abcd1234",
            "abcd1234",
            "python train.py",
            None,
            None,
        );
        assert!(script.contains("cat > \"$R/run.sh\" <<'JMS_RUNNER_EOF'"));
        assert!(script.contains("command -v tmux"));
        assert!(script.contains("tmux new-session -d -s 'jms-abcd1234'"));
        assert!(script.contains("echo LAUNCHER=tmux"));
        // Detached commands use absolute paths: a tmux/setsid child does not inherit
        // the launcher's shell variables.
        assert!(script.contains("R=\"$HOME\"/jobs/abcd1234"));
        assert!(script.contains("wait_started"));
        // The detached pane gets an expanded absolute path, never a bare "$R".
        assert!(script.contains("tmux new-session -d -s 'jms-abcd1234'"));
        assert!(script.contains("\\\"$R/run.sh\\\""));
        assert!(script.contains("no tmux and no setsid"));
    }

    /// A job that finishes before the launcher looks at it must still be
    /// acknowledged: the runner writes `pid`/`status` before it does any work.
    #[test]
    fn fast_job_is_acknowledged_even_though_its_process_is_gone() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("jobs");
        let script = launch_script(
            root.to_str().unwrap(),
            "jms-abc12345",
            "abc12345",
            "echo quick; exit 3",
            None,
            None,
        );
        // Force the setsid branch: a PATH with setsid but without tmux.
        let bin = directory.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for tool in [
            "setsid", "bash", "sh", "cat", "sleep", "kill", "mkdir", "echo", "dirname",
        ] {
            let source = ["/usr/bin", "/bin"]
                .iter()
                .map(|dir| std::path::Path::new(dir).join(tool))
                .find(|path| path.exists());
            if let Some(source) = source {
                let _ = std::os::unix::fs::symlink(source, bin.join(tool));
            }
        }
        let output = std::process::Command::new("/bin/bash")
            .arg("-c")
            .arg(&script)
            .env("PATH", &bin)
            .output()
            .expect("launcher script runs");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(
            stdout.contains("LAUNCHER=setsid"),
            "launcher did not acknowledge a fast job: rc={:?} stdout={stdout:?} stderr={:?} tree={:?}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
            std::fs::read_dir(&root)
                .map(|entries| entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name())
                    .collect::<Vec<_>>())
                .unwrap_or_default()
        );
        let status = std::fs::read_to_string(root.join("status")).unwrap_or_default();
        assert_eq!(status.trim(), "failed", "exit 3 must be recorded as failed");
        let code = std::fs::read_to_string(root.join("exit_code")).unwrap_or_default();
        assert_eq!(code.trim(), "3");
        let log = std::fs::read_to_string(root.join("stdout.log")).unwrap_or_default();
        assert!(log.contains("quick"), "job output missing: {log:?}");
    }

    fn evidence(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn a_transmitted_but_unconfirmed_launch_stays_unknown() {
        // The execution layer reported "sent, no evidence": that is not a refusal.
        let meta = evidence(json!({
            "executed": false,
            "execution_state": "unknown",
            "completion_unknown": true,
        }));
        assert_eq!(derive_launch_state(false, &meta), LaunchState::Unknown);
    }

    #[test]
    fn a_launcher_that_only_timed_out_waiting_stays_unknown() {
        // Exit 5 means "no pid/status was seen yet"; the detached runner may still
        // start the job, so calling it a refusal would invite a duplicate.
        let meta = evidence(json!({
            "executed": true,
            "exit_code": 5,
            "execution_state": "completed",
            "completion_unknown": false,
        }));
        assert_eq!(derive_launch_state(false, &meta), LaunchState::Unknown);
    }

    #[test]
    fn the_two_explicit_launcher_refusals_are_rejections() {
        for code in [3, 4] {
            let meta = evidence(json!({
                "executed": true,
                "exit_code": code,
                "execution_state": "completed",
                "completion_unknown": false,
            }));
            assert_eq!(
                derive_launch_state(false, &meta),
                LaunchState::Rejected,
                "exit {code} must be a refusal"
            );
        }
    }

    #[test]
    fn a_failure_before_sending_is_a_rejection() {
        let meta = evidence(json!({
            "executed": false,
            "execution_state": "not_started",
            "completion_unknown": false,
            "failure_stage": "channel",
        }));
        assert_eq!(derive_launch_state(false, &meta), LaunchState::Rejected);
        // Without a pre-send stage the same flags are not enough to claim a refusal.
        let unclear = evidence(json!({
            "executed": false,
            "execution_state": "not_started",
            "completion_unknown": false,
        }));
        assert_eq!(derive_launch_state(false, &unclear), LaunchState::Unknown);
    }

    #[test]
    fn an_acknowledged_launcher_wins_over_any_other_flag() {
        let meta = evidence(json!({"executed": true, "exit_code": 5}));
        assert_eq!(derive_launch_state(true, &meta), LaunchState::Acknowledged);
    }

    #[test]
    fn wait_rows_keep_known_statuses_and_flag_only_the_unwatched_ones() {
        let pairs = vec![
            (host(None), "aaaa1111".to_string()),
            (host(None), "bbbb2222".to_string()),
        ];
        let mut last = std::collections::HashMap::new();
        last.insert(
            ("asset-1".to_string(), "aaaa1111".to_string()),
            json!({"host": "asset-1", "job_id": "aaaa1111", "status": "done", "exit_code": "0"}),
        );
        // A host that already answered keeps its verdict...
        let rows = collect_rows(&pairs, &last, true);
        assert_eq!(rows[0]["status"], "done");
        assert!(rows[0].get("watch_timeout").is_none());
        // ...while the one that never answered is flagged, not invented.
        assert_eq!(rows[1]["status"], "unknown");
        assert_eq!(rows[1]["watch_timeout"], true);
        assert_eq!(rows.len(), pairs.len());
    }

    #[test]
    fn a_cancelled_job_is_a_terminal_state_for_wait() {
        for status in ["done", "failed", "cancelled", "missing"] {
            assert!(
                is_terminal_status(&json!({"status": status})),
                "{status} must end the watch"
            );
        }
        for status in ["running", "queued", "unknown", ""] {
            assert!(!is_terminal_status(&json!({"status": status})), "{status}");
        }
        // A row without a status is not terminal either.
        assert!(!is_terminal_status(&json!({"host": "h1"})));
    }

    #[test]
    fn launcher_parses_only_the_launcher_line() {
        assert_eq!(launcher_of("LAUNCHER=tmux\n"), "tmux");
        assert_eq!(launcher_of("noise\nLAUNCHER=setsid\n"), "setsid");
        assert_eq!(launcher_of("nothing"), "unknown");
    }
}
