//! Remote job lifecycle: submit / status / logs / cancel / bounded wait.
//!
//! A call that *starts* work never blocks on it. The job is launched detached (tmux,
//! or setsid where tmux is missing), writes `status` / `exit_code` / `pid` files plus
//! a `stdout.log` next to its runner, and is addressed by an 8-hex id afterwards.
//! `jms_job_wait` only stops *watching*; a timeout cancels nothing.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

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

/// Open once so the watermark and bytes come from the same file even if the
/// pathname is replaced. Encode bytes so UTF-8 replacement cannot affect the cursor.
fn job_log_command(log_path: &str, offset: u64, max_bytes: u64, tail: bool) -> String {
    job_log_command_with_generation(log_path, offset, max_bytes, tail, false)
}

fn job_log_command_with_generation(
    log_path: &str,
    offset: u64,
    max_bytes: u64,
    tail: bool,
    generation: bool,
) -> String {
    let position = if tail {
        format!("offset=$((size > {max_bytes} ? size - {max_bytes} : 0))")
    } else {
        format!("offset={offset}")
    };
    let (missing_generation, read_generation) = if generation {
        (
            "printf 'generation=missing\\n'",
            r#"generation=$(stat -Lc %d:%i "/proc/self/fd/3") || exit
printf 'generation=%s\n' "$generation""#,
        )
    } else {
        ("", "")
    };
    format!(
        r#"(
if [ ! -f {log_path} ]; then
  {missing_generation}
  printf 'size=0\noffset={missing_offset}\n'
  exit 0
fi
exec 3< {log_path} || exit
{read_generation}
size=$(stat -Lc %s "/proc/self/fd/3") || exit
{position}
printf 'size=%s\noffset=%s\n' "$size" "$offset"
remaining=$((size - offset))
if [ "$remaining" -gt 0 ]; then
  count=$(({max_bytes} < remaining ? {max_bytes} : remaining))
  set -o pipefail
  dd bs=4096 iflag=skip_bytes,count_bytes skip="$offset" count="$count" status=none <&3 | base64 -w0
fi
)"#,
        missing_offset = if tail { 0 } else { offset },
    )
}

fn parse_job_log(
    output: &str,
    requested: u64,
    max_bytes: u64,
    tail: bool,
) -> BridgeResult<(u64, u64, Vec<u8>)> {
    let malformed = || BridgeError::invalid("invalid response from remote job log reader");
    let mut fields = output.splitn(3, '\n');
    let mut read_field = |prefix: &str| fields.next()?.strip_prefix(prefix)?.parse::<u64>().ok();
    let size = read_field("size=").ok_or_else(malformed)?;
    let offset = read_field("offset=").ok_or_else(malformed)?;
    let expected = if tail {
        size.saturating_sub(max_bytes)
    } else {
        requested
    };
    if offset != expected {
        return Err(malformed());
    }
    let body = BASE64
        .decode(fields.next().unwrap_or_default().trim_end())
        .map_err(|_| malformed())?;
    if body.len() as u64 > max_bytes.min(size.saturating_sub(offset)) {
        return Err(malformed());
    }
    Ok((size, offset, body))
}

const JOB_LOG_SCAN_BYTES: u64 = 1024 * 1024;
const JOB_LOG_MATCHES: usize = 20;
pub(crate) const JOB_LOG_PATTERN_BYTES: usize = 1024;

#[derive(Debug, PartialEq, Eq)]
struct JobLogCursor<'a> {
    generation: &'a str,
    offset: u64,
    size: u64,
}

fn job_log_search_scope(host: &Host, job_id: &str, pattern: &str) -> String {
    let key = json!([
        host.asset_id.as_ref().unwrap_or(&host.name),
        host.asset_id.is_none().then_some(&host.address),
        host.account,
        host.workdir,
        job_id,
        pattern
    ]);
    hex::encode(Sha256::digest(key.to_string()))
}

fn encode_search_cursor(generation: &str, offset: u64, size: u64, scope: &str) -> String {
    format!("v1:{offset}:{size}:{generation}:{scope}")
}

fn job_log_generation(generation: &str) -> bool {
    generation.split_once(':').is_some_and(|(dev, ino)| {
        !dev.is_empty()
            && !ino.is_empty()
            && dev.bytes().all(|b| b.is_ascii_digit())
            && ino.bytes().all(|b| b.is_ascii_digit())
    })
}

fn decode_search_cursor<'a>(cursor: &'a str, scope: &str) -> BridgeResult<JobLogCursor<'a>> {
    let invalid =
        || BridgeError::invalid("job log cursor does not match this target, job or pattern");
    let (without_scope, cursor_scope) = cursor.rsplit_once(':').ok_or_else(invalid)?;
    if cursor_scope != scope {
        return Err(invalid());
    }
    let mut parts = without_scope.splitn(4, ':');
    if parts.next() != Some("v1") {
        return Err(invalid());
    }
    let offset = parts
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .ok_or_else(invalid)?;
    let size = parts
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .ok_or_else(invalid)?;
    let generation = parts
        .next()
        .filter(|s| job_log_generation(s))
        .ok_or_else(invalid)?;
    if offset > size || size > i64::MAX as u64 {
        return Err(invalid());
    }
    Ok(JobLogCursor {
        generation,
        offset,
        size,
    })
}

fn parse_search_frame(output: &str, offset: u64) -> BridgeResult<(&str, u64, Vec<u8>)> {
    let invalid = || BridgeError::invalid("invalid job log search frame");
    let (prefix, body) = output.split_once('\n').ok_or_else(invalid)?;
    let generation = prefix.strip_prefix("generation=").ok_or_else(invalid)?;
    if generation != "missing" && !job_log_generation(generation) {
        return Err(invalid());
    }
    let (size, _, bytes) = parse_job_log(body, offset, JOB_LOG_SCAN_BYTES, false)?;
    Ok((generation, size, bytes))
}

fn search_page_needs_reset(
    previous: Option<&JobLogCursor<'_>>,
    generation: &str,
    size: u64,
    offset: u64,
    read: usize,
) -> bool {
    previous.is_some_and(|c| c.generation != generation || c.size > size)
        || read as u64 != JOB_LOG_SCAN_BYTES.min(size.saturating_sub(offset))
}

fn find_literals(
    body: &[u8],
    needle: &[u8],
    offset: u64,
    output_limit: usize,
) -> (Vec<Value>, u64, bool) {
    // Matches starting in this deferred suffix did not yet have enough bytes
    // to be decided. Start there on the next page or after an append.
    let decided = body.len().saturating_sub(needle.len() - 1);
    let mut rows = Vec::new();
    let mut spent = 2; // JSON array brackets
    let mut matched = 0;
    let mut failure = vec![0; needle.len()];
    for i in 1..needle.len() {
        while matched > 0 && needle[i] != needle[matched] {
            matched = failure[matched - 1];
        }
        matched += usize::from(needle[i] == needle[matched]);
        failure[i] = matched;
    }
    matched = 0;
    for (i, byte) in body.iter().enumerate() {
        while matched > 0 && *byte != needle[matched] {
            matched = failure[matched - 1];
        }
        matched += usize::from(*byte == needle[matched]);
        if matched != needle.len() {
            continue;
        }
        let at = i + 1 - needle.len();
        let absolute = offset + at as u64;
        let lo = at.saturating_sub(24);
        let hi = (at + 72).min(body.len());
        let row = json!({"offset":absolute, "text_offset":offset + lo as u64,
            "text":String::from_utf8_lossy(&body[lo..hi])});
        let cost = row.to_string().len() + usize::from(!rows.is_empty());
        if rows.len() == JOB_LOG_MATCHES || spent + cost > output_limit {
            // Re-read the first unreturned match, rather than skipping it.
            return (rows, absolute, false);
        }
        spent += cost;
        rows.push(row);
        matched = failure[matched - 1];
    }
    (rows, offset + decided as u64, true)
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

/// Address observations by permitted asset/connection identity, not display name.
fn pair_key(host: &Host, id: &str) -> (String, String) {
    let identity = host
        .connection_key()
        .unwrap_or_else(|_| match host.asset_id.as_deref() {
            Some(asset) => format!("asset:{asset}"),
            None => format!("name:{}", host.name),
        });
    (identity, id.to_string())
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
        .map(|(host, job_id)| match last.get(&pair_key(host, job_id)) {
            Some(row) => {
                let mut row = row.clone();
                if watch_timeout && !is_terminal_status(&row) {
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
        })
        .collect()
}

/// Terminal job states for `wait`: nothing may change after them.
const TERMINAL_STATUSES: [&str; 4] = ["done", "failed", "cancelled", "missing"];

pub(crate) fn is_terminal_status(row: &Value) -> bool {
    if row.get("ok") == Some(&Value::Bool(false)) {
        return false;
    }
    row.get("status")
        .and_then(Value::as_str)
        .map(|status| TERMINAL_STATUSES.contains(&status))
        .unwrap_or(false)
}

/// Watch read-only probes with task ownership scoped to this operation. Dropping
/// the stream at the deadline also drops queued/in-flight probes: nothing detached
/// can consume another permit or start later. Rows are keyed on input identity,
/// never on the order or contents of a remote response.
async fn watch_pairs<F, Fut>(
    pairs: &[(Host, String)],
    deadline: tokio::time::Instant,
    interval: std::time::Duration,
    probe: F,
) -> (Vec<Value>, bool)
where
    F: Fn(Host, String) -> Fut + Sync,
    Fut: std::future::Future<Output = BridgeResult<Value>>,
{
    use futures::{stream::FuturesUnordered, StreamExt};
    use std::{cmp::Reverse, collections::BinaryHeap};
    use tokio::time::{sleep_until, Instant};
    const MAX_IN_FLIGHT: usize = 4;

    let mut seen = std::collections::HashSet::new();
    let unique: Vec<_> = pairs
        .iter()
        .filter(|(host, id)| seen.insert(pair_key(host, id)))
        .collect();
    let now = Instant::now();
    let mut scheduled: BinaryHeap<_> = (0..unique.len())
        .map(|index| Reverse((now, index)))
        .collect();
    let mut in_flight = FuturesUnordered::new();
    let mut last = std::collections::HashMap::new();

    while Instant::now() < deadline {
        while in_flight.len() < MAX_IN_FLIGHT {
            let Some(&Reverse((due, index))) = scheduled.peek() else {
                break;
            };
            let now = Instant::now();
            if now < due || now >= deadline {
                break;
            }
            scheduled.pop();
            let (host, id) = unique[index];
            let probe = &probe;
            in_flight.push(async move {
                // Enqueuing a future does not poll it. Check again at actual start.
                if Instant::now() >= deadline {
                    return None;
                }
                let key = pair_key(host, id);
                let row = match probe(host.clone(), id.clone()).await {
                    Ok(row) => row,
                    Err(error) => json!({"host":host.name,"job_id":id,"ok":false,
                                         "error":error.message()}),
                };
                Some((index, key, row))
            });
        }

        if scheduled.is_empty() && in_flight.is_empty() {
            return (collect_rows(pairs, &last, false), true);
        }

        // A hanging status request occupies only its own slot. A timely running
        // response can be rechecked independently at its own next poll time.
        let next_ready = if in_flight.len() < MAX_IN_FLIGHT {
            scheduled
                .peek()
                .map(|Reverse((due, _))| *due)
                .unwrap_or(deadline)
        } else {
            deadline
        };
        tokio::select! {
            biased;
            _ = sleep_until(deadline) => break,
            observed = in_flight.next(), if !in_flight.is_empty() => {
                if let Some(Some((index, key, row))) = observed {
                    if !is_terminal_status(&row) {
                        scheduled.push(Reverse((Instant::now() + interval, index)));
                    }
                    last.insert(key, row);
                }
            }
            _ = sleep_until(next_ready) => {}
        }
    }
    let finished = last.len() == unique.len() && last.values().all(is_terminal_status);
    (collect_rows(pairs, &last, !finished), finished)
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
        if let Some(asset_id) = &host.asset_id {
            receipt.insert("asset_id".into(), json!(asset_id));
        }
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

    pub async fn logs(
        &self,
        host: &Host,
        job_id: &str,
        offset: u64,
        max_bytes: u64,
        tail: bool,
    ) -> BridgeResult<Value> {
        if let Some(error) = validate_job_id(job_id) {
            return Err(BridgeError::invalid(error));
        }
        let log_path = format!("{}/stdout.log", job_root(host, job_id));
        let command = job_log_command(&log_path, offset, max_bytes, tail);
        let outcome = self
            .runner
            .exec_on(host, &command, 60.0, false, false, false)
            .await?;
        let (size, offset, body) = if outcome.ok() {
            parse_job_log(&outcome.stdout, offset, max_bytes, tail)?
        } else {
            (0, offset, Vec::new())
        };
        let consumed = body.len() as u64;
        Ok(json!({
            "ok": outcome.ok(),
            "host": host.name,
            "job_id": job_id,
            "offset": offset,
            "size": size,
            "next_offset": offset + consumed,
            "log": String::from_utf8_lossy(&body),
            "exit_code": outcome.exit_code,
            "error": if outcome.ok() { String::new() } else {
                outcome.stderr.trim().chars().take(400).collect::<String>()
            },
        }))
    }

    pub async fn search_logs(
        &self,
        host: &Host,
        job_id: &str,
        offset: u64,
        output_limit: usize,
        pattern: &str,
        cursor: Option<&str>,
    ) -> BridgeResult<Value> {
        if let Some(error) = validate_job_id(job_id) {
            return Err(BridgeError::invalid(error));
        }
        if pattern.is_empty() || pattern.len() > JOB_LOG_PATTERN_BYTES {
            return Err(BridgeError::invalid(
                "job log search pattern must be 1–1024 UTF-8 bytes",
            ));
        }
        let scope = job_log_search_scope(host, job_id, pattern);
        let previous = cursor
            .map(|c| decode_search_cursor(c, &scope))
            .transpose()?;
        let offset = previous.as_ref().map_or(offset, |c| c.offset);
        let log_path = format!("{}/stdout.log", job_root(host, job_id));
        let command =
            job_log_command_with_generation(&log_path, offset, JOB_LOG_SCAN_BYTES, false, true);
        let outcome = self
            .runner
            .exec_on(host, &command, 60.0, false, false, false)
            .await?;
        if !outcome.ok() {
            return Ok(json!({"ok":false,"host":host.name,"job_id":job_id,
                "matches":[],"next_offset":offset,"next_cursor":cursor,
                "exit_code":outcome.exit_code,
                "error":outcome.stderr.trim().chars().take(400).collect::<String>()}));
        }
        let (generation, size, body) = parse_search_frame(&outcome.stdout, offset)?;
        if search_page_needs_reset(previous.as_ref(), generation, size, offset, body.len()) {
            return Ok(
                json!({"ok":false,"host":host.name,"job_id":job_id,"size":size,
                "matches":[],"reset":true,"reason":"log_replaced_or_truncated","next_offset":0}),
            );
        }
        let (matches, next_offset, complete) =
            find_literals(&body, pattern.as_bytes(), offset, output_limit);
        let next_cursor = if generation != "missing" && next_offset <= size {
            Some(encode_search_cursor(generation, next_offset, size, &scope))
        } else {
            None
        };
        Ok(
            json!({"ok":true,"host":host.name,"job_id":job_id,"size":size,
            "matches":matches,"offset":offset,"next_offset":next_offset,"next_cursor":next_cursor,
            "scan_bytes":body.len(),"eof":complete && offset + body.len() as u64 >= size}),
        )
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
        self.wait_until(pairs, deadline, interval).await
    }

    pub(crate) async fn wait_until(
        &self,
        pairs: &[(Host, String)],
        deadline: tokio::time::Instant,
        interval: f64,
    ) -> (Vec<Value>, bool) {
        watch_pairs(
            pairs,
            deadline,
            std::time::Duration::from_secs_f64(interval.max(0.1)),
            |host, id| async move { self.status(&host, &id).await },
        )
        .await
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
    fn search_paginates_without_matches_then_finds_a_boundary_literal_after_append() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("search ' log");
        let mut body = vec![b'.'; JOB_LOG_SCAN_BYTES as usize - 2];
        body.extend_from_slice(b"[$");
        std::fs::write(&path, &body).unwrap();
        let literal = b"[$?]";
        let log = shell_quote(path.to_str().unwrap());
        let read = |offset| {
            let output = std::process::Command::new("bash")
                .arg("-c")
                .arg(job_log_command_with_generation(
                    &log,
                    offset,
                    JOB_LOG_SCAN_BYTES,
                    false,
                    true,
                ))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        };

        let page = read(0);
        let (generation, size, body) = parse_search_frame(&page, 0).unwrap();
        assert_eq!(size, JOB_LOG_SCAN_BYTES);
        let (rows, next, complete) = find_literals(&body, literal, 0, 1024);
        assert!(complete && rows.is_empty());
        assert_eq!(next, size - 3);
        let marker = encode_search_cursor(generation, next, size, "scope");
        let previous = decode_search_cursor(&marker, "scope").unwrap();

        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"?]more")
            .unwrap();
        let page = read(next);
        let (new_generation, new_size, body) = parse_search_frame(&page, next).unwrap();
        assert!(!search_page_needs_reset(
            Some(&previous),
            new_generation,
            new_size,
            next,
            body.len()
        ));
        let (rows, next_again, complete) = find_literals(&body, literal, next, 1024);
        assert!(complete);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["offset"], size - 2);
        assert_eq!(next_again, new_size - 3);

        let replacement = dir.path().join("replacement");
        std::fs::write(&replacement, &body).unwrap();
        std::fs::rename(replacement, &path).unwrap();
        let page = read(next);
        let (new_generation, new_size, body) = parse_search_frame(&page, next).unwrap();
        assert_ne!(generation, new_generation);
        assert!(search_page_needs_reset(
            Some(&previous),
            new_generation,
            new_size,
            next,
            body.len()
        ));
        assert!(search_page_needs_reset(
            Some(&previous),
            generation,
            size - 1,
            next,
            2
        ));
        assert!(search_page_needs_reset(
            Some(&previous),
            generation,
            size,
            next,
            2
        ));
    }

    #[test]
    fn search_finds_a_literal_near_the_end_of_a_full_one_mib_page() {
        let mut body = vec![b'.'; JOB_LOG_SCAN_BYTES as usize];
        let needle = b"[$?]";
        let at = body.len() - needle.len();
        body[at..].copy_from_slice(needle);
        let (rows, next, complete) = find_literals(&body, needle, 0, 1024);
        assert!(complete);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["offset"], at);
        assert_eq!(next, at as u64 + 1);
    }

    #[test]
    fn search_cursor_binds_target_job_and_filter() {
        let prior = host(None);
        let token_scope = job_log_search_scope(&prior, "abcd1234", "[$?]");
        let token = encode_search_cursor("2:987", 32, 33, &token_scope);
        assert_eq!(
            decode_search_cursor(&token, &token_scope).unwrap(),
            JobLogCursor {
                generation: "2:987",
                offset: 32,
                size: 33,
            }
        );
        for different_scope in [
            job_log_search_scope(
                &Host {
                    name: "different".into(),
                    ..prior.clone()
                },
                "abcd1234",
                "[$?]",
            ),
            job_log_search_scope(&prior, "abcd1235", "[$?]"),
            job_log_search_scope(&prior, "abcd1234", "other"),
        ] {
            assert!(decode_search_cursor(&token, &different_scope).is_err());
        }
        assert!(decode_search_cursor(
            &encode_search_cursor("2:987", 34, 33, &token_scope),
            &token_scope
        )
        .is_err());
    }

    #[test]
    fn search_next_offset_is_first_unreturned_match_and_counts_source_bytes() {
        let body = vec![b'a'; 200];
        let (rows, next, completed) = find_literals(&body, b"aa", 100, 16 * 1024);
        assert_eq!(rows.len(), JOB_LOG_MATCHES);
        assert_eq!(next, 100 + JOB_LOG_MATCHES as u64);
        assert!(!completed);
        let (next_rows, _, _) = find_literals(&body[(next - 100) as usize..], b"aa", next, 1024);
        assert_eq!(next_rows[0]["offset"], next);
        assert!(json!(next_rows).to_string().len() <= 1024);
        let (_, partial, _) = find_literals(&[0xe2, 0x82], "€".as_bytes(), 800, 1024);
        assert_eq!(partial, 800);
    }

    #[test]
    fn log_tail_reads_bounded_raw_bytes_and_resume_reads_only_appends() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed ' log");
        let mut bytes = vec![b'a'; 1024];
        bytes.extend_from_slice(&[0xc3, 0xa9, b'\n']);
        std::fs::write(&path, &bytes).unwrap();
        let log = shell_quote(path.to_str().unwrap());
        let read = |offset, cap, tail| {
            let output = std::process::Command::new("bash")
                .arg("-c")
                .arg(job_log_command(&log, offset, cap, tail))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            parse_job_log(
                &String::from_utf8(output.stdout).unwrap(),
                offset,
                cap,
                tail,
            )
            .unwrap()
        };

        let (size, start, tail) = read(0, 2, true);
        assert_eq!((size, start), (1027, 1025));
        assert_eq!(tail, &[0xa9, b'\n']);
        let next = start + tail.len() as u64;
        assert_eq!(next, 1027);

        std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(b"new")
            .unwrap();
        assert_eq!(read(next, 2, false), (1030, 1027, b"ne".to_vec()));
        assert_eq!(read(1029, 4096, false), (1030, 1029, b"w".to_vec()));
        assert_eq!(read(1200, 4096, false), (1030, 1200, Vec::new()));
    }

    #[test]
    fn log_logical_watermark_does_not_advance_beyond_a_short_read() {
        let output = format!("size=32\noffset=12\n{}", BASE64.encode([0xe2, 0x82]));
        let (size, start, bytes) = parse_job_log(&output, 12, 4, false).unwrap();
        assert_eq!((size, start + bytes.len() as u64), (32, 14));
        assert_eq!(String::from_utf8_lossy(&bytes), "�");
        assert!(parse_job_log(&output, 12, 1, false).is_err());
        assert!(parse_job_log(&output, 11, 4, false).is_err());
    }

    #[test]
    fn missing_log_keeps_the_requested_forward_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let log = shell_quote(dir.path().join("missing").to_str().unwrap());
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(job_log_command(&log, 74, 4096, false))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            parse_job_log(&String::from_utf8(output.stdout).unwrap(), 74, 4096, false).unwrap(),
            (0, 74, Vec::new())
        );
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

    #[tokio::test]
    async fn wait_deadline_keeps_known_rows_and_never_starts_queued_jobs_later() {
        use std::sync::{Arc, Mutex};
        use tokio::time::{Duration, Instant};
        let observations = Arc::new(Mutex::new(Vec::new()));
        let probes = observations.clone();
        let names = [
            "done", "failed", "slow-1", "done", "slow-2", "slow-3", "slow-4", "queued",
        ];
        let pairs: Vec<_> = names
            .iter()
            .map(|name| {
                (
                    Host {
                        name: name.to_string(),
                        ..Host::default()
                    },
                    "aaaa1111".to_string(),
                )
            })
            .collect();
        let deadline = Instant::now() + Duration::from_millis(70);
        let (rows, finished) = watch_pairs(&pairs, deadline, Duration::from_millis(1), move |host, id| {
            let probes = probes.clone();
            async move {
                probes.lock().unwrap().push((host.name.clone(), Instant::now()));
                match host.name.as_str() {
                    "done" => Ok(json!({"host":host.name,"job_id":id,"ok":true,"status":"done","exit_code":"0"})),
                    "failed" => Ok(json!({"host":host.name,"job_id":id,"ok":true,"status":"failed","exit_code":"5"})),
                    _ => std::future::pending().await,
                }
            }
        }).await;
        assert!(!finished);
        assert_eq!(rows.len(), pairs.len());
        assert_eq!(rows[1]["exit_code"], "5");
        assert_eq!(rows[0], rows[3]);
        assert_eq!(rows[2]["status"], "unknown");
        assert_eq!(rows[7]["watch_timeout"], true);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let observations = observations.lock().unwrap();
        assert_eq!(
            observations
                .iter()
                .filter(|(host, _)| host == "done")
                .count(),
            1
        );
        assert!(observations
            .iter()
            .all(|(host, time)| host != "queued" && *time < deadline));
    }

    #[tokio::test]
    async fn running_handle_is_repolled_while_another_probe_hangs() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        use tokio::time::Instant;
        let pair = |name: &str| {
            (
                Host {
                    name: name.into(),
                    ..Host::default()
                },
                "abcd1234".to_string(),
            )
        };
        let counters = AtomicUsize::new(0);
        let started_at = Instant::now();
        let (rows, finished) = watch_pairs(
            &[pair("fast"), pair("hung")],
            started_at + Duration::from_millis(150),
            Duration::from_millis(5),
            |host, id| {
                let counters = &counters;
                async move {
                    if host.name == "hung" {
                        return std::future::pending().await;
                    }
                    let attempt = counters.fetch_add(1, Ordering::SeqCst);
                    let status = if attempt == 0 { "running" } else { "done" };
                    Ok(json!({"job_id":id,"host":host.name,"status":status,"exit_code":"0"}))
                }
            },
        )
        .await;
        assert!(!finished);
        assert_eq!(counters.load(Ordering::SeqCst), 2);
        assert_eq!(rows[0]["status"], "done");
        assert_eq!(rows[1]["watch_timeout"], true);
    }

    #[tokio::test]
    async fn wait_does_not_merge_distinct_assets_with_the_same_display_name() {
        let pair = |asset_id: &str| {
            (
                Host {
                    name: "same-name".into(),
                    asset_id: Some(asset_id.into()),
                    ..Host::default()
                },
                "aaaa1111".to_string(),
            )
        };
        let pairs = [pair("asset-a"), pair("asset-b"), pair("asset-a")];
        let (rows, complete) = watch_pairs(
            &pairs,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(2),
            |host, id| async move {
                let code = if host.asset_id.as_deref() == Some("asset-a") {
                    "0"
                } else {
                    "5"
                };
                Ok(json!({"host":host.name,"job_id":id,"status":"done","exit_code":code}))
            },
        )
        .await;
        assert!(complete);
        assert_eq!(rows[0]["exit_code"], "0");
        assert_eq!(rows[1]["exit_code"], "5");
        assert_eq!(rows[2], rows[0]);
    }

    #[tokio::test]
    async fn wait_repolls_only_nonterminal_jobs() {
        use std::sync::{Arc, Mutex};
        use tokio::time::{Duration, Instant};
        let counters = Arc::new(Mutex::new(std::collections::HashMap::<String, u32>::new()));
        let observed = counters.clone();
        let pairs = [
            (
                Host {
                    name: "once".into(),
                    ..Host::default()
                },
                "aaaa1111".to_string(),
            ),
            (
                Host {
                    name: "changes".into(),
                    ..Host::default()
                },
                "bbbb2222".to_string(),
            ),
        ];
        let (rows, finished) = watch_pairs(
            &pairs,
            Instant::now() + Duration::from_secs(1),
            Duration::from_millis(2),
            move |host, id| {
                let observed = observed.clone();
                async move {
                    let mut observed = observed.lock().unwrap();
                    let count = observed.entry(host.name.clone()).or_default();
                    *count += 1;
                    let state = if host.name == "once" || *count == 2 {
                        "done"
                    } else {
                        "running"
                    };
                    Ok(json!({"host":host.name,"job_id":id,"status":state}))
                }
            },
        )
        .await;
        assert!(finished);
        assert_eq!(rows[1]["status"], "done");
        let counters = counters.lock().unwrap();
        assert_eq!(counters["once"], 1);
        assert_eq!(counters["changes"], 2);
    }

    #[test]
    fn wait_rows_keep_known_statuses_and_flag_only_the_unwatched_ones() {
        let pairs = vec![
            (host(None), "aaaa1111".to_string()),
            (host(None), "bbbb2222".to_string()),
        ];
        let mut last = std::collections::HashMap::new();
        last.insert(
            pair_key(&pairs[0].0, &pairs[0].1),
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
