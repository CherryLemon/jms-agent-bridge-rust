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
        "R=\"$(cd \"$(dirname \"$0\")\" && pwd)\"".to_string(),
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
    [
        "set -eu".to_string(),
        // Exported so the detached launcher (tmux/setsid) can expand "$R".
        format!("export R={root}"),
        "mkdir -p \"$R\"".to_string(),
        format!("cat > \"$R/run.sh\" <<'JMS_RUNNER_EOF'\n{runner}JMS_RUNNER_EOF"),
        "if command -v tmux >/dev/null 2>&1; then".to_string(),
        format!(
            "  tmux new-session -d -s {} 'bash \"$R/run.sh\" > \"$R/stdout.log\" 2>&1; echo $? > \"$R/tmux_exit\"'",
            shell_quote(session)
        ),
        format!("  tmux has-session -t {} && echo LAUNCHER=tmux", shell_quote(session)),
        "else".to_string(),
        "  command -v setsid >/dev/null 2>&1 || { echo 'no tmux and no setsid' >&2; exit 3; }"
            .to_string(),
        "  setsid bash \"$R/run.sh\" > \"$R/stdout.log\" 2>&1 < /dev/null &".to_string(),
        "  echo \"$!\" > \"$R/launcher_pid\"".to_string(),
        "  sleep 1".to_string(),
        "  kill -0 \"$(cat \"$R/launcher_pid\")\" 2>/dev/null && echo LAUNCHER=setsid".to_string(),
        "fi".to_string(),
    ]
    .join("\n")
}

#[derive(Debug, Clone)]
pub struct JobHandle {
    pub job_id: String,
    pub host: String,
    pub session: String,
    pub launcher: String,
}

impl JobHandle {
    pub fn to_json(&self) -> Value {
        json!({"job_id": self.job_id, "host": self.host,
               "session": self.session, "launcher": self.launcher})
    }
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
    ) -> (Option<JobHandle>, ExecOutcome) {
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
            progress.record("submission_receipts", Value::Object(receipt.clone()));
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
        let metadata = &outcome.meta;
        receipt.insert("result_id".into(), Value::from(outcome.result_id.clone()));
        receipt.insert("launch_acknowledged".into(), Value::Bool(acknowledged));
        receipt.insert(
            "submission_state".into(),
            Value::from(if acknowledged {
                "acknowledged".to_string()
            } else {
                metadata
                    .get("execution_state")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string()
            }),
        );
        receipt.insert(
            "completion_unknown".into(),
            Value::Bool(if acknowledged {
                false
            } else {
                metadata
                    .get("completion_unknown")
                    .and_then(Value::as_bool)
                    .unwrap_or(true)
            }),
        );
        for (key, value) in queue_rejection(metadata) {
            receipt.insert(key, value);
        }
        if let Some(progress) = progress {
            progress.record("submission_receipts", Value::Object(receipt));
        }
        if acknowledged {
            return (
                Some(JobHandle {
                    job_id,
                    host: host.name.clone(),
                    session,
                    launcher: launcher_of(&outcome.stdout),
                }),
                outcome,
            );
        }
        (None, outcome)
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

    pub async fn status_many(&self, pairs: &[(Host, String)]) -> Vec<Value> {
        let mut out = Vec::new();
        for (host, job_id) in pairs {
            match self.status(host, job_id).await {
                Ok(value) => out.push(value),
                Err(error) => out.push(json!({"host": host.name, "job_id": job_id,
                                              "ok": false, "error": error.message()})),
            }
        }
        out
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
if tmux has-session -t jms-{job_id} 2>/dev/null; then tmux kill-session -t jms-{job_id} && killed=yes; fi; \
if [ -f {root}/pid ]; then pid=$(cat {root}/pid); \
kill -TERM \"-$pid\" 2>/dev/null || kill -TERM \"$pid\" 2>/dev/null; killed=yes; fi; \
echo cancelled > {root}/status 2>/dev/null || true; \
echo \"killed=$killed\""
        );
        let outcome = self
            .runner
            .exec_on(host, &command, 60.0, false, false, false)
            .await?;
        Ok(json!({
            "host": host.name,
            "job_id": job_id,
            "killed": outcome.stdout.contains("killed=yes"),
            "ok": outcome.ok(),
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
        loop {
            let latest = self.status_many(pairs).await;
            let terminal = latest.iter().all(|row| {
                matches!(
                    row.get("status").and_then(Value::as_str),
                    Some("done") | Some("failed") | Some("missing")
                )
            });
            if terminal {
                return (latest, true);
            }
            if tokio::time::Instant::now() >= deadline {
                return (latest, false);
            }
            tokio::time::sleep(std::time::Duration::from_secs_f64(interval.max(0.1))).await;
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
        assert!(script.contains("setsid bash \"$R/run.sh\""));
        assert!(script.contains("no tmux and no setsid"));
    }

    #[test]
    fn launcher_parses_only_the_launcher_line() {
        assert_eq!(launcher_of("LAUNCHER=tmux\n"), "tmux");
        assert_eq!(launcher_of("noise\nLAUNCHER=setsid\n"), "setsid");
        assert_eq!(launcher_of("nothing"), "unknown");
    }
}
