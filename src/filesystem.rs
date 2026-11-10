//! Structured remote exploration and transfers over the resident SSH runner.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Map, Value};
use tokio::sync::Mutex;

use crate::errors::{BridgeError, BridgeResult};
use crate::execution::{ExecOutcome, ExecSpec, Runner};
use crate::fsprobe::{decode, remote_script, FsOptions, DEFAULT_BYTES, WIRE_LIMIT};
use crate::inventory::Host;
use crate::rest::AssetCatalog;
use crate::scheduler::queue_rejection;
use crate::storage::results::ResultStore;

pub const OPERATION: &str = "jms_fs";

pub const ACTIONS: [&str; 10] = [
    "list",
    "stat",
    "read",
    "read_many",
    "glob",
    "search",
    "tree",
    "checksum",
    "upload",
    "download",
];

/// Reject arguments no action reads, and combinations that cannot mean anything.
pub fn validate(arguments: &Map<String, Value>) -> BridgeResult<()> {
    let action = arguments
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| BridgeError::invalid("action is required"))?;
    let paths: Vec<String> = if action == "read_many" {
        arguments
            .get("paths")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![arguments
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()]
    };
    if paths.is_empty()
        || paths
            .iter()
            .any(|path| !path.starts_with('/') || path.contains('\0'))
    {
        return Err(BridgeError::invalid(
            "provide absolute remote path (or paths for read_many); NUL is invalid",
        ));
    }
    let pattern = arguments.get("pattern").and_then(Value::as_str);
    if matches!(action, "glob" | "search") && pattern.unwrap_or("").is_empty() {
        return Err(BridgeError::invalid("glob/search requires pattern"));
    }
    if arguments.contains_key("byte_offset")
        && (arguments.contains_key("start_line")
            || arguments.get("tail").and_then(Value::as_bool) == Some(true))
    {
        return Err(BridgeError::invalid(
            "byte_offset cannot be combined with start_line or tail",
        ));
    }
    if action == "read_many" && arguments.contains_key("byte_offset") {
        return Err(BridgeError::invalid("use read for individual byte cursors"));
    }
    let max_bytes = arguments
        .get("max_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_BYTES as u64) as usize;
    if action == "read_many" && max_bytes < 256 * paths.len() {
        return Err(BridgeError::invalid(
            "read_many max_bytes must allow at least 256 bytes per file",
        ));
    }
    let timeout = arguments
        .get("timeout")
        .and_then(Value::as_u64)
        .unwrap_or(30);
    if matches!(action, "upload" | "download") {
        let local = arguments
            .get("local_path")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !local.starts_with('/') || local.contains('\0') {
            return Err(BridgeError::invalid(
                "upload/download requires absolute local_path on the MCP server machine",
            ));
        }
        if action == "upload" && !std::path::Path::new(local).exists() {
            return Err(BridgeError::invalid(
                "upload local_path does not exist on the MCP server machine",
            ));
        }
    } else if timeout > 120 {
        return Err(BridgeError::invalid(
            "exploration timeout must be <=120 seconds",
        ));
    }
    let mut allowed: Vec<&str> = vec![
        "target",
        "action",
        "path",
        "container",
        "timeout",
        "max_bytes",
    ];
    allowed.extend(
        crate::schemas::fs_action_options(action)
            .ok_or_else(|| BridgeError::invalid("unknown fs action"))?,
    );
    let unused: Vec<String> = arguments
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .cloned()
        .collect();
    if !unused.is_empty() {
        let mut unused = unused;
        unused.sort();
        return Err(BridgeError::invalid(format!(
            "parameters not applicable to action: {}",
            unused.join(", ")
        )));
    }
    if action == "read_many" && arguments.contains_key("path") {
        return Err(BridgeError::invalid(
            "parameters not applicable to action: path",
        ));
    }
    Ok(())
}

pub fn options_from(arguments: &Map<String, Value>) -> FsOptions {
    let strings = |key: &str| -> Vec<String> {
        arguments
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let text = |key: &str| {
        arguments
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let number = |key: &str| arguments.get(key).and_then(Value::as_u64);
    let flag = |key: &str| arguments.get(key).and_then(Value::as_bool);
    FsOptions {
        action: text("action"),
        path: text("path"),
        paths: strings("paths"),
        pattern: text("pattern"),
        include: strings("include"),
        exclude: strings("exclude"),
        container: arguments
            .get("container")
            .and_then(Value::as_str)
            .map(str::to_string),
        local_path: arguments
            .get("local_path")
            .and_then(Value::as_str)
            .map(str::to_string),
        overwrite: flag("overwrite").unwrap_or(false),
        literal: flag("literal"),
        case_sensitive: flag("case_sensitive"),
        hidden: flag("hidden"),
        respect_ignore: flag("respect_ignore"),
        offset: number("offset"),
        limit: number("limit"),
        depth: number("depth"),
        start_line: number("start_line"),
        line_count: number("line_count"),
        byte_offset: number("byte_offset"),
        tail: flag("tail"),
        max_bytes: number("max_bytes").map(|value| value as usize),
        context_lines: number("context_lines"),
        max_file_bytes: number("max_file_bytes"),
        timeout: number("timeout"),
    }
}

struct WorkerEntry {
    key: String,
    session_id: String,
    host: Host,
    busy: bool,
    last_used: Instant,
}

/// Private reusable shell channels; each filesystem probe is a fresh Bash process.
pub struct FilesystemWorkers {
    runner: Arc<Runner>,
    limit: usize,
    per_target: usize,
    idle_seconds: f64,
    entries: Mutex<Vec<WorkerEntry>>,
    hits: Mutex<u64>,
    misses: Mutex<u64>,
    fallbacks: Mutex<u64>,
    startup_retries: Mutex<u64>,
    sweeping: std::sync::atomic::AtomicBool,
    closing: std::sync::atomic::AtomicBool,
}

impl FilesystemWorkers {
    pub fn new(
        runner: Arc<Runner>,
        limit: usize,
        per_target: usize,
        idle_seconds: f64,
    ) -> Arc<Self> {
        Arc::new(Self {
            runner,
            limit,
            per_target,
            idle_seconds,
            entries: Mutex::new(Vec::new()),
            hits: Mutex::new(0),
            misses: Mutex::new(0),
            fallbacks: Mutex::new(0),
            startup_retries: Mutex::new(0),
            sweeping: std::sync::atomic::AtomicBool::new(false),
            closing: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub async fn status(&self) -> Value {
        let entries = self.entries.lock().await;
        json!({
            "total": entries.len(),
            "busy": entries.iter().filter(|entry| entry.busy).count(),
            "limit": self.limit,
            "per_target": self.per_target,
            "idle_seconds": self.idle_seconds,
            "reused": *self.hits.lock().await,
            "created": *self.misses.lock().await,
            "isolated_fallbacks": *self.fallbacks.lock().await,
            "startup_retries": *self.startup_retries.lock().await,
        })
    }

    fn ensure_sweeper(self: &Arc<Self>) {
        use std::sync::atomic::Ordering;
        if self.sweeping.swap(true, Ordering::SeqCst) {
            return;
        }
        let workers = self.clone();
        tokio::spawn(async move {
            loop {
                if workers.closing.load(Ordering::SeqCst) {
                    return;
                }
                let sleep_for = workers.idle_seconds.min(30.0).max(0.2);
                tokio::time::sleep(std::time::Duration::from_secs_f64(sleep_for)).await;
                workers.sweep().await;
            }
        });
    }

    async fn sweep(&self) {
        let expired: Vec<WorkerEntry> = {
            let mut entries = self.entries.lock().await;
            let mut expired = Vec::new();
            let mut keep = Vec::new();
            for entry in entries.drain(..) {
                if !entry.busy && entry.last_used.elapsed().as_secs_f64() >= self.idle_seconds {
                    expired.push(entry);
                } else {
                    keep.push(entry);
                }
            }
            *entries = keep;
            expired
        };
        for entry in expired {
            let _ = self
                .runner
                .close_session(&entry.host, &entry.session_id, true)
                .await;
        }
    }

    pub async fn execute(
        self: &Arc<Self>,
        host: &Host,
        script: &str,
        timeout: f64,
        container: Option<&str>,
        progress: Option<&dyn crate::storage::journal::ProgressSink>,
    ) -> BridgeResult<Map<String, Value>> {
        let first = self
            .execute_once(host, script, timeout, container, progress)
            .await?;
        if !startup_failed(&first) {
            return Ok(first);
        }
        *self.startup_retries.lock().await += 1;
        let second = self
            .execute_once(host, script, timeout, container, progress)
            .await?;
        Ok(second)
    }

    async fn execute_once(
        self: &Arc<Self>,
        host: &Host,
        script: &str,
        timeout: f64,
        container: Option<&str>,
        progress: Option<&dyn crate::storage::journal::ProgressSink>,
    ) -> BridgeResult<Map<String, Value>> {
        self.ensure_sweeper();
        let key = format!(
            "{}\u{1f}{}",
            host.connection_key()?,
            container.unwrap_or("")
        );
        let entry = self.acquire_entry(host, &key, container).await?;
        match entry {
            None => {
                *self.fallbacks.lock().await += 1;
                // Saturation uses the isolated path; execution slots still bound it.
                let spec = ExecSpec {
                    container: container.map(str::to_string),
                    startup_probe: true,
                    ..Default::default()
                };
                self.runner
                    .execute_to_store(host, script, timeout, &spec, progress)
                    .await
                    .map_err(|failure| failure.error)
            }
            Some(session_id) => {
                let spec = ExecSpec {
                    container: container.map(str::to_string),
                    session_id: Some(session_id.clone()),
                    internal_session: true,
                    ..Default::default()
                };
                let result = self
                    .runner
                    .execute_to_store(host, script, timeout, &spec, progress)
                    .await
                    .map_err(|failure| failure.error);
                let failed = match &result {
                    Ok(meta) => meta.get("ok") != Some(&Value::Bool(true)),
                    Err(_) => true,
                };
                let mut entries = self.entries.lock().await;
                if failed {
                    entries.retain(|entry| entry.session_id != session_id);
                    drop(entries);
                    let _ = self.runner.close_session(host, &session_id, true).await;
                } else if let Some(entry) = entries
                    .iter_mut()
                    .find(|entry| entry.session_id == session_id)
                {
                    entry.busy = false;
                    entry.last_used = Instant::now();
                }
                result
            }
        }
    }

    async fn acquire_entry(
        &self,
        host: &Host,
        key: &str,
        _container: Option<&str>,
    ) -> BridgeResult<Option<String>> {
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(BridgeError::invalid("filesystem workers are closing"));
        }
        let mut retired: Option<WorkerEntry> = None;
        let chosen = {
            let mut entries = self.entries.lock().await;
            if let Some(entry) = entries
                .iter_mut()
                .find(|entry| entry.key == key && !entry.busy)
            {
                entry.busy = true;
                *self.hits.lock().await += 1;
                Some(entry.session_id.clone())
            } else if entries.iter().filter(|entry| entry.key == key).count() < self.per_target {
                if entries.len() >= self.limit {
                    if let Some(index) = entries
                        .iter()
                        .enumerate()
                        .filter(|(_, entry)| !entry.busy)
                        .min_by_key(|(_, entry)| entry.last_used)
                        .map(|(index, _)| index)
                    {
                        retired = Some(entries.remove(index));
                    }
                }
                if entries.len() < self.limit {
                    let session_id = format!("_fs:{}", uuid::Uuid::new_v4().simple());
                    entries.push(WorkerEntry {
                        key: key.to_string(),
                        session_id: session_id.clone(),
                        host: host.clone(),
                        busy: true,
                        last_used: Instant::now(),
                    });
                    *self.misses.lock().await += 1;
                    Some(session_id)
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(entry) = retired {
            let _ = self
                .runner
                .close_session(&entry.host, &entry.session_id, true)
                .await;
        }
        Ok(chosen)
    }

    pub async fn close(self: &Arc<Self>) -> BridgeResult<()> {
        self.closing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let entries: Vec<WorkerEntry> = {
            let mut entries = self.entries.lock().await;
            let taken = entries.drain(..).collect();
            taken
        };
        for entry in entries {
            if entry.busy {
                return Err(BridgeError::storage(
                    "filesystem work must drain before shutdown",
                ));
            }
            let _ = self
                .runner
                .close_session(&entry.host, &entry.session_id, true)
                .await;
        }
        Ok(())
    }
}

pub fn startup_failed(meta: &Map<String, Value>) -> bool {
    meta.get("failure_stage").and_then(Value::as_str) == Some("shell_startup")
        && meta.get("execution_state").and_then(Value::as_str) == Some("not_started")
        && meta.get("completion_unknown") != Some(&Value::Bool(true))
        && meta.get("timed_out") != Some(&Value::Bool(true))
        && meta.get("exit_code").and_then(Value::as_i64) == Some(75)
}

pub struct Filesystem {
    catalog: Arc<AssetCatalog>,
    runner: Arc<Runner>,
    store: Arc<ResultStore>,
    pub workers: Arc<FilesystemWorkers>,
}

impl Filesystem {
    pub fn new(catalog: Arc<AssetCatalog>, runner: Arc<Runner>, store: Arc<ResultStore>) -> Self {
        let workers = FilesystemWorkers::new(runner.clone(), 16, 2, 300.0);
        Self {
            catalog,
            runner,
            store,
            workers,
        }
    }

    /// Size of one remote file, or `None` when it cannot be determined cheaply.
    async fn remote_size(
        &self,
        host: &Host,
        remote: &str,
        container: Option<&str>,
        progress: Option<&dyn crate::storage::journal::ProgressSink>,
    ) -> Option<u64> {
        let script = format!(
            "stat -c %s -- {} 2>/dev/null || true",
            crate::fsprobe::shlex_quote(remote)
        );
        let meta = self
            .workers
            .execute(host, &script, 15.0, container, progress)
            .await
            .ok()?;
        let result_id = meta.get("result_id")?.as_str()?.to_string();
        let path = self.store.path(&result_id, "stdout").ok()?;
        let text = std::fs::read_to_string(path).ok()?;
        text.trim().parse::<u64>().ok().filter(|size| *size > 0)
    }

    pub async fn execute(
        &self,
        arguments: Map<String, Value>,
        progress: Option<&dyn crate::storage::journal::ProgressSink>,
    ) -> BridgeResult<Value> {
        validate(&arguments)?;
        let target = arguments
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if target.eq_ignore_ascii_case("all") || target.contains(['*', '?', '[', ']']) {
            return Err(BridgeError::invalid(
                "jms_fs requires one explicit REST target",
            ));
        }
        let inventory = self.catalog.ensure().await?;
        let hosts = inventory.resolve(&[target])?;
        if hosts.len() != 1 {
            return Err(BridgeError::invalid(
                "jms_fs requires exactly one permitted SSH asset",
            ));
        }
        let host = hosts.into_iter().next().expect("one host");
        let action = arguments
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let options = options_from(&arguments);
        if matches!(action.as_str(), "upload" | "download") {
            let local = options.local_path.clone().unwrap_or_default();
            let remote = options.path.clone();
            let timeout = options.timeout.unwrap_or(900) as f64;
            // A known size makes progress and ETA available from the first byte: the
            // local file for an upload, one `stat` for a download.
            let expected_total = if action == "upload" {
                std::fs::metadata(&local).ok().map(|meta| meta.len())
            } else {
                self.remote_size(&host, &remote, options.container.as_deref(), progress)
                    .await
            };
            let outcome = self
                .runner
                .rsync(
                    &host,
                    &local,
                    &remote,
                    if action == "upload" { "push" } else { "pull" },
                    &options.exclude,
                    false,
                    timeout,
                    options.container.as_deref(),
                    options.overwrite,
                    progress,
                    expected_total,
                )
                .await?;
            if let Some(progress) = progress {
                // The result id was recorded before the transfer started; this adds the
                // action now that the outcome is known.
                let _ = progress.record(
                    "execution_results",
                    serde_json::json!({
                        "host": host.name,
                        "result_id": outcome.result_id,
                        "action": action,
                    }),
                );
            }
            let meta = self.store.metadata(&outcome.result_id)?;
            let mut row = Map::new();
            for key in [
                "ok",
                "host",
                "result_id",
                "exit_code",
                "timing",
                "completion_unknown",
                "execution_state",
                "queue_timed_out",
                "failure_stage",
            ] {
                if let Some(value) = meta.get(key) {
                    row.insert(key.to_string(), value.clone());
                }
            }
            for (key, value) in self.store.preview(&outcome.result_id, 4096)? {
                row.insert(key, value);
            }
            for (key, value) in queue_rejection(&meta) {
                row.insert(key, value);
            }
            row.insert("action".into(), Value::from(action));
            row.insert("local_path".into(), Value::from(local));
            row.insert("path".into(), Value::from(remote));
            // The transfer's own byte accounting, so a completed call still says how much
            // moved and how fast.
            let mut progress_row = Map::new();
            for key in ["bytes_done", "total_bytes", "progress_pct", "rate_bps"] {
                if let Some(value) = meta.get(key) {
                    progress_row.insert(key.to_string(), value.clone());
                }
            }
            if !progress_row.is_empty() {
                row.insert("progress".into(), Value::Object(progress_row));
            }
            row.insert("overwrite".into(), Value::Bool(options.overwrite));
            row.insert(
                "existing_files".into(),
                Value::from(if options.overwrite { "replace" } else { "skip" }),
            );
            return Ok(Value::Object(row));
        }
        let script = remote_script(&options, "rg").map_err(BridgeError::invalid)?;
        let timeout = options.timeout.unwrap_or(30) as f64 + 5.0;
        let meta = self
            .workers
            .execute(
                &host,
                &script,
                timeout,
                options.container.as_deref(),
                progress,
            )
            .await?;
        let rid = meta
            .get("result_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if meta.get("ok") != Some(&Value::Bool(true)) {
            let mut row = Map::new();
            for key in [
                "ok",
                "result_id",
                "host",
                "exit_code",
                "execution_state",
                "completion_unknown",
                "timing",
                "warning",
                "failure_stage",
                "startup_retry_result_id",
                "connection_recovery",
            ] {
                if let Some(value) = meta.get(key) {
                    row.insert(key.to_string(), value.clone());
                }
            }
            for (key, value) in self.store.preview(&rid, 2048)? {
                row.insert(key, value);
            }
            for (key, value) in queue_rejection(&meta) {
                row.insert(key, value);
            }
            return Ok(Value::Object(row));
        }
        let path = self.store.path(&rid, "stdout")?;
        if std::fs::metadata(&path)?.len() as usize > WIRE_LIMIT * 2 + 65536 {
            return Ok(json!({"ok": false, "result_id": rid,
                             "error": "filesystem probe exceeded wire limit"}));
        }
        let raw = std::fs::read(&path)?;
        let stderr = {
            let stderr_path = self.store.path(&rid, "stderr")?;
            let mut data = Vec::new();
            if let Ok(bytes) = std::fs::read(&stderr_path) {
                data.extend_from_slice(&bytes[..bytes.len().min(2048)]);
            }
            data
        };
        let value = decode(&raw, &options, &stderr);
        let mut meta_fields = Map::new();
        meta_fields.insert("kind".into(), Value::from("filesystem"));
        meta_fields.insert("operation".into(), Value::from(action.clone()));
        meta_fields.insert("host".into(), Value::from(host.name.clone()));
        let result_id = self.store.save_json(&value, meta_fields)?;
        let mut result = Map::new();
        result.insert(
            "ok".into(),
            value.get("ok").cloned().unwrap_or(Value::Bool(false)),
        );
        result.insert("result_id".into(), Value::from(result_id));
        result.insert("execution_result_id".into(), Value::from(rid));
        result.insert("host".into(), Value::from(host.name.clone()));
        result.insert(
            "timing".into(),
            meta.get("timing").cloned().unwrap_or(Value::Null),
        );
        for key in ["startup_retry_result_id", "connection_recovery"] {
            if let Some(value) = meta.get(key) {
                result.insert(key.to_string(), value.clone());
            }
        }
        result.insert("data".into(), value);
        Ok(Value::Object(result))
    }
}

/// Execution rows for a fan-out of the legacy `jms_exec` operation.
pub fn exec_rows(store: &ResultStore, outcomes: &[ExecOutcome], budget_total: usize) -> Vec<Value> {
    let budget = budget_total / outcomes.len().max(1);
    outcomes
        .iter()
        .map(|outcome| {
            let mut row = Map::new();
            row.insert("host".into(), Value::from(outcome.host.clone()));
            row.insert("ok".into(), Value::Bool(outcome.ok()));
            row.insert("exit_code".into(), json!(outcome.exit_code));
            row.insert("result_id".into(), Value::from(outcome.result_id.clone()));
            if let Some(preview) = &outcome.preview {
                for (key, value) in preview.compact(budget) {
                    row.insert(key, value);
                }
            } else if let Ok(preview) = store.preview(&outcome.result_id, budget) {
                for (key, value) in preview {
                    row.insert(key, value);
                }
            }
            for (key, value) in &outcome.rejection {
                row.insert(key.clone(), value.clone());
            }
            for (key, value) in &outcome.recovery {
                row.insert(key.clone(), value.clone());
            }
            Value::Object(row)
        })
        .collect()
}

/// Counts used by diagnostics: how many workers exist per target string.
pub fn worker_counts(status: &Value) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    if let Some(total) = status.get("total").and_then(Value::as_u64) {
        out.insert("total".into(), total);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap()
    }

    #[test]
    fn validation_requires_absolute_paths() {
        let error = validate(&args(
            json!({"target": "a", "action": "read", "path": "rel/x"}),
        ))
        .unwrap_err();
        assert!(error.message().contains("absolute remote path"));
        assert!(validate(&args(
            json!({"target": "a", "action": "read", "path": "/abs"})
        ))
        .is_ok());
    }

    #[test]
    fn validation_rejects_irrelevant_parameters() {
        let error = validate(&args(
            json!({"target": "a", "action": "stat", "path": "/x", "limit": 10}),
        ))
        .unwrap_err();
        assert_eq!(
            error.message(),
            "parameters not applicable to action: limit"
        );
        let error = validate(&args(
            json!({"target": "a", "action": "read_many", "paths": ["/a"], "path": "/b"}),
        ))
        .unwrap_err();
        assert_eq!(error.message(), "parameters not applicable to action: path");
    }

    #[test]
    fn validation_enforces_cursor_exclusivity_and_budgets() {
        assert!(
            validate(&args(json!({"target": "a", "action": "read", "path": "/x",
                                      "byte_offset": 10, "tail": true})))
            .is_err()
        );
        assert!(validate(&args(json!({"target": "a", "action": "read_many",
                                      "paths": ["/a", "/b"], "max_bytes": 300})))
        .is_err());
        assert!(
            validate(&args(json!({"target": "a", "action": "list", "path": "/x",
                                      "timeout": 900})))
            .is_err()
        );
        assert!(validate(&args(
            json!({"target": "a", "action": "download", "path": "/x",
                                      "local_path": "relative"})
        ))
        .is_err());
    }

    #[test]
    fn startup_failure_predicate_matches_the_transmission_boundary() {
        let mut meta = Map::new();
        meta.insert("failure_stage".into(), json!("shell_startup"));
        meta.insert("execution_state".into(), json!("not_started"));
        meta.insert("completion_unknown".into(), json!(false));
        meta.insert("timed_out".into(), json!(false));
        meta.insert("exit_code".into(), json!(75));
        assert!(startup_failed(&meta));
        meta.insert("completion_unknown".into(), json!(true));
        assert!(!startup_failed(&meta));
    }
}
