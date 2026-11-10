//! Durable, caller-addressable receipts; a claimed request is never replayed.
//!
//! The journal deliberately never resumes work after a restart. A receipt without a
//! live owner is reported as `interrupted`/`completion_unknown` so the caller
//! reconciles saved job or result IDs instead of re-running a write.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;

use crate::errors::{BridgeError, BridgeResult};
use crate::storage::results::{atomic_json, now, sync_directory};

/// Receives durable progress for one accepted request.
pub trait ProgressSink: Send + Sync {
    /// Persist one progress field.
    ///
    /// Callers that must not start remote work without a durable trail treat an error
    /// as fatal; best-effort bookkeeping can ignore it.
    fn record(&self, field: &str, value: Value) -> BridgeResult<()>;
}

pub struct NullProgress;

impl ProgressSink for NullProgress {
    fn record(&self, _field: &str, _value: Value) -> BridgeResult<()> {
        Ok(())
    }
}

pub struct RequestProgress {
    journal: Arc<RequestJournal>,
    request_id: String,
}

impl RequestProgress {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

impl ProgressSink for RequestProgress {
    fn record(&self, field: &str, value: Value) -> BridgeResult<()> {
        self.journal.progress(&self.request_id, field, value)
    }
}

pub struct RequestJournal {
    root: PathBuf,
    fs: Mutex<()>,
    claim: AsyncMutex<()>,
    /// One lock per request: a fan-out writes many rows for the *same* request, and
    /// different requests must not queue behind each other's fsync.
    request_locks: Mutex<HashMap<String, std::sync::Weak<Mutex<()>>>>,
    tasks: Mutex<HashMap<String, ()>>,
}

impl RequestJournal {
    pub fn new(root: PathBuf) -> BridgeResult<Self> {
        std::fs::create_dir_all(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self {
            root,
            fs: Mutex::new(()),
            claim: AsyncMutex::new(()),
            request_locks: Mutex::new(HashMap::new()),
            tasks: Mutex::new(HashMap::new()),
        })
    }

    pub fn directory(&self, request_id: &str) -> BridgeResult<PathBuf> {
        if !valid_request_id(request_id) {
            return Err(BridgeError::invalid(
                "request_id must contain 1..128 letters, digits, dots, colons, underscores, or hyphens",
            ));
        }
        let digest = Sha256::digest(request_id.as_bytes());
        Ok(self.root.join(hex::encode(digest)))
    }

    /// The lock that serializes read-modify-write for one request.
    ///
    /// Entries are weak: once nobody holds the guard the entry disappears, so a long
    /// running service does not accumulate one lock per request id it has ever seen.
    fn request_lock(&self, request_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.request_locks.lock().expect("request lock map");
        locks.retain(|_, weak| weak.strong_count() > 0);
        if let Some(existing) = locks.get(request_id).and_then(|weak| weak.upgrade()) {
            return existing;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(request_id.to_string(), Arc::downgrade(&lock));
        lock
    }

    pub fn save(&self, receipt: &Map<String, Value>) -> BridgeResult<()> {
        let request_id = receipt
            .get("request_id")
            .and_then(Value::as_str)
            .ok_or_else(|| BridgeError::storage("receipt without request_id"))?
            .to_string();
        let lock = self.request_lock(&request_id);
        let _guard = lock.lock().expect("request lock");
        self.save_unlocked(receipt)
    }

    /// Save with the caller already holding the journal lock.
    fn save_unlocked(&self, receipt: &Map<String, Value>) -> BridgeResult<()> {
        let request_id = receipt
            .get("request_id")
            .and_then(Value::as_str)
            .ok_or_else(|| BridgeError::storage("receipt without request_id"))?;
        let directory = self.directory(request_id)?;
        atomic_json(
            &directory.join("state.json"),
            &Value::Object(receipt.clone()),
        )?;
        sync_directory(&directory)?;
        Ok(())
    }

    pub fn load(&self, request_id: &str) -> BridgeResult<Map<String, Value>> {
        let lock = self.request_lock(request_id);
        let _guard = lock.lock().expect("request lock");
        self.load_unlocked(request_id)
    }

    /// Load with the caller already holding the journal lock.
    fn load_unlocked(&self, request_id: &str) -> BridgeResult<Map<String, Value>> {
        let directory = self.directory(request_id)?;
        let path = directory.join("state.json");
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Value>(&text) {
                Ok(Value::Object(map)) => Ok(map),
                Ok(_) => Err(BridgeError::storage("corrupt request receipt")),
                Err(error) => Err(BridgeError::storage(format!(
                    "corrupt request receipt: {error}"
                ))),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if directory.exists() {
                    // A crash between the atomic directory claim and the first write
                    // must never make a second invocation eligible to execute.
                    let mut receipt = Map::new();
                    receipt.insert("request_id".into(), Value::from(request_id));
                    receipt.insert("request_state".into(), Value::from("interrupted"));
                    receipt.insert("completion_unknown".into(), Value::Bool(true));
                    receipt.insert(
                        "error".into(),
                        Value::from("receipt initialization interrupted"),
                    );
                    Ok(receipt)
                } else {
                    Err(BridgeError::invalid("unknown request_id"))
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn status(&self, request_id: &str, duplicate: bool) -> BridgeResult<Value> {
        let lock = self.request_lock(request_id);
        let _guard = lock.lock().expect("request lock");
        let mut receipt = self.load_unlocked(request_id)?;
        let live = self
            .tasks
            .lock()
            .expect("task map")
            .contains_key(request_id);
        if receipt.get("request_state").and_then(Value::as_str) == Some("running") && !live {
            receipt.insert("request_state".into(), Value::from("interrupted"));
            receipt.insert("completion_unknown".into(), Value::Bool(true));
            receipt.insert(
                "error".into(),
                Value::from(
                    "no live request owner; reconcile saved job/result IDs before new work",
                ),
            );
            self.save_unlocked(&receipt)?;
        }
        let mut response = match receipt.get("response") {
            Some(Value::Object(map)) => map.clone(),
            _ => Map::new(),
        };
        for (key, value) in &receipt {
            if key == "fingerprint" || key == "response" {
                continue;
            }
            response.insert(key.clone(), value.clone());
        }
        response.entry("ok".to_string()).or_insert_with(|| {
            Value::Bool(receipt.get("request_state").and_then(Value::as_str) == Some("running"))
        });
        response.insert("duplicate".into(), Value::Bool(duplicate));
        response.insert("execution_replayed".into(), Value::Bool(false));
        Ok(Value::Object(response))
    }

    fn progress(&self, request_id: &str, field: &str, value: Value) -> BridgeResult<()> {
        // One lock per request covers the whole read-modify-write: several targets of
        // the same request must not overwrite each other's rows, while other requests
        // keep their own lane.
        let lock = self.request_lock(request_id);
        let _guard = lock.lock().expect("request lock");
        let mut receipt = self.load_unlocked(request_id)?;
        let identity = if field == "execution_results" {
            "result_id"
        } else {
            "job_id"
        };
        let mut rows = match receipt.remove(field) {
            Some(Value::Array(rows)) => rows,
            _ => Vec::new(),
        };
        let same = |row: &Value| {
            row.get(identity) == value.get(identity) && row.get("host") == value.get("host")
        };
        if let Some(slot) = rows.iter_mut().find(|row| same(row)) {
            *slot = value;
        } else {
            rows.push(value);
        }
        receipt.insert(field.to_string(), Value::Array(rows));
        self.save_unlocked(&receipt)
    }

    /// Reserve the request id before any side effect. `Ok((false, status))` means the
    /// id was already claimed with identical arguments and nothing may run again.
    pub fn claim(
        &self,
        request_id: &str,
        operation: &str,
        arguments: &Value,
    ) -> BridgeResult<(bool, Map<String, Value>)> {
        let directory = self.directory(request_id)?;
        let fingerprint = fingerprint_of(operation, arguments);
        {
            let _guard = self.fs.lock().expect("journal lock");
            match std::fs::create_dir(&directory) {
                Ok(()) => {
                    sync_directory(&self.root)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    drop(_guard);
                    let receipt = self.load(request_id)?;
                    if receipt.get("fingerprint").and_then(Value::as_str) != Some(&fingerprint) {
                        return Err(BridgeError::invalid(
                            "request_id already claimed; use request_status to reconcile it (arguments cannot change)",
                        ));
                    }
                    let status = self.status(request_id, true)?;
                    let map = match status {
                        Value::Object(map) => map,
                        _ => Map::new(),
                    };
                    return Ok((false, map));
                }
                Err(error) => return Err(error.into()),
            }
        }
        let mut receipt = Map::new();
        receipt.insert("request_id".into(), Value::from(request_id));
        receipt.insert("operation".into(), Value::from(operation));
        receipt.insert("fingerprint".into(), Value::from(fingerprint));
        receipt.insert("request_state".into(), Value::from("running"));
        receipt.insert("accepted_at".into(), serde_json::json!(now()));
        receipt.insert("completion_unknown".into(), Value::Bool(false));
        self.save(&receipt)?;
        Ok((true, receipt))
    }

    /// Run `perform` under a durable claim and keep it owned by the service.
    ///
    /// The worker runs in its own task: an MCP response or client disconnect cannot
    /// cancel accepted work, and the caller can always reconcile with the original
    /// request id.
    pub async fn execute<F, Fut>(
        self: &Arc<Self>,
        request_id: &str,
        operation: &str,
        arguments: &Value,
        perform: F,
    ) -> BridgeResult<Value>
    where
        F: FnOnce(Arc<RequestProgress>) -> Fut + Send + 'static,
        Fut: Future<Output = BridgeResult<Value>> + Send + 'static,
    {
        let worker = {
            let _claim = self.claim.lock().await;
            let (created, receipt) = self.claim(request_id, operation, arguments)?;
            if !created {
                return Ok(Value::Object(receipt));
            }
            let journal = self.clone();
            let id = request_id.to_string();
            // Register ownership before the worker can possibly finish, so a very
            // fast completion cannot leave a stale liveness entry behind.
            self.tasks
                .lock()
                .expect("task map")
                .insert(request_id.to_string(), ());
            let handle = tokio::spawn(async move {
                let initial = receipt;
                let progress = Arc::new(RequestProgress {
                    journal: journal.clone(),
                    request_id: id.clone(),
                });
                let outcome = perform(progress).await;
                // Progress rows written during the worker live on disk; merging them
                // before the final save keeps the receipt complete instead of stale.
                let mut receipt = journal.load(&id).unwrap_or(initial);
                match outcome {
                    Ok(response) => {
                        let unknown = response_unknown(&response, &receipt);
                        receipt.insert("response".into(), response);
                        receipt.insert("request_state".into(), Value::from("complete"));
                        receipt.insert("completion_unknown".into(), Value::Bool(unknown));
                        receipt.insert("finished_at".into(), serde_json::json!(now()));
                    }
                    Err(error) => {
                        // A raised failure alone cannot prove no side effect occurred.
                        receipt.insert("request_state".into(), Value::from("failed"));
                        receipt.insert("completion_unknown".into(), Value::Bool(true));
                        receipt.insert(
                            "error".into(),
                            Value::from(format!(
                                "request failed ({}); inspect saved receipts",
                                error.message()
                            )),
                        );
                        receipt.insert("finished_at".into(), serde_json::json!(now()));
                    }
                }
                if let Err(error) = journal.save(&receipt) {
                    tracing::error!(%error, request_id = %id, "request receipt could not be saved");
                }
                journal.tasks.lock().expect("task map").remove(&id);
            });
            handle
        };
        // Awaiting a JoinHandle never transfers ownership of the task itself, so a
        // dropped caller leaves the worker running to completion.
        let _ = worker.await;
        self.status(request_id, false)
    }

    pub fn active_tasks(&self) -> usize {
        self.tasks.lock().expect("task map").len()
    }

    pub async fn drain(&self) {
        loop {
            if self.active_tasks() == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

fn response_unknown(response: &Value, receipt: &Map<String, Value>) -> bool {
    if response.get("completion_unknown") == Some(&Value::Bool(true)) {
        return true;
    }
    for field in ["results", "submission_receipts"] {
        let rows = response
            .get(field)
            .and_then(Value::as_array)
            .or_else(|| receipt.get(field).and_then(Value::as_array));
        if let Some(rows) = rows {
            if rows
                .iter()
                .any(|row| row.get("completion_unknown") == Some(&Value::Bool(true)))
            {
                return true;
            }
        }
    }
    false
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-'))
}

/// Deterministic hash of the identity of a request: same id + same arguments only.
pub fn fingerprint_of(operation: &str, arguments: &Value) -> String {
    let canonical = canonical_json(&Value::Array(vec![
        Value::from(operation),
        arguments.clone(),
    ]));
    let digest = Sha256::digest(canonical.as_bytes());
    hex::encode(digest)
}

/// Compact JSON with object keys sorted recursively (Python `sort_keys=True`).
pub fn canonical_json(value: &Value) -> String {
    fn write(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key).expect("key serializes"));
                    out.push(':');
                    write(&map[*key], out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&serde_json::to_string(other).expect("scalar serializes")),
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> (tempfile::TempDir, Arc<RequestJournal>) {
        let directory = tempfile::tempdir().unwrap();
        let journal = Arc::new(RequestJournal::new(directory.path().join("requests")).unwrap());
        (directory, journal)
    }

    #[test]
    fn request_id_validation_and_hashing() {
        let (_tmp, journal) = journal();
        assert!(journal.directory("req-1").is_ok());
        assert_eq!(
            journal.directory("../etc/passwd").unwrap_err().message(),
            "request_id must contain 1..128 letters, digits, dots, colons, underscores, or hyphens"
        );
        // Directory names are hashes, so no id can escape the journal root.
        let directory = journal.directory("a/b").unwrap_err();
        assert!(directory.message().contains("request_id"));
    }

    #[test]
    fn claim_is_exclusive_and_rejects_changed_arguments() {
        let (_tmp, journal) = journal();
        let arguments = serde_json::json!({"targets": ["a"], "script": "ls"});
        let (created, receipt) = journal.claim("r1", "run", &arguments).unwrap();
        assert!(created);
        assert_eq!(receipt["request_state"], "running");

        let (again, status) = journal.claim("r1", "run", &arguments).unwrap();
        assert!(!again);
        assert_eq!(status["duplicate"], true);
        assert_eq!(status["execution_replayed"], false);

        let changed = serde_json::json!({"targets": ["b"], "script": "ls"});
        let error = journal.claim("r1", "run", &changed).unwrap_err();
        assert!(error.message().contains("already claimed"));
    }

    #[test]
    fn running_receipt_without_owner_is_interrupted() {
        let (_tmp, journal) = journal();
        journal.claim("r2", "run", &Value::Null).unwrap();
        let status = journal.status("r2", false).unwrap();
        assert_eq!(status["request_state"], "interrupted");
        assert_eq!(status["completion_unknown"], true);
        // Persisted, so a later read cannot resurrect "running".
        assert_eq!(journal.load("r2").unwrap()["request_state"], "interrupted");
    }

    #[tokio::test]
    async fn execute_keeps_worker_owned_and_records_response() {
        let (_tmp, journal) = journal();
        let arguments = serde_json::json!({"x": 1});
        let status = journal
            .execute("r3", "run", &arguments, |progress| async move {
                let _ = progress.record(
                    "execution_results",
                    serde_json::json!({"host": "h1", "result_id": "a".repeat(32)}),
                );
                Ok(serde_json::json!({"ok": true, "results": [{"host": "h1"}]}))
            })
            .await
            .unwrap();
        assert_eq!(status["request_state"], "complete");
        assert_eq!(status["completion_unknown"], false);
        assert_eq!(status["results"][0]["host"], "h1");
        assert_eq!(status["execution_results"][0]["result_id"], "a".repeat(32));
        assert_eq!(journal.active_tasks(), 0);
    }

    #[tokio::test]
    async fn duplicate_execute_returns_receipt_without_running() {
        let (_tmp, journal) = journal();
        let arguments = serde_json::json!({"x": 1});
        let first = journal
            .execute("r4", "run", &arguments, |_progress| async move {
                Ok(serde_json::json!({"ok": true}))
            })
            .await
            .unwrap();
        assert_eq!(first["request_state"], "complete");
        let second = journal
            .execute("r4", "run", &arguments, |_progress| async move {
                panic!("duplicate must not execute");
            })
            .await
            .unwrap();
        assert_eq!(second["duplicate"], true);
        assert_eq!(second["execution_replayed"], false);
    }

    #[tokio::test]
    async fn failed_worker_is_not_reported_as_sent_but_is_unknown() {
        let (_tmp, journal) = journal();
        let status = journal
            .execute("r5", "run", &Value::Null, |_progress| async move {
                Err(BridgeError::invalid("boom"))
            })
            .await
            .unwrap();
        assert_eq!(status["request_state"], "failed");
        assert_eq!(status["completion_unknown"], true);
    }

    #[test]
    fn canonical_json_sorts_nested_keys() {
        let value = serde_json::json!({"b": 1, "a": {"d": 2, "c": [3, {"f": 4, "e": 5}]}});
        assert_eq!(
            canonical_json(&value),
            r#"{"a":{"c":[3,{"e":5,"f":4}],"d":2},"b":1}"#
        );
    }

    /// Several targets finishing at once must not overwrite each other's rows.
    #[test]
    fn concurrent_progress_keeps_every_row() {
        let directory = tempfile::tempdir().unwrap();
        let journal =
            std::sync::Arc::new(RequestJournal::new(directory.path().to_path_buf()).unwrap());
        journal
            .claim("req-1", "run", &serde_json::json!({"targets": ["a"]}))
            .unwrap();
        let handles: Vec<_> = (0..8)
            .map(|index| {
                let journal = journal.clone();
                std::thread::spawn(move || {
                    journal
                        .progress(
                            "req-1",
                            "execution_results",
                            serde_json::json!({
                                "host": format!("host-{index}"),
                                "result_id": format!("result-{index}"),
                            }),
                        )
                        .unwrap();
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let receipt = journal.load("req-1").unwrap();
        let rows = receipt
            .get("execution_results")
            .and_then(serde_json::Value::as_array)
            .expect("rows");
        assert_eq!(rows.len(), 8, "rows were lost: {rows:?}");
    }
}
