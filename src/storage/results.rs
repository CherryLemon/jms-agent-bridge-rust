//! Private, durable results with bounded previews and byte-offset reads.
//!
//! Layout per result: `meta.json`, `stdout.log`, `stderr.log`, `result.json`.
//! Raw bytes are always written whole; previews and pages are computed when a
//! caller asks for them, never by truncating a saved stream.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::errors::{BridgeError, BridgeResult};

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn atomic_json(path: &Path, value: &Value) -> BridgeResult<()> {
    let temp = path.with_file_name(format!(
        "{}.{}.tmp",
        path.file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "state.json".into()),
        Uuid::new_v4().simple()
    ));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let text = serde_json::to_vec(value)?;
        file.write_all(&text)?;
        file.flush()?;
        file.sync_all()?;
    }
    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temp);
            Err(error.into())
        }
    }
}

pub fn sync_directory(path: &Path) -> BridgeResult<()> {
    let directory = File::open(path)?;
    directory.sync_all()?;
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> BridgeResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn valid_result_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// A bounded raw snapshot of both streams, used by callers that preview many
/// results with different budgets without re-reading the files.
pub struct OutputPreview {
    pub stdout_head: Vec<u8>,
    pub stderr_head: Vec<u8>,
    pub stderr_tail: Vec<u8>,
    pub sizes: BTreeMap<String, u64>,
}

impl OutputPreview {
    pub fn stdout_truncated(&self) -> bool {
        self.sizes.get("stdout").copied().unwrap_or(0) > self.stdout_head.len() as u64
    }

    pub fn stderr_truncated(&self) -> bool {
        self.sizes.get("stderr").copied().unwrap_or(0) > self.stderr_head.len() as u64
    }

    /// Spread `budget` over both streams with stderr reserved a share, then decode.
    pub fn compact(&self, budget: usize) -> Map<String, Value> {
        preview_buffers(
            &self.stdout_head,
            &self.stderr_tail,
            budget,
            Some(&self.sizes),
        )
    }
}

/// Head of stdout plus the tail of stderr, sharing one byte budget.
///
/// stderr is reserved up to half the budget so noisy stdout cannot hide the error
/// that explains a failure.
pub fn preview_buffers(
    stdout: &[u8],
    stderr_tail: &[u8],
    budget: usize,
    sizes: Option<&BTreeMap<String, u64>>,
) -> Map<String, Value> {
    let out_size = sizes
        .and_then(|map| map.get("stdout").copied())
        .unwrap_or(stdout.len() as u64);
    let err_size = sizes
        .and_then(|map| map.get("stderr").copied())
        .unwrap_or(stderr_tail.len() as u64);
    let mut err_budget = err_size.min((budget / 2) as u64) as usize;
    let out_budget = out_size.min(budget.saturating_sub(err_budget) as u64) as usize;
    err_budget = err_size.min(budget.saturating_sub(out_budget) as u64) as usize;

    let mut out = Map::new();
    let out_limit = out_budget.min(stdout.len());
    if out_limit > 0 {
        out.insert(
            "stdout".into(),
            Value::from(String::from_utf8_lossy(&stdout[..out_limit]).to_string()),
        );
    }
    if out_size > out_limit as u64 {
        out.insert("stdout_truncated".into(), Value::Bool(true));
    }
    let err_limit = err_budget.min(stderr_tail.len());
    if err_limit > 0 {
        // The tail slice is already aligned to the end of the stream.
        out.insert(
            "stderr".into(),
            Value::from(
                String::from_utf8_lossy(&stderr_tail[stderr_tail.len() - err_limit..]).to_string(),
            ),
        );
    }
    if err_size > err_limit as u64 {
        out.insert("stderr_truncated".into(), Value::Bool(true));
    }
    out
}

pub struct ResultStore {
    pub root: PathBuf,
    ttl_seconds: f64,
    cleanup_interval_seconds: f64,
    active: Mutex<HashSet<String>>,
    /// Serializes metadata mutation so two writers cannot lose an update.
    io: Mutex<()>,
    last_cleanup: Mutex<Option<Value>>,
    stop_retention: Arc<AtomicBool>,
}

impl ResultStore {
    pub fn new(
        root: PathBuf,
        ttl_seconds: f64,
        cleanup_interval_seconds: f64,
    ) -> BridgeResult<Self> {
        if !ttl_seconds.is_finite()
            || ttl_seconds <= 0.0
            || !cleanup_interval_seconds.is_finite()
            || cleanup_interval_seconds <= 0.0
        {
            return Err(BridgeError::invalid(
                "result TTL and cleanup interval must be positive finite seconds",
            ));
        }
        fs::create_dir_all(&root)?;
        set_mode(&root, 0o700)?;
        Ok(Self {
            root,
            ttl_seconds,
            cleanup_interval_seconds,
            active: Mutex::new(HashSet::new()),
            io: Mutex::new(()),
            last_cleanup: Mutex::new(None),
            stop_retention: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn ttl_seconds(&self) -> f64 {
        self.ttl_seconds
    }

    pub fn directory(&self, result_id: &str) -> BridgeResult<PathBuf> {
        if !valid_result_id(result_id) {
            return Err(BridgeError::invalid("invalid result_id"));
        }
        Ok(self.root.join(result_id))
    }

    pub fn path(&self, result_id: &str, stream: &str) -> BridgeResult<PathBuf> {
        let suffix = match stream {
            "stdout" => "stdout.log",
            "stderr" => "stderr.log",
            "result" => "result.json",
            _ => {
                return Err(BridgeError::invalid(
                    "stream must be stdout, stderr, or result",
                ))
            }
        };
        Ok(self.directory(result_id)?.join(suffix))
    }

    /// Create the result directory and its metadata; the caller writes streams.
    pub fn create(&self, metadata: Map<String, Value>) -> BridgeResult<String> {
        let _guard = self.io.lock().expect("result store lock");
        let result_id = Uuid::new_v4().simple().to_string();
        let directory = self.directory(&result_id)?;
        fs::create_dir(&directory)?;
        set_mode(&directory, 0o700)?;
        let mut meta = metadata;
        meta.insert("result_id".into(), Value::from(result_id.clone()));
        meta.insert("created_at".into(), json!(now()));
        meta.insert("status".into(), Value::from("running"));
        atomic_json(&directory.join("meta.json"), &Value::Object(meta))?;
        self.active
            .lock()
            .expect("active lock")
            .insert(result_id.clone());
        Ok(result_id)
    }

    pub fn metadata(&self, result_id: &str) -> BridgeResult<Map<String, Value>> {
        let path = self.directory(result_id)?.join("meta.json");
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::invalid(format!(
                    "unknown or expired result_id; result outputs are retained for {} seconds",
                    format_seconds(self.ttl_seconds)
                )))
            }
            Err(error) => return Err(error.into()),
        };
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(map)) => Ok(map),
            Ok(_) => Err(BridgeError::storage("corrupt result metadata")),
            Err(error) => Err(BridgeError::storage(format!(
                "corrupt result metadata: {error}"
            ))),
        }
    }

    /// Mark a result complete and record the byte size of every stored stream.
    pub fn finish(
        &self,
        result_id: &str,
        values: Map<String, Value>,
    ) -> BridgeResult<Map<String, Value>> {
        let _guard = self.io.lock().expect("result store lock");
        let mut meta = self.metadata(result_id)?;
        for (key, value) in values {
            meta.insert(key, value);
        }
        let finished = now();
        meta.insert("status".into(), Value::from("complete"));
        meta.insert("finished_at".into(), json!(finished));
        meta.insert("expires_at".into(), json!(finished + self.ttl_seconds));
        let mut sizes = Map::new();
        for stream in ["stdout", "stderr", "result"] {
            let path = self.path(result_id, stream)?;
            if let Ok(metadata) = fs::metadata(&path) {
                sizes.insert(stream.to_string(), json!(metadata.len()));
            }
        }
        meta.insert("bytes".into(), Value::Object(sizes));
        atomic_json(
            &self.directory(result_id)?.join("meta.json"),
            &Value::Object(meta.clone()),
        )?;
        self.active.lock().expect("active lock").remove(result_id);
        Ok(meta)
    }

    /// Attach diagnostic associations without changing completion or retention.
    pub fn annotate(
        &self,
        result_id: &str,
        values: Map<String, Value>,
    ) -> BridgeResult<Map<String, Value>> {
        let _guard = self.io.lock().expect("result store lock");
        let mut meta = self.metadata(result_id)?;
        for (key, value) in values {
            meta.insert(key, value);
        }
        atomic_json(
            &self.directory(result_id)?.join("meta.json"),
            &Value::Object(meta.clone()),
        )?;
        Ok(meta)
    }

    pub fn save_json(&self, value: &Value, metadata: Map<String, Value>) -> BridgeResult<String> {
        let result_id = self.create(metadata)?;
        atomic_json(&self.path(&result_id, "result")?, value)?;
        let ok = !matches!(value, Value::Object(map) if map.get("ok") == Some(&Value::Bool(false)));
        let mut values = Map::new();
        values.insert("ok".into(), Value::Bool(ok));
        self.finish(&result_id, values)?;
        Ok(result_id)
    }

    pub fn preview_snapshot(&self, result_id: &str, limit: usize) -> BridgeResult<OutputPreview> {
        if limit > 16384 {
            return Err(BridgeError::invalid(
                "preview snapshot limit must be 0..16384 bytes",
            ));
        }
        let meta = self.metadata(result_id)?;
        let sizes = meta
            .get("bytes")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(key, value)| value.as_u64().map(|size| (key.clone(), size)))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let mut stdout_head = Vec::new();
        let mut stderr_head = Vec::new();
        let mut stderr_tail = Vec::new();
        for stream in ["stdout", "stderr"] {
            let size = sizes.get(stream).copied().unwrap_or(0);
            if size == 0 || limit == 0 {
                continue;
            }
            let path = self.path(result_id, stream)?;
            let mut file = File::open(&path)?;
            let mut prefix = vec![0u8; (size.min(limit as u64)) as usize];
            file.read_exact(&mut prefix)?;
            if stream == "stdout" {
                stdout_head = prefix;
            } else {
                stderr_head = prefix.clone();
                if size <= limit as u64 {
                    stderr_tail = prefix;
                } else {
                    file.seek(SeekFrom::Start(size - limit as u64))?;
                    let mut tail = vec![0u8; limit];
                    file.read_exact(&mut tail)?;
                    stderr_tail = tail;
                }
            }
        }
        Ok(OutputPreview {
            stdout_head,
            stderr_head,
            stderr_tail,
            sizes,
        })
    }

    /// Read a saved stream with an explicit byte budget; stderr keeps tail errors.
    pub fn preview(&self, result_id: &str, budget: usize) -> BridgeResult<Map<String, Value>> {
        let meta = self.metadata(result_id)?;
        let mut sizes = BTreeMap::new();
        if let Some(Value::Object(map)) = meta.get("bytes") {
            for (key, value) in map {
                if let Some(size) = value.as_u64() {
                    sizes.insert(key.clone(), size);
                }
            }
        }
        let err_size = sizes.get("stderr").copied().unwrap_or(0);
        let out_size = sizes.get("stdout").copied().unwrap_or(0);
        let mut err_budget = err_size.min((budget / 2) as u64) as usize;
        let out_budget = out_size.min(budget.saturating_sub(err_budget) as u64) as usize;
        err_budget = err_size.min(budget.saturating_sub(out_budget) as u64) as usize;

        let mut out = Map::new();
        for (stream, limit) in [("stdout", out_budget), ("stderr", err_budget)] {
            let size = sizes.get(stream).copied().unwrap_or(0);
            if size > 0 && limit > 0 {
                let path = self.path(result_id, stream)?;
                let mut file = File::open(&path)?;
                if stream == "stderr" {
                    file.seek(SeekFrom::Start(size.saturating_sub(limit as u64)))?;
                }
                let mut data = vec![0u8; limit];
                let read = read_full(&mut file, &mut data)?;
                out.insert(
                    stream.to_string(),
                    Value::from(String::from_utf8_lossy(&data[..read]).to_string()),
                );
            }
            if size > limit as u64 {
                out.insert(format!("{stream}_truncated"), Value::Bool(true));
            }
        }
        Ok(out)
    }

    pub fn read(
        &self,
        result_id: &str,
        stream: &str,
        offset: u64,
        limit: usize,
        tail: bool,
        pattern: Option<&str>,
    ) -> BridgeResult<Value> {
        let meta = self.metadata(result_id)?;
        if limit == 0 || limit > 16384 {
            return Err(BridgeError::invalid(
                "limit must be 1..16384 bytes; offset must be nonnegative",
            ));
        }
        let path = self.path(result_id, stream)?;
        if !path.exists() {
            let available: Vec<String> = meta
                .get("bytes")
                .and_then(Value::as_object)
                .map(|map| map.keys().cloned().collect())
                .unwrap_or_default();
            return Err(BridgeError::invalid(format!(
                "no {stream} stream; available: {available:?}"
            )));
        }
        let size = fs::metadata(&path)?.len();
        if let Some(pattern) = pattern {
            if tail || pattern.is_empty() || pattern.len() > 1024 {
                return Err(BridgeError::invalid(
                    "search needs a nonempty pattern of at most 1024 bytes and tail=false",
                ));
            }
            return self.search(&path, result_id, stream, pattern, offset, limit, size);
        }
        let mut start = if tail {
            size.saturating_sub(limit as u64)
        } else {
            offset.min(size)
        };
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(start))?;
        let mut data = vec![0u8; limit + 3];
        let read = read_full(&mut file, &mut data)?;
        data.truncate(read);
        if tail {
            // Never start a page in the middle of a UTF-8 sequence.
            while !data.is_empty() && (0x80..0xC0).contains(&data[0]) {
                data.remove(0);
                start += 1;
            }
        }
        let mut count = limit.min(data.len());
        while count < data.len() && (0x80..0xC0).contains(&data[count]) {
            count += 1;
        }
        data.truncate(count);
        let end = start + data.len() as u64;
        let mut out = Map::new();
        out.insert("result_id".into(), Value::from(result_id));
        out.insert("stream".into(), Value::from(stream));
        out.insert("offset".into(), json!(start));
        out.insert("next_offset".into(), json!(end));
        out.insert("total_bytes".into(), json!(size));
        out.insert("eof".into(), Value::Bool(end >= size));
        out.insert(
            "text".into(),
            Value::from(String::from_utf8_lossy(&data).to_string()),
        );
        Ok(Value::Object(out))
    }

    fn search(
        &self,
        path: &Path,
        result_id: &str,
        stream: &str,
        pattern: &str,
        offset: u64,
        limit: usize,
        size: u64,
    ) -> BridgeResult<Value> {
        let needle = pattern.as_bytes();
        let start = offset.min(size);
        // Bounded scan and bounded result: the cursor can continue past any page.
        let end = size.min(start + 8 * 1024 * 1024);
        let mut matches = Vec::new();
        let mut spent = 0usize;
        let mut cursor = start;
        let mut file = File::open(path)?;
        while cursor < end && spent < limit && matches.len() < 20 {
            file.seek(SeekFrom::Start(cursor))?;
            let advance = 65536u64.min(end - cursor);
            let mut buffer = vec![0u8; (advance as usize) + needle.len().saturating_sub(1)];
            let read = read_full(&mut file, &mut buffer)?;
            buffer.truncate(read);
            let found = find_subslice(&buffer, needle);
            let Some(position) = found else {
                cursor += advance;
                continue;
            };
            let absolute = cursor + position as u64;
            let low = absolute.saturating_sub(120);
            file.seek(SeekFrom::Start(low))?;
            let want = 360.min(limit - spent);
            let mut snippet = vec![0u8; want];
            let read = read_full(&mut file, &mut snippet)?;
            snippet.truncate(read);
            let mut row = Map::new();
            row.insert("offset".into(), json!(absolute));
            row.insert(
                "text".into(),
                Value::from(String::from_utf8_lossy(&snippet).to_string()),
            );
            matches.push(Value::Object(row));
            spent += snippet.len();
            cursor = absolute + needle.len() as u64;
        }
        let mut out = Map::new();
        out.insert("result_id".into(), Value::from(result_id));
        out.insert("stream".into(), Value::from(stream));
        out.insert("matches".into(), Value::Array(matches));
        out.insert("next_offset".into(), json!(cursor.min(size)));
        out.insert("total_bytes".into(), json!(size));
        out.insert("eof".into(), Value::Bool(cursor >= size));
        Ok(Value::Object(out))
    }

    pub fn retention_status(&self) -> Value {
        let active = self.active.lock().expect("active lock").len();
        let last_cleanup = self
            .last_cleanup
            .lock()
            .expect("cleanup lock")
            .clone()
            .unwrap_or(Value::Null);
        json!({
            "ttl_seconds": self.ttl_seconds,
            "cleanup_interval_seconds": self.cleanup_interval_seconds,
            "active_results": active,
            "last_cleanup": last_cleanup,
            "request_receipts": "retained separately; TTL never enables request replay",
        })
    }

    /// Expire completed outputs and abandoned old results; never live writers.
    pub fn cleanup(&self, now: f64) -> Value {
        let mut report = json!({
            "at": now,
            "removed": 0,
            "removed_bytes": 0,
            "active_skipped": 0,
            "invalid_skipped": 0,
            "abandoned_removed": 0,
            "errors": 0,
        });
        let mut removed = 0u64;
        let mut removed_bytes = 0u64;
        let mut active_skipped = 0u64;
        let mut invalid_skipped = 0u64;
        let mut abandoned_removed = 0u64;
        let mut errors = 0u64;
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(_) => {
                report["errors"] = json!(1);
                return report;
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let garbage = name.starts_with(".gc-") && valid_result_id(&name[4..]);
            if !valid_result_id(&name) && !garbage {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => {
                    errors += 1;
                    continue;
                }
            };
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                continue;
            }
            let directory = entry.path();
            if self.active.lock().expect("active lock").contains(&name) {
                active_skipped += 1;
                continue;
            }
            if !garbage {
                let meta_path = directory.join("meta.json");
                if meta_path.is_symlink() {
                    invalid_skipped += 1;
                    continue;
                }
                let stamp = match fs::read_to_string(&meta_path)
                    .ok()
                    .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                {
                    Some(Value::Object(map)) => {
                        let key = if map.get("status").and_then(Value::as_str) == Some("complete") {
                            "finished_at"
                        } else {
                            "created_at"
                        };
                        map.get(key).and_then(Value::as_f64)
                    }
                    _ => None,
                };
                let Some(stamp) = stamp else {
                    invalid_skipped += 1;
                    continue;
                };
                if now - stamp < self.ttl_seconds {
                    continue;
                }
                let complete = fs::read_to_string(&meta_path)
                    .ok()
                    .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                    .and_then(|value| {
                        value
                            .get("status")
                            .and_then(Value::as_str)
                            .map(|status| status == "complete")
                    })
                    .unwrap_or(false);
                if !complete {
                    abandoned_removed += 1;
                }
                let trash = self.root.join(format!(".gc-{name}"));
                if fs::rename(&directory, &trash).is_err() {
                    errors += 1;
                    continue;
                }
                removed_bytes += directory_size(&trash);
                if fs::remove_dir_all(&trash).is_ok() {
                    removed += 1;
                } else {
                    errors += 1;
                }
            } else {
                removed_bytes += directory_size(&directory);
                if fs::remove_dir_all(&directory).is_ok() {
                    removed += 1;
                } else {
                    errors += 1;
                }
            }
        }
        report["removed"] = json!(removed);
        report["removed_bytes"] = json!(removed_bytes);
        report["active_skipped"] = json!(active_skipped);
        report["invalid_skipped"] = json!(invalid_skipped);
        report["abandoned_removed"] = json!(abandoned_removed);
        report["errors"] = json!(errors);
        *self.last_cleanup.lock().expect("cleanup lock") = Some(report.clone());
        report
    }

    /// Start the hourly retention sweep. It never deletes a live writer.
    pub fn start_retention(self: &Arc<Self>) {
        let store = self.clone();
        let stop = self.stop_retention.clone();
        tokio::spawn(async move {
            let interval =
                std::time::Duration::from_secs_f64(store.cleanup_interval_seconds.max(1.0));
            loop {
                let sweeper = store.clone();
                let _ = tokio::task::spawn_blocking(move || sweeper.cleanup(now())).await;
                let mut waited = 0.0;
                while waited < store.cleanup_interval_seconds {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    waited += 0.2;
                    let _ = interval;
                }
                if stop.load(Ordering::SeqCst) {
                    return;
                }
            }
        });
    }

    pub fn stop_retention(&self) {
        self.stop_retention.store(true, Ordering::SeqCst);
    }
}

fn read_full(file: &mut File, buffer: &mut [u8]) -> BridgeResult<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(filled)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn directory_size(path: &Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() && !metadata.file_type().is_symlink() {
                    total += metadata.len();
                }
            }
        }
    }
    total
}

fn format_seconds(value: f64) -> String {
    if (value.fract()).abs() < f64::EPSILON {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Arc<ResultStore>) {
        let directory = tempfile::tempdir().unwrap();
        let store = ResultStore::new(directory.path().join("results"), 3600.0, 3600.0).unwrap();
        (directory, Arc::new(store))
    }

    fn write_streams(store: &ResultStore, result_id: &str, stdout: &[u8], stderr: &[u8]) {
        fs::write(store.path(result_id, "stdout").unwrap(), stdout).unwrap();
        fs::write(store.path(result_id, "stderr").unwrap(), stderr).unwrap();
    }

    #[test]
    fn finish_records_sizes_and_expiry() {
        let (_tmp, store) = store();
        let mut meta = Map::new();
        meta.insert("kind".into(), Value::from("run"));
        let result_id = store.create(meta).unwrap();
        write_streams(&store, &result_id, b"hello\n", b"");
        let meta = store.finish(&result_id, Map::new()).unwrap();
        assert_eq!(meta["status"], "complete");
        assert_eq!(meta["bytes"]["stdout"], 6);
        assert!(meta["expires_at"].as_f64().unwrap() > meta["finished_at"].as_f64().unwrap());
    }

    #[test]
    fn read_pages_never_split_utf8() {
        let (_tmp, store) = store();
        let result_id = store.create(Map::new()).unwrap();
        // "é" is two bytes; a 1-byte page must not cut it in half.
        write_streams(&store, &result_id, "aé".as_bytes(), b"");
        store.finish(&result_id, Map::new()).unwrap();
        let first = store.read(&result_id, "stdout", 0, 1, false, None).unwrap();
        assert_eq!(first["text"], "a");
        assert_eq!(first["next_offset"], 1);
        let second = store.read(&result_id, "stdout", 1, 1, false, None).unwrap();
        assert_eq!(second["text"], "é");
        assert_eq!(second["next_offset"], 3);
        assert_eq!(second["eof"], true);
    }

    #[test]
    fn tail_reserves_stderr_and_reports_truncation() {
        let (_tmp, store) = store();
        let result_id = store.create(Map::new()).unwrap();
        write_streams(&store, &result_id, &vec![b'o'; 200], &vec![b'e'; 200]);
        store.finish(&result_id, Map::new()).unwrap();
        let preview = store.preview(&result_id, 100).unwrap();
        assert_eq!(preview["stdout_truncated"], true);
        assert_eq!(preview["stderr_truncated"], true);
        // 50/50 split of the budget, stderr from the end of the stream.
        assert_eq!(preview["stdout"].as_str().unwrap().len(), 50);
        assert_eq!(preview["stderr"].as_str().unwrap().len(), 50);
    }

    #[test]
    fn search_reports_offsets_and_continuation() {
        let (_tmp, store) = store();
        let result_id = store.create(Map::new()).unwrap();
        write_streams(
            &store,
            &result_id,
            b"alpha\nERROR one\nbeta\nERROR two\n",
            b"",
        );
        store.finish(&result_id, Map::new()).unwrap();
        let found = store
            .read(&result_id, "stdout", 0, 4096, false, Some("ERROR"))
            .unwrap();
        assert_eq!(found["matches"].as_array().unwrap().len(), 2);
        assert_eq!(found["matches"][0]["offset"], 6);
        assert_eq!(found["matches"][1]["offset"], 21);
        // Scanning continues to the window end after the last match.
        assert_eq!(found["next_offset"], 31);
        assert_eq!(found["eof"], true);
    }

    #[test]
    fn unknown_result_id_is_an_argument_error() {
        let (_tmp, store) = store();
        let error = store
            .read(&"0".repeat(32), "stdout", 0, 10, false, None)
            .unwrap_err();
        assert!(error.message().contains("unknown or expired result_id"));
        let invalid = store
            .read("not-an-id", "stdout", 0, 10, false, None)
            .unwrap_err();
        assert_eq!(invalid.message(), "invalid result_id");
    }

    #[test]
    fn cleanup_removes_expired_and_skips_active() {
        let (_tmp, store) = store();
        let done = store.create(Map::new()).unwrap();
        write_streams(&store, &done, b"x", b"");
        store.finish(&done, Map::new()).unwrap();
        let running = store.create(Map::new()).unwrap();
        let report = store.cleanup(now() + 10_000.0);
        assert_eq!(report["removed"], 1);
        assert_eq!(report["active_skipped"], 1);
        assert!(!store.directory(&done).unwrap().exists());
        assert!(store.directory(&running).unwrap().exists());
    }
}
