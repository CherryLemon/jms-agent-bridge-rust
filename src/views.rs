//! Small presentation views; execution rows, receipts and saved results stay canonical.
//!
//! Only known facade envelopes are reduced. Unrecognized operations and failed
//! payloads pass through untouched, because an error's diagnostic detail is exactly
//! what the caller needs next.

use std::collections::HashMap;

use serde_json::{Map, Value};

fn identity(row: &Map<String, Value>, addresses: &HashMap<String, String>) -> Map<String, Value> {
    let mut out = row.clone();
    if let Some(host) = out.get("host").and_then(Value::as_str) {
        if let Some(address) = addresses.get(host) {
            out.insert("host".into(), Value::from(address.clone()));
        }
    }
    out
}

fn get_bool(row: &Map<String, Value>, key: &str) -> bool {
    row.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn execution(row: &Map<String, Value>, addresses: &HashMap<String, String>) -> Map<String, Value> {
    // Keep the stable keys clients use; transport diagnostics stay in metadata.
    const KEYS: [&str; 12] = [
        "host",
        "result_id",
        "ok",
        "exit_code",
        "execution_state",
        "stdout",
        "stderr",
        "stdout_truncated",
        "stderr_truncated",
        "warning",
        "error",
        "message",
    ];
    if !get_bool(row, "ok") {
        return identity(row, addresses);
    }
    let mut out = Map::new();
    for key in KEYS {
        if let Some(value) = row.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    let completed = row.get("execution_state").and_then(Value::as_str) == Some("completed");
    if !completed || get_bool(row, "completion_unknown") {
        for key in [
            "executed",
            "completion_unknown",
            "timed_out",
            "queue_timed_out",
            "failure_stage",
            "connection_state",
        ] {
            if let Some(value) = row.get(key) {
                out.insert(key.to_string(), value.clone());
            }
        }
    }
    if row.get("session_state").and_then(Value::as_str) == Some("lost") {
        if let Some(session_id) = row.get("session_id") {
            out.insert("session_id".into(), session_id.clone());
        }
        out.insert("session_state".into(), Value::from("lost"));
    }
    if row.get("connection_recovery").is_some() || get_bool(row, "reconnected") {
        out.insert("reconnected".into(), Value::Bool(true));
    }
    identity(&out, addresses)
}

fn row_needs_evidence(row: &Map<String, Value>) -> bool {
    let reason = row.get("reason").and_then(Value::as_str);
    let state = row.get("execution_state").and_then(Value::as_str);
    reason == Some("queue_full")
        || get_bool(row, "completion_unknown")
        || matches!(state, Some("unknown") | Some("not_started"))
        || row.get("ok") == Some(&Value::Bool(false))
}

fn receipt_flags(value: &Map<String, Value>, mut out: Map<String, Value>) -> Map<String, Value> {
    let state = value.get("request_state").and_then(Value::as_str);
    if !matches!(state, None | Some("complete")) || get_bool(value, "completion_unknown") {
        for key in [
            "request_id",
            "request_state",
            "completion_unknown",
            "error",
            "execution_results",
            "submission_receipts",
        ] {
            if let Some(item) = value.get(key) {
                out.insert(key.to_string(), item.clone());
            }
        }
    }
    if get_bool(value, "duplicate") {
        if let Some(request_id) = value.get("request_id") {
            out.insert("request_id".into(), request_id.clone());
        }
        out.insert("duplicate".into(), Value::Bool(true));
        out.insert("execution_replayed".into(), Value::Bool(false));
    }
    for key in ["execution_results", "submission_receipts"] {
        let Some(Value::Array(rows)) = value.get(key) else {
            continue;
        };
        if rows
            .iter()
            .filter_map(Value::as_object)
            .any(row_needs_evidence)
        {
            out.insert(key.to_string(), Value::Array(rows.clone()));
        }
    }
    out
}

/// Keep continuation, partial lines and concurrent modification visible.
fn file_page(value: &Value) -> Value {
    let Some(map) = value.as_object() else {
        return value.clone();
    };
    let mut out = map.clone();
    if map.contains_key("text") && map.contains_key("next_byte_offset") {
        for key in ["backend", "elapsed_seconds", "encoding", "decoding_errors"] {
            out.remove(key);
        }
        if get_bool(map, "eof") && !get_bool(map, "changed_during_read") {
            out.remove("fingerprint");
        }
        for key in [
            "partial_first_line",
            "partial_last_line",
            "changed_during_read",
        ] {
            if out.get(key) == Some(&Value::Bool(false)) {
                out.remove(key);
            }
        }
    }
    if let Some(Value::Array(files)) = out.get("files").cloned() {
        out.insert(
            "files".into(),
            Value::Array(files.iter().map(file_page).collect()),
        );
    }
    Value::Object(out)
}

fn operation_of(arguments: &Map<String, Value>) -> String {
    arguments
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Return a presentation copy. Never mutates a saved receipt or its fingerprint.
pub fn compact(
    tool: &str,
    value: &Value,
    arguments: &Map<String, Value>,
    addresses: &HashMap<String, String>,
) -> Value {
    // Staging metadata is added by the runtime, not by the tool, so it is re-attached
    // after the per-tool projection: dropping it would hide that the payload is on disk.
    let staged = season_staging(value);
    let projected = compact_inner(tool, value, arguments, addresses);
    attach_staging(projected, staged)
}

/// Staging fields worth keeping, in the order they are attached.
const STAGING_KEYS: [&str; 6] = [
    "staged",
    "operation",
    "bytes",
    "result_id",
    "preview",
    "note",
];

fn season_staging(value: &Value) -> Option<Map<String, Value>> {
    let map = value.as_object()?;
    if map.get("staged") != Some(&Value::Bool(true)) {
        return None;
    }
    let mut out = Map::new();
    for key in STAGING_KEYS {
        if let Some(item) = map.get(key) {
            out.insert(key.to_string(), item.clone());
        }
    }
    Some(out)
}

fn attach_staging(projected: Value, staged: Option<Map<String, Value>>) -> Value {
    let Some(staged) = staged else {
        return projected;
    };
    let mut out = match projected {
        Value::Object(map) => map,
        other => return other,
    };
    for (key, value) in staged {
        out.insert(key, value);
    }
    Value::Object(out)
}

fn compact_inner(
    tool: &str,
    value: &Value,
    arguments: &Map<String, Value>,
    addresses: &HashMap<String, String>,
) -> Value {
    let Some(map) = value.as_object() else {
        return value.clone();
    };
    let operation = operation_of(arguments);
    if tool == "terminal" || (tool == "call" && operation.starts_with("terminal_")) {
        let mut out = Map::new();
        for (key, item) in map {
            if matches!(
                key.as_str(),
                "request_id"
                    | "request_state"
                    | "accepted_at"
                    | "finished_at"
                    | "operation"
                    | "duplicate"
                    | "execution_replayed"
                    | "execution_results"
                    | "submission_receipts"
            ) {
                continue;
            }
            out.insert(key.clone(), item.clone());
        }
        if out.get("completion_unknown") == Some(&Value::Bool(false)) {
            out.remove("completion_unknown");
        }
        return Value::Object(receipt_flags(map, out));
    }
    if tool == "run" || (tool == "call" && operation == "jms_exec") {
        let Some(Value::Array(results)) = map.get("results") else {
            return value.clone();
        };
        let rows: Vec<Value> = results
            .iter()
            .filter_map(Value::as_object)
            .map(|row| Value::Object(execution(row, addresses)))
            .collect();
        let mut out = Map::new();
        out.insert(
            "ok".into(),
            map.get("ok").cloned().unwrap_or(Value::Bool(false)),
        );
        out.insert("results".into(), Value::Array(rows));
        if get_bool(map, "inventory_stale") {
            out.insert("inventory_stale".into(), Value::Bool(true));
        }
        return Value::Object(receipt_flags(map, out));
    }
    if tool == "fs" || (tool == "call" && operation == "jms_fs") {
        // Unknown or failed execution must retain transport diagnostics inline.
        if !get_bool(map, "ok") {
            return value.clone();
        }
        let mut out = Map::new();
        for key in [
            "ok",
            "host",
            "result_id",
            "action",
            "local_path",
            "path",
            "overwrite",
            "existing_files",
            "stdout",
            "stderr",
            "stdout_truncated",
            "stderr_truncated",
            "warning",
            // A staged response must stay readable as such: without these keys the
            // caller sees only a result id and no hint that the payload moved to disk.
            "staged",
            // Byte accounting of a transfer, so a completed call reports how much moved.
            "progress",
            "operation",
            "bytes",
            "preview",
            "note",
            "request_id",
            "request_state",
            "execution_state",
            "completion_unknown",
            "failure_stage",
            "error",
        ] {
            if let Some(item) = map.get(key) {
                out.insert(key.to_string(), item.clone());
            }
        }
        if let Some(data) = map.get("data") {
            out.insert("data".into(), file_page(data));
        }
        let out = identity(&out, addresses);
        return Value::Object(receipt_flags(map, out));
    }
    if tool == "read_result" {
        let mut out = map.clone();
        out.remove("stream");
        out.remove("total_bytes");
        return Value::Object(out);
    }
    if tool == "discover" {
        if arguments.get("topic").and_then(Value::as_str) == Some("assets") {
            if let Some(Value::Array(assets)) = map.get("assets") {
                let mut out = Map::new();
                for (key, item) in map {
                    if key != "inventory" {
                        out.insert(key.clone(), item.clone());
                    }
                }
                let rows: Vec<Value> = assets
                    .iter()
                    .map(|asset| {
                        let mut row = asset.clone();
                        if let Some(map) = row.as_object_mut() {
                            map.remove("name");
                            map.remove("accounts");
                        }
                        row
                    })
                    .collect();
                out.insert("assets".into(), Value::Array(rows));
                if map
                    .get("inventory")
                    .and_then(|inventory| inventory.get("stale"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    out.insert("inventory_stale".into(), Value::Bool(true));
                }
                return Value::Object(out);
            }
        }
        return value.clone();
    }
    if tool != "call" {
        return value.clone();
    }
    if matches!(
        operation.as_str(),
        "request_status" | "result_metadata" | "script_guard_check"
    ) {
        return value.clone();
    }
    if operation == "jms_accelerator_status" {
        let mut out = Map::new();
        for (key, item) in map {
            if key == "policy" || key == "details" {
                continue;
            }
            out.insert(key.clone(), item.clone());
        }
        if let Some(Value::Array(hosts)) = out.get("hosts").cloned() {
            let rows: Vec<Value> = hosts
                .iter()
                .map(|host| {
                    let mut row = host.clone();
                    if let Some(map) = row.as_object_mut() {
                        map.remove("timing");
                        if let Some(address) = map.get("address").and_then(Value::as_str) {
                            map.insert("host".into(), Value::from(address.to_string()));
                        }
                    }
                    row
                })
                .collect();
            out.insert("hosts".into(), Value::Array(rows));
        }
        return Value::Object(out);
    }
    let mut out = Map::new();
    for (key, item) in map {
        if key == "execution_results" || key == "submission_receipts" {
            continue;
        }
        out.insert(key.clone(), item.clone());
    }
    if let Some(data) = map.get("data").and_then(Value::as_object) {
        let mut trimmed = Map::new();
        for (key, item) in data {
            if key == "execution_results" || key == "submission_receipts" {
                continue;
            }
            trimmed.insert(key.clone(), item.clone());
        }
        let mut data_out = receipt_flags(data, trimmed);
        for key in ["jobs", "status", "hosts"] {
            if let Some(Value::Array(rows)) = data_out.get(key).cloned() {
                let mapped: Vec<Value> = rows
                    .iter()
                    .map(|row| match row.as_object() {
                        Some(map) => Value::Object(identity(map, addresses)),
                        None => row.clone(),
                    })
                    .collect();
                data_out.insert(key.to_string(), Value::Array(mapped));
            }
        }
        if operation == "jms_submit_job" {
            let receipts: Vec<Value> = data
                .get("submission_receipts")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(Value::Array(jobs)) = data_out.get("jobs").cloned() {
                let jobs: Vec<Value> = jobs
                    .iter()
                    .map(|job| {
                        let Some(job_map) = job.as_object() else {
                            return job.clone();
                        };
                        let receipt =
                            receipts
                                .iter()
                                .filter_map(Value::as_object)
                                .find(|receipt| {
                                    let receipt_host =
                                        receipt.get("host").and_then(Value::as_str).map(|host| {
                                            addresses
                                                .get(host)
                                                .cloned()
                                                .unwrap_or_else(|| host.to_string())
                                        });
                                    let job_host = job_map
                                        .get("host")
                                        .and_then(Value::as_str)
                                        .map(str::to_string);
                                    let empty_job_id = job_map
                                        .get("job_id")
                                        .map(|value| value.is_null() || value.as_str() == Some(""))
                                        .unwrap_or(true);
                                    receipt_host == job_host
                                        && (empty_job_id
                                            || receipt.get("job_id") == job_map.get("job_id"))
                                });
                        let mut merged = job_map.clone();
                        if let Some(receipt) = receipt {
                            let launched = get_bool(job_map, "launched");
                            if !launched || get_bool(receipt, "completion_unknown") {
                                for key in [
                                    "job_id",
                                    "submission_state",
                                    "completion_unknown",
                                    "result_id",
                                ] {
                                    if let Some(item) = receipt.get(key) {
                                        merged.insert(key.to_string(), item.clone());
                                    }
                                }
                            }
                        }
                        Value::Object(merged)
                    })
                    .collect();
                data_out.insert("jobs".into(), Value::Array(jobs));
            }
        }
        out.insert("data".into(), Value::Object(data_out));
    }
    Value::Object(receipt_flags(map, out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn arguments(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn a_staged_payload_keeps_its_read_instructions() {
        // `call jms_fs` with a payload above the budget: the runtime replaced `data`
        // with a summary, so the fs projection must not strip the summary away.
        let value = json!({
            "ok": true,
            "host": "h1",
            "staged": true,
            "operation": "jms_fs",
            "bytes": 40000,
            "result_id": "abc",
            "preview": "{\"ok\":true",
            "note": "response exceeded 8192 bytes; full payload saved as abc (read_result with stream='result')",
        });
        let out = compact(
            "call",
            &value,
            &arguments(json!({"operation": "jms_fs"})),
            &HashMap::new(),
        );
        assert_eq!(out["staged"], true);
        assert_eq!(out["result_id"], "abc");
        assert!(out["note"].as_str().unwrap().contains("read_result"));
        assert_eq!(out["bytes"], 40000);
    }

    #[test]
    fn successful_execution_drops_routine_transport_detail() {
        let value = json!({
            "ok": true,
            "results": [{
                "host": "asset-1", "result_id": "r1", "ok": true, "exit_code": 0,
                "execution_state": "completed", "stdout": "hi\n", "bytes": {"stdout": 3},
                "timing": {"queue_seconds": 0.0}, "reconnected": true,
            }],
        });
        let mut addresses = HashMap::new();
        addresses.insert("asset-1".to_string(), "10.0.0.1".to_string());
        let view = compact("run", &value, &arguments(json!({})), &addresses);
        let row = &view["results"][0];
        assert_eq!(row["host"], "10.0.0.1");
        assert_eq!(row["stdout"], "hi\n");
        assert!(row.get("timing").is_none());
        assert!(row.get("bytes").is_none());
        assert_eq!(row["reconnected"], true);
    }

    #[test]
    fn unknown_completion_keeps_evidence() {
        let value = json!({
            "ok": false,
            "results": [{
                "host": "asset-1", "result_id": "r1", "ok": false, "exit_code": 75,
                "execution_state": "unknown", "completion_unknown": true,
                "timing": {"execution_seconds": 1.2},
            }],
        });
        let view = compact("run", &value, &arguments(json!({})), &HashMap::new());
        let row = &view["results"][0];
        assert_eq!(row["completion_unknown"], true);
        assert_eq!(row["execution_state"], "unknown");
        // Failed rows keep their full diagnostic payload.
        assert!(row.get("timing").is_some());
    }

    #[test]
    fn request_state_is_visible_when_not_complete() {
        let value = json!({
            "ok": true, "request_id": "req-1", "request_state": "running",
            "results": [{"host": "h", "ok": true, "result_id": "r", "execution_state": "completed"}],
        });
        let view = compact("run", &value, &arguments(json!({})), &HashMap::new());
        assert_eq!(view["request_state"], "running");
        assert_eq!(view["execution_replayed"], Value::Null);
    }

    #[test]
    fn duplicate_receipt_hides_replay_noise_but_marks_duplicate() {
        let value = json!({
            "ok": true, "request_id": "req-1", "request_state": "complete",
            "duplicate": true, "execution_replayed": false,
            "results": [{"host": "h", "ok": true, "result_id": "r", "execution_state": "completed"}],
        });
        let view = compact("run", &value, &arguments(json!({})), &HashMap::new());
        assert_eq!(view["duplicate"], true);
        assert_eq!(view["execution_replayed"], false);
    }

    #[test]
    fn read_result_view_drops_stream_echo_only() {
        let value = json!({
            "result_id": "r", "stream": "stdout", "offset": 0, "next_offset": 4,
            "total_bytes": 4, "eof": true, "text": "abc\n",
        });
        let view = compact(
            "read_result",
            &value,
            &arguments(json!({})),
            &HashMap::new(),
        );
        assert!(view.get("stream").is_none());
        assert!(view.get("total_bytes").is_none());
        assert_eq!(view["next_offset"], 4);
        assert_eq!(view["text"], "abc\n");
    }

    #[test]
    fn file_page_removes_redundant_flags_only() {
        let page = json!({
            "ok": true, "path": "/tmp/a", "text": "x", "next_byte_offset": 1,
            "backend": "bash", "elapsed_seconds": 0.1, "encoding": "utf-8",
            "decoding_errors": "replace", "eof": true, "changed_during_read": false,
            "partial_first_line": false, "partial_last_line": false,
            "fingerprint": {"size": 1, "mtime_ns": 2},
        });
        let view = file_page(&page);
        assert!(view.get("backend").is_none());
        assert!(view.get("fingerprint").is_none());
        assert!(view.get("partial_last_line").is_none());
        assert_eq!(view["text"], "x");
    }

    #[test]
    fn failed_fs_response_is_returned_whole() {
        let value = json!({
            "ok": false, "result_id": "r", "host": "h", "execution_state": "unknown",
            "completion_unknown": true, "timing": {"queue_seconds": 0.2},
        });
        let view = compact("fs", &value, &arguments(json!({})), &HashMap::new());
        assert_eq!(view, value);
    }

    #[test]
    fn asset_discovery_hides_redundant_name_and_accounts() {
        let value = json!({
            "assets": [{"id": "a", "name": "node-1", "address": "10.0.0.1",
                        "accounts": ["root"], "account": "root", "active": true}],
            "matched": 1, "next_offset": null,
            "inventory": {"stale": true, "assets": 1},
        });
        let view = compact(
            "discover",
            &value,
            &arguments(json!({"topic": "assets"})),
            &HashMap::new(),
        );
        assert!(view["assets"][0].get("name").is_none());
        assert!(view["assets"][0].get("accounts").is_none());
        assert_eq!(view["inventory_stale"], true);
        assert!(view.get("inventory").is_none());
    }

    #[test]
    fn accelerator_view_keeps_per_host_state_and_drops_policy() {
        let value = json!({
            "ok": true, "policy": {"free_util_below_pct": 5}, "details": "read_result(...)",
            "hosts": [{"host": "asset", "address": "10.0.0.9", "state": "free",
                       "timing": {"queue_seconds": 0.0}}],
        });
        let view = compact(
            "call",
            &value,
            &arguments(json!({"operation": "jms_accelerator_status"})),
            &HashMap::new(),
        );
        assert!(view.get("policy").is_none());
        assert!(view.get("details").is_none());
        assert_eq!(view["hosts"][0]["host"], "10.0.0.9");
        assert!(view["hosts"][0].get("timing").is_none());
    }
}
