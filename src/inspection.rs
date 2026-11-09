//! Bounded fleet inspection using the bridge-owned SSH transport.
//!
//! The collector and the per-vendor parsers run on the node — they are the scripts
//! that were written against captured vendor output — and return one parsed JSON
//! snapshot. The bridge owns the fan-out, the execution lane, the enrichment pass and
//! the compact view. "Unknown" is never reported as "free".

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Map, Value};

use crate::errors::{BridgeError, BridgeResult};
use crate::execution::{ExecSpec, Runner};
use crate::inventory::Host;
use crate::rest::AssetCatalog;
use crate::scheduler::{queue_rejection, Lane};
use crate::storage::results::{now, ResultStore};

pub const OPERATION: &str = "jms_accelerator_status";
pub const MAX_HOSTS: usize = 8;

pub fn policy() -> Value {
    json!({
        "free_util_below_pct": 5,
        "free_memory_at_most_pct": 10,
        "requires_complete_metrics_and_process_query": true,
        "snapshot_only_not_a_reservation": true,
    })
}

const FAMILIES_SOURCE: &str = include_str!("../resources/inspection_families.py");
const PROBE_SOURCE: &str = include_str!("../resources/inspection_probe.py");
const PARSE_SOURCE: &str = include_str!("../resources/inspection_parse.py");

/// One remote payload: collector + vendored parsers + node-side parsing.
pub fn node_payload(options: &Value) -> String {
    let families = BASE64.encode(FAMILIES_SOURCE);
    let probe = BASE64.encode(PROBE_SOURCE);
    let parse = BASE64.encode(PARSE_SOURCE);
    let options = BASE64.encode(serde_json::to_vec(options).unwrap_or_else(|_| b"{}".to_vec()));
    // Raw literal: the indented lines are real Python indentation, not Rust string
    // continuations (which strip leading whitespace and break the loader).
    format!(
        r#"python3 -I - <<'__JMS_INSPECTION_PY__'
import base64
import json
import sys
import types


def __jms_load(name, source, inject=None):
    module = types.ModuleType(name)
    if inject:
        module.__dict__.update(inject)
    sys.modules[name] = module
    exec(compile(base64.b64decode(source).decode("utf-8"), name + ".py", "exec"), module.__dict__)
    return module.__dict__


__jms_f = __jms_load("jms_families", "{families}")
__jms_p = __jms_load("jms_probe", "{probe}")
__jms_parse = __jms_load("jms_parse", "{parse}", {{"__jms_f": __jms_f, "__jms_p": __jms_p}})
__jms_parse["__jms_entry"](json.loads(base64.b64decode("{options}").decode("utf-8")))
__JMS_INSPECTION_PY__
"#
    )
}

pub struct AcceleratorInspector {
    catalog: Arc<AssetCatalog>,
    runner: Arc<Runner>,
    store: Arc<ResultStore>,
}

impl AcceleratorInspector {
    pub fn new(catalog: Arc<AssetCatalog>, runner: Arc<Runner>, store: Arc<ResultStore>) -> Self {
        Self {
            catalog,
            runner,
            store,
        }
    }

    pub async fn inspect(&self, targets: &[String], timeout: u64) -> BridgeResult<Value> {
        if targets.is_empty() || targets.len() > MAX_HOSTS {
            return Err(BridgeError::invalid(
                "inspection requires 1-8 explicit targets; no automatic batching",
            ));
        }
        if !(15..=180).contains(&timeout) {
            return Err(BridgeError::invalid(
                "inspection timeout must be an integer in 15..180 seconds",
            ));
        }
        for target in targets {
            if target.is_empty()
                || matches!(target.to_lowercase().as_str(), "all" | "*")
                || target.contains(['*', '?', '[', ']'])
            {
                return Err(BridgeError::invalid(
                    "inspection requires exact asset names, IDs or IPs; no wildcard/all selectors",
                ));
            }
        }
        let inventory = self.catalog.ensure().await?;
        let mut hosts: Vec<Host> = Vec::new();
        for target in targets {
            let resolved = inventory.resolve(std::slice::from_ref(target))?;
            if resolved.len() != 1 {
                return Err(BridgeError::invalid(
                    "each inspection target must resolve to exactly one machine",
                ));
            }
            let host = resolved.into_iter().next().expect("one host");
            if !hosts
                .iter()
                .any(|existing| existing.asset_id == host.asset_id)
            {
                hosts.push(host);
            }
        }
        if hosts.len() > MAX_HOSTS {
            return Err(BridgeError::invalid(
                "inspection resolved to more than 8 machines",
            ));
        }
        // Inspection uses reserved execution capacity and the shared connections.
        let mut set = tokio::task::JoinSet::new();
        for host in hosts {
            let runner = self.runner.clone();
            let store = self.store.clone();
            set.spawn(async move { inspect_host(runner, store, host, timeout).await });
        }
        let mut rows: Vec<Value> = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(row) => rows.push(row),
                Err(error) => {
                    return Err(BridgeError::ssh(format!("inspection task failed: {error}")))
                }
            }
        }
        let ok = rows
            .iter()
            .all(|row| row["errors"].as_array().map(Vec::is_empty).unwrap_or(true));
        let inventory_stale = self.catalog.status()["stale"].as_bool().unwrap_or(false);
        let value = json!({
            "ok": ok,
            "policy": policy(),
            "inventory_stale": inventory_stale,
            "hosts": rows,
        });
        let result_id = self
            .store
            .save_json(&value, metadata("call", Some(OPERATION)))?;
        Ok(json!({
            "ok": ok,
            "result_id": result_id,
            "policy": policy(),
            "inventory_stale": inventory_stale,
            "device_columns": ["id", "state", "util_pct", "memory_used_mib", "memory_total_mib"],
            "hosts": rows.iter().filter_map(|row| row.as_object()).map(compact_host).collect::<Vec<_>>(),
            "details": "read_result(result_id, stream=\"result\"); each host has its own detail result_id",
        }))
    }
}

fn metadata(kind: &str, operation: Option<&str>) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("kind".into(), Value::from(kind));
    if let Some(operation) = operation {
        map.insert("operation".into(), Value::from(operation));
    }
    map
}

async fn run_json(
    runner: &Runner,
    store: &ResultStore,
    host: &Host,
    options: Value,
    timeout: f64,
) -> (Option<Value>, Map<String, Value>) {
    let spec = ExecSpec {
        lane: Lane::Inspection,
        ..Default::default()
    };
    let meta = match runner
        .execute_to_store(host, &node_payload(&options), timeout, &spec, None)
        .await
    {
        Ok(meta) => meta,
        Err(error) => {
            let mut map = Map::new();
            map.insert("ok".into(), Value::Bool(false));
            map.insert("result_id".into(), Value::from(""));
            map.insert("warning".into(), Value::from(error.message()));
            map.insert("failure_stage".into(), Value::from("connection"));
            return (None, map);
        }
    };
    if meta.get("ok") != Some(&Value::Bool(true)) {
        return (None, meta);
    }
    let result_id = meta
        .get("result_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let parsed = read_result_json(store, &result_id);
    (parsed, meta)
}

fn read_result_json(store: &ResultStore, result_id: &str) -> Option<Value> {
    let path = store.path(result_id, "stdout").ok()?;
    let metadata = std::fs::metadata(&path).ok()?;
    if metadata.len() > 8 * 1024 * 1024 {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<Value>(&text) {
        Ok(value) if value.is_object() => Some(value),
        _ => None,
    }
}

async fn inspect_host(
    runner: Arc<Runner>,
    store: Arc<ResultStore>,
    host: Host,
    timeout: u64,
) -> Value {
    let mut row: Map<String, Value> = Map::new();
    row.insert("host".into(), Value::from(host.name.clone()));
    row.insert(
        "address".into(),
        host.address.clone().map(Value::from).unwrap_or(Value::Null),
    );
    row.insert(
        "asset_id".into(),
        host.asset_id
            .clone()
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    row.insert("state".into(), Value::from("unknown"));
    row.insert("whole_node_available".into(), Value::Bool(false));
    row.insert("sampled_at".into(), Value::Null);
    row.insert("devices".into(), json!([]));
    row.insert("processes".into(), json!([]));
    row.insert("errors".into(), json!([]));
    row.insert("warnings".into(), json!([]));
    row.insert("execution_results".into(), json!([]));
    row.insert("timing".into(), json!({}));
    row.insert("sample_received_at".into(), Value::Null);

    let record = |meta: &Map<String, Value>, row: &mut Map<String, Value>| {
        let rejection = queue_rejection(meta);
        if !rejection.is_empty() {
            let entry = json!({
                "result_id": meta.get("result_id").cloned().unwrap_or(Value::Null),
                "reason": rejection.get("reason").cloned().unwrap_or(Value::Null),
                "retryable": rejection.get("retryable").cloned().unwrap_or(Value::Null),
                "queue": rejection.get("queue").cloned().unwrap_or(Value::Null),
            });
            match row.get_mut("backpressure") {
                Some(Value::Array(entries)) => entries.push(entry),
                _ => {
                    row.insert("backpressure".into(), json!([entry]));
                }
            }
        }
        let recovered = meta.get("connection_recovery").cloned();
        let mut ids: Vec<String> = Vec::new();
        for value in [
            meta.get("startup_retry_result_id"),
            recovered
                .as_ref()
                .and_then(|value| value.get("previous_result_id")),
            meta.get("result_id"),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(id) = value.as_str() {
                if !ids.iter().any(|existing| existing == id) {
                    ids.push(id.to_string());
                }
            }
        }
        let merged: Vec<Value> = {
            let mut all: Vec<Value> = row
                .get("execution_results")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|value| {
                    value
                        .as_str()
                        .map(|text| !ids.iter().any(|id| id == text))
                        .unwrap_or(true)
                })
                .collect();
            all.extend(ids.into_iter().map(Value::from));
            all
        };
        row.insert("execution_results".into(), Value::Array(merged));
        if let Some(recovered) = recovered {
            row.insert("connection_recovery".into(), recovered);
        }
        if let Some(Value::Object(timing)) = meta.get("timing") {
            let mut total = row
                .get("timing")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            for (key, value) in timing {
                let previous = total.get(key).and_then(Value::as_f64).unwrap_or(0.0);
                let add = value.as_f64().unwrap_or(0.0);
                total.insert(
                    key.clone(),
                    json!(((previous + add) * 1000.0).round() / 1000.0),
                );
            }
            row.insert("timing".into(), Value::Object(total));
        }
    };

    let (snapshot, snapshot_meta) =
        run_json(&runner, &store, &host, json!({}), timeout as f64).await;
    record(&snapshot_meta, &mut row);
    match snapshot {
        None => {
            let state = if snapshot_meta.get("reason").and_then(Value::as_str) == Some("queue_full")
            {
                "unknown"
            } else if snapshot_meta
                .get("connection_state")
                .and_then(Value::as_str)
                != Some("connected")
            {
                "down"
            } else {
                "unknown"
            };
            row.insert("state".into(), Value::from(state));
            let message = if snapshot_meta.get("failure_stage").and_then(Value::as_str)
                == Some("shell_startup")
            {
                "collector startup failed; script was not sent"
            } else if snapshot_meta.get("completion_unknown") == Some(&Value::Bool(true)) {
                "collector completion unknown after transmission"
            } else {
                "collection failed"
            };
            let result_id = snapshot_meta
                .get("result_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            push(
                &mut row,
                "errors",
                Value::from(format!("{message}; inspect execution result {result_id}")),
            );
        }
        Some(snapshot) => {
            row.insert("sample_received_at".into(), json!(now()));
            if let Value::Object(map) = &snapshot {
                for (key, value) in map {
                    row.insert(key.clone(), value.clone());
                }
            }
            let pids: Vec<u64> = row
                .get("processes")
                .and_then(Value::as_array)
                .map(|rows| {
                    let mut pids: Vec<u64> = rows
                        .iter()
                        .filter_map(|row| row.get("pid").and_then(Value::as_u64))
                        .collect();
                    pids.sort_unstable();
                    pids.dedup();
                    pids
                })
                .unwrap_or_default();
            if !pids.is_empty() {
                let mut limited = pids.clone();
                limited.truncate(128);
                let options = json!({
                    "mode": "processes",
                    "pids": limited,
                    "sampled_at": row.get("sampled_at").cloned().unwrap_or(Value::Null),
                });
                let (details, detail_meta) =
                    run_json(&runner, &store, &host, options, (timeout as f64).min(45.0)).await;
                record(&detail_meta, &mut row);
                match details {
                    Some(details) => {
                        let by_pid: std::collections::HashMap<u64, &Value> = details
                            .get("processes")
                            .and_then(Value::as_array)
                            .map(|rows| {
                                rows.iter()
                                    .filter_map(|row| {
                                        row.get("pid").and_then(Value::as_u64).map(|pid| (pid, row))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        if let Some(Value::Array(rows)) = row.get_mut("processes") {
                            for process in rows.iter_mut() {
                                if let Some(map) = process.as_object_mut() {
                                    let pid = map.get("pid").and_then(Value::as_u64).unwrap_or(0);
                                    match by_pid.get(&pid) {
                                        Some(detail) => {
                                            if let Some(detail) = detail.as_object() {
                                                for (key, value) in detail {
                                                    map.insert(key.clone(), value.clone());
                                                }
                                            }
                                        }
                                        None => {
                                            map.insert(
                                                "detail_state".into(),
                                                Value::from("not_collected"),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(error) = details.get("docker_error").and_then(Value::as_str) {
                            push(&mut row, "warnings", Value::from(error));
                        }
                        row.insert(
                            "process_details_observed_at".into(),
                            details.get("observed_at").cloned().unwrap_or(Value::Null),
                        );
                    }
                    None => push(
                        &mut row,
                        "warnings",
                        Value::from("process enrichment failed; PID occupancy retained"),
                    ),
                }
                if pids.len() > 128 {
                    push(
                        &mut row,
                        "warnings",
                        Value::from(
                            "process metadata limited to 128 PIDs; full occupancy retained",
                        ),
                    );
                }
            }
        }
    }
    row.insert("collected_at".into(), json!(now()));
    let mut meta = metadata("inspection", None);
    meta.insert("host".into(), Value::from(host.name.clone()));
    let result_id = store
        .save_json(&Value::Object(row.clone()), meta)
        .unwrap_or_default();
    row.insert("result_id".into(), Value::from(result_id));
    Value::Object(row)
}

fn push(row: &mut Map<String, Value>, key: &str, value: Value) {
    match row.get_mut(key) {
        Some(Value::Array(items)) => items.push(value),
        _ => {
            row.insert(key.to_string(), json!([value]));
        }
    }
}

/// One host's compact row: states, device tuples and occupant groups.
pub fn compact_host(host: &Map<String, Value>) -> Value {
    let devices = host
        .get("devices")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut order: Vec<Value> = Vec::new();
    let mut groups: std::collections::HashMap<String, Map<String, Value>> =
        std::collections::HashMap::new();
    if let Some(processes) = host.get("processes").and_then(Value::as_array) {
        for process in processes {
            let container = process
                .get("container")
                .and_then(|container| container.get("name"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let command = process
                .get("command")
                .and_then(Value::as_str)
                .or_else(|| process.get("name").and_then(Value::as_str))
                .unwrap_or("?")
                .to_string();
            let user = process
                .get("user")
                .and_then(Value::as_str)
                .map(str::to_string);
            let key = format!(
                "{}\u{1f}{}\u{1f}{}",
                user.clone().unwrap_or_default(),
                container.clone().unwrap_or_default(),
                command
            );
            let entry = groups.entry(key.clone()).or_insert_with(|| {
                order.push(Value::from(key));
                let mut map = Map::new();
                map.insert(
                    "user".into(),
                    user.clone().map(Value::from).unwrap_or(Value::Null),
                );
                map.insert(
                    "container".into(),
                    container.clone().map(Value::from).unwrap_or(Value::Null),
                );
                map.insert("command".into(), Value::from(take_chars(&command, 120)));
                map.insert("pids".into(), json!([]));
                map.insert("devices".into(), json!([]));
                map
            });
            if let Some(pid) = process.get("pid") {
                push(entry, "pids", pid.clone());
            }
            if let Some(owned) = process.get("devices").and_then(Value::as_array) {
                let mut merged: Vec<String> = entry["devices"]
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                for device in owned.iter().filter_map(Value::as_str) {
                    if !merged.iter().any(|existing| existing == device) {
                        merged.push(device.to_string());
                    }
                }
                merged.sort();
                entry.insert(
                    "devices".into(),
                    Value::Array(merged.into_iter().map(Value::from).collect()),
                );
            }
            if process.get("scope").and_then(Value::as_str) == Some("host") {
                entry.insert("scope".into(), Value::from("host; device mapping unknown"));
            }
        }
    }
    let mut row = Map::new();
    for key in [
        "host",
        "address",
        "state",
        "sampled_at",
        "collected_at",
        "whole_node_available",
        "result_id",
        "timing",
        "sample_received_at",
    ] {
        row.insert(
            key.to_string(),
            host.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    let mut models: Vec<String> = devices
        .iter()
        .filter_map(|device| device.get("model").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    models.sort();
    models.dedup();
    row.insert(
        "models".into(),
        Value::Array(models.into_iter().map(Value::from).collect()),
    );
    row.insert(
        "free_devices".into(),
        Value::Array(
            devices
                .iter()
                .filter(|device| device.get("state").and_then(Value::as_str) == Some("free"))
                .filter_map(|device| device.get("id").cloned())
                .collect(),
        ),
    );
    row.insert(
        "devices".into(),
        Value::Array(
            devices
                .iter()
                .map(|device| {
                    json!([
                        device.get("id").cloned().unwrap_or(Value::Null),
                        device.get("state").cloned().unwrap_or(Value::Null),
                        device.get("util_pct").cloned().unwrap_or(Value::Null),
                        device
                            .get("memory_used_mib")
                            .cloned()
                            .unwrap_or(Value::Null),
                        device
                            .get("memory_total_mib")
                            .cloned()
                            .unwrap_or(Value::Null),
                    ])
                })
                .collect(),
        ),
    );
    let occupants: Vec<Value> = order
        .iter()
        .filter_map(|key| key.as_str())
        .filter_map(|key| groups.get(key))
        .take(4)
        .map(|group| Value::Object(group.clone()))
        .collect();
    row.insert("occupants".into(), Value::Array(occupants));
    row.insert(
        "process_count".into(),
        json!(host
            .get("processes")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)),
    );
    row.insert(
        "more_occupant_groups".into(),
        json!(groups.len().saturating_sub(4)),
    );
    if let Some(errors) = host.get("errors").and_then(Value::as_array) {
        if !errors.is_empty() {
            row.insert(
                "errors".into(),
                Value::Array(errors.iter().take(4).cloned().collect()),
            );
        }
    }
    if let Some(warnings) = host.get("warnings").and_then(Value::as_array) {
        if !warnings.is_empty() {
            row.insert(
                "warnings".into(),
                Value::Array(warnings.iter().take(3).cloned().collect()),
            );
        }
    }
    if let Some(backpressure) = host.get("backpressure") {
        row.insert("backpressure".into(), backpressure.clone());
    }
    Value::Object(row)
}

fn take_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_payload_embeds_all_three_modules() {
        let payload = node_payload(&json!({}));
        assert!(payload.starts_with("python3 -I - <<'__JMS_INSPECTION_PY__'"));
        assert!(payload.trim_end().ends_with("__JMS_INSPECTION_PY__"));
        // Base64 payloads cannot terminate the heredoc or become shell syntax.
        assert!(!payload.contains("FAMILIES ="));
        assert!(payload.contains("__jms_entry"));
    }

    #[test]
    fn compact_host_keeps_states_and_occupants() {
        let host = json!({
            "host": "asset-1", "address": "10.0.0.1", "state": "busy",
            "result_id": "r1", "whole_node_available": false,
            "devices": [
                {"id": "nvidia:0", "state": "busy", "util_pct": 90.0,
                 "memory_used_mib": 1000.0, "memory_total_mib": 2000.0, "model": "A100"},
                {"id": "nvidia:1", "state": "free", "util_pct": 0.0,
                 "memory_used_mib": 0.0, "memory_total_mib": 2000.0, "model": "A100"},
            ],
            "processes": [
                {"pid": 42, "user": "alice", "command": "python train.py", "devices": ["nvidia:0"]},
                {"pid": 43, "user": "alice", "command": "python train.py", "devices": ["nvidia:0"]},
                {"pid": 44, "user": "bob", "command": "vllm serve", "devices": ["nvidia:0"]},
            ],
            "errors": ["nvidia: process table unavailable", "e2", "e3", "e4", "e5"],
        });
        let compact = compact_host(host.as_object().unwrap());
        assert_eq!(compact["models"], json!(["A100"]));
        assert_eq!(compact["free_devices"], json!(["nvidia:1"]));
        assert_eq!(compact["process_count"], 3);
        assert_eq!(compact["occupants"].as_array().unwrap().len(), 2);
        assert_eq!(compact["occupants"][0]["pids"], json!([42, 43]));
        assert_eq!(compact["errors"].as_array().unwrap().len(), 4);
        assert_eq!(compact["devices"][0][1], "busy");
    }
}
