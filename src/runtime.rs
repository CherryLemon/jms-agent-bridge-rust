//! The resident bridge: one owner for connections, receipts, results and workers.
//!
//! MCP handlers are entry points only. Every accepted request is executed by a
//! service-owned task, so a client that disconnects mid-call can still reconcile the
//! request by id instead of leaving orphaned work or a lost result.

use std::path::Path;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::config::{load_config, load_settings, BastionConfig, BridgeSettings, StateLock};
use crate::errors::{BridgeError, BridgeResult};
use crate::execution::{ExecSpec, Runner};
use crate::filesystem::Filesystem;
use crate::guard;
use crate::inspection::AcceleratorInspector;
use crate::inventory::Host;
use crate::jobs::{validate_job_id, Jobs};
use crate::rest::AssetCatalog;
use crate::scheduler::{queue_rejection, Lane};
use crate::schemas::{self, DANGEROUS_FLAG_DESCRIPTION};
use crate::storage::journal::RequestJournal;
use crate::storage::results::{now, ResultStore};
use crate::terminal::{Interactive, ReadWait};

pub struct BridgeRuntime {
    pub cfg: Arc<BastionConfig>,
    pub settings: Arc<BridgeSettings>,
    pub store: Arc<ResultStore>,
    pub journal: Arc<RequestJournal>,
    pub catalog: Arc<AssetCatalog>,
    pub runner: Arc<Runner>,
    pub filesystem: Arc<Filesystem>,
    pub terminals: Arc<Interactive>,
    pub jobs: Arc<Jobs>,
    pub inspector: Arc<AcceleratorInspector>,
    pub started_at: f64,
    discovery_scope: uuid::Uuid,
    _lock: Option<StateLock>,
}

impl BridgeRuntime {
    pub async fn start(
        config_path: Option<&Path>,
        take_state_lock: bool,
    ) -> BridgeResult<Arc<Self>> {
        crate::tls::install_default_provider();
        let cfg = Arc::new(load_config(config_path)?);
        let settings = Arc::new(load_settings(config_path)?);
        let lock = if take_state_lock {
            Some(StateLock::acquire(&settings.state_dir)?)
        } else {
            None
        };
        let store = Arc::new(ResultStore::new(
            settings.state_dir.join("results"),
            settings.result_ttl_seconds,
            settings.result_cleanup_interval_seconds,
        )?);
        store.start_retention();
        let journal = Arc::new(RequestJournal::new(settings.state_dir.join("requests"))?);
        let catalog = AssetCatalog::new(cfg.clone(), settings.clone())?;
        let runner = Runner::new(cfg.clone(), settings.clone(), store.clone())?;
        let filesystem = Arc::new(Filesystem::new(
            catalog.clone(),
            runner.clone(),
            store.clone(),
        ));
        let terminals = Arc::new(Interactive::new(
            catalog.clone(),
            runner.clone(),
            store.clone(),
        ));
        terminals.start().await?;
        let jobs = Arc::new(Jobs::new(runner.clone()));
        let inspector = Arc::new(AcceleratorInspector::new(
            catalog.clone(),
            runner.clone(),
            store.clone(),
        ));
        catalog.start();
        Ok(Arc::new(Self {
            cfg,
            settings,
            store,
            journal,
            catalog,
            runner,
            filesystem,
            terminals,
            jobs,
            inspector,
            started_at: now(),
            discovery_scope: uuid::Uuid::new_v4(),
            _lock: lock,
        }))
    }

    pub async fn shutdown(&self) {
        self.catalog.close();
        self.terminals.close_all().await;
        let _ = self.filesystem.workers.close().await;
        self.runner.close().await;
        self.journal.drain().await;
        self.store.stop_retention();
    }

    pub fn guard_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for pattern in guard::DANGEROUS_PATTERNS {
            hasher.update(pattern.as_bytes());
            hasher.update([0]);
        }
        hex::encode(hasher.finalize())
    }

    pub async fn status(&self) -> Value {
        let mut value = json!({
            "inventory": self.catalog.status(),
            "ssh_connections": self.runner.connection_status().await,
            "persistent_shells": self.runner.sessions().await,
            "result_directory": self.store.root.to_string_lossy(),
            "result_retention": self.store.retention_status(),
            "filesystem_workers": self.filesystem.workers.status().await,
            "rg_helper": {"command": "rg", "fallback": "bash grep/awk"},
            "execution": {
                "queue_timeout_seconds": self.runner.queue_timeout,
            },
            "login": {"serialized": true, "minimum_interval_seconds": 5},
            "requests": {"active": self.journal.active_tasks()},
        });
        let scheduler = self.runner.scheduler.status().await;
        if let Some(execution) = value.get_mut("execution").and_then(Value::as_object_mut) {
            for (key, item) in scheduler.as_object().cloned().unwrap_or_default() {
                execution.insert(key, item);
            }
        }
        if let Some(map) = value.as_object_mut() {
            map.insert(
                "service".into(),
                json!({
                    "version": crate::version(),
                    "started_at": self.started_at,
                    "guard": "literal-bash-substring-v1",
                    "guard_sha256": self.guard_digest(),
                }),
            );
        }
        value
    }

    async fn inventory(&self) -> BridgeResult<crate::inventory::Inventory> {
        self.catalog.ensure().await
    }

    async fn resolve_one(&self, selector: &str) -> BridgeResult<Host> {
        if selector.eq_ignore_ascii_case("all") || selector.contains(['*', '?', '[', ']']) {
            return Err(BridgeError::invalid(
                "this operation needs one exact target, not a wildcard",
            ));
        }
        let inventory = self.inventory().await?;
        let hosts = inventory.resolve(&[selector.to_string()])?;
        if hosts.len() != 1 {
            return Err(BridgeError::invalid(
                "this operation needs exactly one permitted asset",
            ));
        }
        Ok(hosts.into_iter().next().expect("one host"))
    }

    async fn resolve_many(&self, targets: &[String]) -> BridgeResult<Vec<Host>> {
        let inventory = self.inventory().await?;
        let hosts = inventory.resolve(targets)?;
        if hosts.is_empty() {
            let why = self
                .catalog
                .explain_no_targets()
                .map(|why| format!(" — {why}"))
                .unwrap_or_default();
            return Err(BridgeError::invalid(format!(
                "no permitted SSH assets matched the targets{why}"
            )));
        }
        Ok(hosts)
    }

    // --- run -----------------------------------------------------------------

    async fn run_inner(
        &self,
        arguments: Map<String, Value>,
        progress: Option<Arc<dyn crate::storage::journal::ProgressSink>>,
    ) -> BridgeResult<Value> {
        let targets = string_list(arguments.get("targets"));
        let script = arguments
            .get("script")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let timeout = arguments
            .get("timeout")
            .and_then(Value::as_f64)
            .or_else(|| {
                arguments
                    .get("timeout")
                    .and_then(Value::as_u64)
                    .map(|v| v as f64)
            })
            .unwrap_or(60.0);
        let max_output = arguments
            .get("max_output_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(4096) as usize;
        if !(1.0..=600.0).contains(&timeout) || !(256..=16384).contains(&max_output) {
            return Err(BridgeError::invalid(
                "timeout must be 1..600 seconds; max_output_bytes must be 256..16384",
            ));
        }
        if targets.is_empty() {
            return Err(BridgeError::invalid("targets must not be empty"));
        }
        let spec = ExecSpec {
            cwd: arguments
                .get("cwd")
                .and_then(Value::as_str)
                .map(str::to_string),
            env: string_pairs(arguments.get("env")),
            container: arguments
                .get("container")
                .and_then(Value::as_str)
                .map(str::to_string),
            image: arguments
                .get("image")
                .and_then(Value::as_str)
                .map(str::to_string),
            docker_args: string_list(arguments.get("docker_args")),
            session_id: arguments
                .get("session_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            wrapped: false,
            lane: Lane::General,
            queue_timeout: None,
            internal_session: false,
            startup_probe: false,
            fs_deadline: None,
        };
        let hosts = self.resolve_many(&targets).await?;
        let mut set = tokio::task::JoinSet::new();
        // One shared copy of the script: a large script on many targets must not be
        // cloned once per task.
        let script: Arc<str> = Arc::from(script.as_str());
        for host in hosts {
            let runner = self.runner.clone();
            let script = script.clone();
            let spec = spec.clone();
            let progress = progress.clone();
            let name = host.name.clone();
            set.spawn(async move {
                let outcome = runner
                    .execute_to_store(&host, script.as_ref(), timeout, &spec, progress.as_deref())
                    .await;
                (name, outcome)
            });
        }
        let mut metas: Vec<Map<String, Value>> = Vec::new();
        // One target failing to set up must not hide the other targets' results: the
        // per-target failure becomes a row of its own (executed=false, not_started).
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((_name, Ok(meta))) => metas.push(meta),
                Ok((name, Err(failure))) => metas.push(failure_row(&name, &failure)),
                // A panicked or cancelled task says nothing about the wire.
                Err(error) => metas.push(unknown_row(
                    "<cancelled>",
                    &format!("fan-out task failed: {error}"),
                )),
            }
        }
        metas.sort_by_key(|meta| {
            meta.get("host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        });
        let rows = crate::execution::fanout_rows(&self.store, &metas, max_output)?;
        let ok = metas
            .iter()
            .all(|meta| meta.get("ok") == Some(&Value::Bool(true)));
        let mut value = Map::new();
        value.insert("ok".into(), Value::Bool(ok));
        value.insert("results".into(), Value::Array(rows));
        if self.catalog.status()["stale"].as_bool().unwrap_or(false) {
            value.insert("inventory_stale".into(), Value::Bool(true));
        }
        Ok(Value::Object(value))
    }

    pub async fn tool_run(self: &Arc<Self>, arguments: Map<String, Value>) -> BridgeResult<Value> {
        let mut arguments = arguments;
        let script = arguments.get("script").and_then(Value::as_str);
        let script_path = arguments.get("script_path").and_then(Value::as_str);
        if script.is_some() == script_path.is_some() {
            return Err(BridgeError::invalid(
                "provide exactly one of script or script_path",
            ));
        }
        if let Some(path) = script_path {
            if !path.starts_with('/') {
                return Err(BridgeError::invalid(
                    "script_path must name an existing absolute local file",
                ));
            }
            let text = std::fs::read_to_string(path).map_err(|error| {
                BridgeError::invalid(format!("script_path could not be read: {error}"))
            })?;
            arguments.insert("script".into(), Value::from(text));
            arguments.remove("script_path");
        }
        let script = arguments
            .get("script")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let allow_dangerous = arguments
            .get("allow_dangerous")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if guard::is_dangerous(&script) && !allow_dangerous {
            return Err(BridgeError::invalid(
                "script matched the existing destructive-pattern guard; authorized operations \
require allow_dangerous=true",
            ));
        }
        if let Some(request_id) = arguments
            .get("request_id")
            .and_then(Value::as_str)
            .map(str::to_string)
        {
            // The fingerprint is computed over the normalized call (defaults filled,
            // absent optionals as null) so an equivalent retry matches receipts written
            // by the Python bridge as well as by this service.
            let identity = normalize_run_arguments(&arguments);
            let runtime = self.clone();
            let work = arguments.clone();
            return self
                .journal
                .execute(&request_id, "run", &identity, move |progress| async move {
                    runtime.run_inner(work, Some(progress)).await
                })
                .await;
        }
        self.run_inner(arguments, None).await
    }

    // --- fs ------------------------------------------------------------------

    pub async fn tool_fs(self: &Arc<Self>, arguments: Map<String, Value>) -> BridgeResult<Value> {
        crate::filesystem::validate(&arguments)?;
        let action = arguments
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if let Some(request_id) = arguments
            .get("request_id")
            .and_then(Value::as_str)
            .map(str::to_string)
        {
            if !matches!(action.as_str(), "upload" | "download") {
                return Err(BridgeError::invalid(
                    "fs request_id applies to upload/download only",
                ));
            }
            let mut identity = arguments.clone();
            identity.remove("request_id");
            let filesystem = self.filesystem.clone();
            let work = identity.clone();
            return self
                .journal
                .execute(
                    &request_id,
                    "jms_fs",
                    &Value::Object(identity),
                    move |progress| async move {
                        filesystem.execute(work, Some(progress.as_ref())).await
                    },
                )
                .await;
        }
        self.filesystem.execute(arguments, None).await
    }

    // --- terminal ------------------------------------------------------------

    pub async fn tool_terminal(
        self: &Arc<Self>,
        action: &str,
        arguments: Map<String, Value>,
    ) -> BridgeResult<Value> {
        let page = PageOptions::from(&arguments);
        let request_id = arguments
            .get("request_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let identity = |map: &Map<String, Value>| {
            let mut identity = map.clone();
            for key in ["request_id", "wait_ms", "wait_for", "max_bytes", "cursor"] {
                identity.remove(key);
            }
            identity
        };
        if action != "read" && arguments.contains_key("result_id") {
            return Err(BridgeError::invalid("result_id is only for terminal read"));
        }
        if action != "close" && arguments.contains_key("expected_result_id") {
            return Err(BridgeError::invalid(
                "expected_result_id is only for terminal close",
            ));
        }
        if matches!(action, "open" | "close") && arguments.contains_key("wait_for") {
            return Err(BridgeError::invalid(
                "wait_for is only for terminal exec, read or write",
            ));
        }
        match action {
            "open" => {
                let target = arguments
                    .get("target")
                    .and_then(Value::as_str)
                    .ok_or_else(|| BridgeError::invalid("terminal open requires target"))?;
                let env = string_pairs(arguments.get("env"));
                let docker_args = string_list(arguments.get("docker_args"));
                self.terminals
                    .open(
                        target,
                        arguments.get("container").and_then(Value::as_str),
                        arguments.get("image").and_then(Value::as_str),
                        &docker_args,
                        arguments.get("cwd").and_then(Value::as_str),
                        &env,
                    )
                    .await
            }
            "exec" => {
                if let Some(request_id) = request_id {
                    let terminals = self.terminals.clone();
                    let work = identity(&arguments);
                    let session = used_string(&work, "session")?;
                    let script = used_string(&work, "script")?;
                    let allow = work
                        .get("allow_dangerous")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    return self
                        .journal
                        .execute(
                            &request_id,
                            "terminal_exec",
                            &Value::Object(work),
                            move |progress| async move {
                                let sink: Arc<dyn crate::storage::journal::ProgressSink> = progress;
                                terminals
                                    .execute_with_wait(
                                        &session,
                                        &script,
                                        allow,
                                        page.read_wait(),
                                        page.max_bytes,
                                        page.cursor.as_ref(),
                                        Some(sink.as_ref()),
                                    )
                                    .await
                            },
                        )
                        .await;
                }
                let session = used_string(&arguments, "session")?;
                let script = used_string(&arguments, "script")?;
                let allow = arguments
                    .get("allow_dangerous")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                self.terminals
                    .execute_with_wait(
                        &session,
                        &script,
                        allow,
                        page.read_wait(),
                        page.max_bytes,
                        page.cursor.as_ref(),
                        None,
                    )
                    .await
            }
            "read" => {
                let session = used_string(&arguments, "session")?;
                if arguments.contains_key("result_id") {
                    let result_id = used_string(&arguments, "result_id")?;
                    return self
                        .terminals
                        .read_result_with_wait(
                            &session,
                            &result_id,
                            page.read_wait(),
                            page.max_bytes,
                            page.cursor.as_ref(),
                        )
                        .await;
                }
                self.terminals
                    .read_with_wait(
                        &session,
                        page.read_wait(),
                        page.max_bytes,
                        page.cursor.as_ref(),
                    )
                    .await
            }
            "write" => {
                if let Some(request_id) = request_id {
                    let terminals = self.terminals.clone();
                    let work = identity(&arguments);
                    let session = used_string(&work, "session")?;
                    let input = work
                        .get("input")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    let signal = work
                        .get("signal")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    let eof = work.get("eof").and_then(Value::as_bool).unwrap_or(false);
                    let allow = work
                        .get("allow_dangerous")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let cursor = page.cursor.clone();
                    let (wait, max_bytes) = (page.read_wait(), page.max_bytes);
                    return self
                        .journal
                        .execute(
                            &request_id,
                            "terminal_write",
                            &Value::Object(work),
                            move |_progress| async move {
                                terminals
                                    .write_with_wait(
                                        &session,
                                        input.as_deref(),
                                        signal.as_deref(),
                                        eof,
                                        allow,
                                        wait,
                                        max_bytes,
                                        cursor.as_ref(),
                                    )
                                    .await
                            },
                        )
                        .await;
                }
                let session = used_string(&arguments, "session")?;
                let input = arguments.get("input").and_then(Value::as_str);
                let signal = arguments.get("signal").and_then(Value::as_str);
                let eof = arguments
                    .get("eof")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let allow = arguments
                    .get("allow_dangerous")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                self.terminals
                    .write_with_wait(
                        &session,
                        input,
                        signal,
                        eof,
                        allow,
                        page.read_wait(),
                        page.max_bytes,
                        page.cursor.as_ref(),
                    )
                    .await
            }
            "close" => {
                let session = used_string(&arguments, "session")?;
                let expected = arguments
                    .contains_key("expected_result_id")
                    .then(|| used_string(&arguments, "expected_result_id"))
                    .transpose()?;
                self.terminals
                    .close_with_expected_result(&session, expected.as_deref())
                    .await
            }
            other => Err(BridgeError::invalid(format!(
                "unknown terminal action {other:?}"
            ))),
        }
    }

    // --- read_result ---------------------------------------------------------

    pub fn tool_read_result(&self, arguments: &Map<String, Value>) -> BridgeResult<Value> {
        let result_id = used_string(arguments, "result_id")?;
        let stream = arguments
            .get("stream")
            .and_then(Value::as_str)
            .unwrap_or("stdout");
        let offset = arguments.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let limit = arguments
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(4096) as usize;
        let tail = arguments
            .get("tail")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let pattern = arguments.get("pattern").and_then(Value::as_str);
        if let Some(lines) = arguments.get("head_lines").and_then(Value::as_u64) {
            if tail || pattern.is_some() {
                return Err(BridgeError::invalid(
                    "head_lines cannot be combined with tail or pattern",
                ));
            }
            return self
                .store
                .read_head(&result_id, stream, offset, limit, lines as usize);
        }
        self.store
            .read(&result_id, stream, offset, limit, tail, pattern)
    }

    // --- discover ------------------------------------------------------------

    pub async fn tool_discover(&self, arguments: &Map<String, Value>) -> BridgeResult<Value> {
        self.tool_discover_with_detail(arguments, "full").await
    }

    pub(crate) async fn tool_discover_with_detail(
        &self,
        arguments: &Map<String, Value>,
        detail: &str,
    ) -> BridgeResult<Value> {
        let raw_query = arguments.get("query").and_then(Value::as_str).unwrap_or("");
        let query = raw_query.trim();
        let topic = arguments
            .get("topic")
            .and_then(Value::as_str)
            .unwrap_or("operations");
        let limit = arguments.get("limit").and_then(Value::as_u64).unwrap_or(10) as usize;
        let offset = arguments.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
        if !(1..=30).contains(&limit) {
            return Err(BridgeError::invalid("limit must be 1..30"));
        }
        if topic == "status" {
            return Ok(self.status().await);
        }
        let operation = arguments.get("operation").and_then(Value::as_str);
        let view = arguments
            .get("view")
            .and_then(Value::as_str)
            .unwrap_or("full");
        // Never compare a global catalog version or a token for another representation.
        let scope = json!([
            self.discovery_scope.to_string(),
            topic,
            raw_query,
            operation,
            view,
            offset,
            limit,
        ]);
        let if_none_match = arguments.get("if_none_match").and_then(Value::as_str);
        if topic == "assets" {
            let scope = json!([scope, detail]);
            return self
                .catalog
                .discover(query, offset, limit, &scope, if_none_match)
                .await;
        }
        let body = Self::discover_operations(query, operation, view, offset, limit)?;
        let etag = schemas::operation_discovery_etag(&scope, &body);
        if if_none_match == Some(etag.as_str()) {
            return Ok(json!({"unchanged": true}));
        }
        let mut body = body;
        body["catalog_version"] = Value::from(schemas::operation_catalog_version());
        body["etag"] = Value::from(etag);
        Ok(body)
    }

    fn discover_operations(
        query: &str,
        operation: Option<&str>,
        view: &str,
        offset: usize,
        limit: usize,
    ) -> BridgeResult<Value> {
        if let Some(name) = operation {
            let schema =
                schemas::exact_operation_schema(name, query).map_err(BridgeError::invalid)?;
            return if view == "signature" {
                Ok(json!({"name": name, "signature": schemas::operation_signature(name, &schema)}))
            } else {
                Ok(schema)
            };
        }
        if query.is_empty() && view != "signature" {
            let categories: Map<String, Value> = schemas::categories()
                .into_iter()
                .map(|(name, members)| (name.to_string(), json!(members.len())))
                .collect();
            return Ok(json!({
                "categories": categories,
                "hint": "Pass a category/search query, then operation for one full schema.",
            }));
        }
        let operations = schemas::operations();
        let lowered = query.to_lowercase();
        let names: Vec<String> = match schemas::categories()
            .into_iter()
            .find(|(name, _)| *name == lowered)
        {
            Some((_, members)) => members.iter().map(|name| name.to_string()).collect(),
            None => operations
                .iter()
                .filter(|(name, schema)| {
                    let description = schema
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_lowercase();
                    format!("{name} {description}")
                        .to_lowercase()
                        .contains(&lowered)
                })
                .map(|(name, _)| name.clone())
                .collect(),
        };
        let selected: Vec<Value> = names
            .iter()
            .skip(offset)
            .take(limit)
            .map(|name| {
                if view == "signature" {
                    return json!({
                        "name": name,
                        "signature": schemas::operation_signature(name, &operations[name]),
                    });
                }
                let description = operations
                    .get(name)
                    .and_then(|schema| schema.get("description"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                json!({
                    "name": name, "description": description,
                    "signature": schemas::operation_signature(name, &operations[name]),
                })
            })
            .collect();
        let next = offset.saturating_add(selected.len());
        Ok(json!({
            "operations": selected,
            "matched": names.len(),
            "next_offset": if next < names.len() { json!(next) } else { Value::Null },
        }))
    }

    // --- call ----------------------------------------------------------------

    pub async fn tool_job(
        self: &Arc<Self>,
        mut payload: Map<String, Value>,
    ) -> BridgeResult<Value> {
        let action = used_string(&payload, "action")?;
        payload.remove("action");
        let request_id = payload.remove("request_id");
        if action != "submit" && request_id.is_some() {
            return Err(BridgeError::invalid(
                "job request_id applies only to submit",
            ));
        }
        if action == "wait" && payload.contains_key("jobs") {
            return self.wait_job_handles(payload).await;
        }
        let operation = match action.as_str() {
            "submit" => {
                if request_id.as_ref().and_then(Value::as_str).is_none() {
                    return Err(BridgeError::invalid("job submit requires request_id"));
                }
                "jms_submit_job"
            }
            "wait" => "jms_job_wait",
            "logs" => "jms_job_logs",
            "status" => "jms_job_status",
            "cancel" => "jms_job_cancel",
            "list" => "jms_job_list",
            _ => return Err(BridgeError::invalid("unknown job action")),
        };
        if matches!(action.as_str(), "logs" | "cancel") {
            if let Some(target) = payload.remove("target") {
                payload.insert("host".into(), target);
            }
        }
        let mut call = Map::new();
        call.insert("operation".into(), json!(operation));
        call.insert("arguments".into(), Value::Object(payload));
        if let Some(request_id) = request_id {
            call.insert("request_id".into(), request_id);
        }
        self.tool_call_impl(call, Some(&action)).await
    }

    async fn wait_job_handles(&self, payload: Map<String, Value>) -> BridgeResult<Value> {
        if payload
            .keys()
            .any(|key| !matches!(key.as_str(), "jobs" | "timeout" | "interval" | "tail"))
        {
            return Err(BridgeError::invalid(
                "job wait takes jobs or targets/job_id, not both",
            ));
        }
        let input = payload
            .get("jobs")
            .ok_or_else(|| BridgeError::invalid("job wait requires jobs"))?;
        let timeout = payload
            .get("timeout")
            .and_then(Value::as_f64)
            .unwrap_or(50.0);
        let interval = payload
            .get("interval")
            .and_then(Value::as_f64)
            .unwrap_or(2.0);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs_f64(timeout);
        // Validate syntax and references before any inventory/gateway access. A
        // typed local result is only a source of handles, never authorization.
        let jobs = load_job_handles(&self.store, input)?;
        let handles = validate_job_handles(&jobs)?;
        let Some(inventory) = job_wait_inventory(deadline, self.inventory()).await? else {
            return stage_job_batch(&self.store, JobBatch::Wait, inventory_timeout_rows(jobs));
        };
        let pairs = inventory.resolve_job_targets(&handles)?;
        let (mut status, finished) = self.jobs.wait_until(&pairs, deadline, interval).await;
        if payload.get("tail").and_then(Value::as_bool) == Some(true) {
            self.jobs.failure_tails(&pairs, &mut status, deadline).await;
        }
        stage_job_batch(
            &self.store,
            JobBatch::Wait,
            project_job_wait(&jobs, &pairs, status, finished),
        )
    }

    pub async fn tool_call(self: &Arc<Self>, arguments: Map<String, Value>) -> BridgeResult<Value> {
        self.tool_call_impl(arguments, None).await
    }

    async fn tool_call_impl(
        self: &Arc<Self>,
        arguments: Map<String, Value>,
        direct_job_action: Option<&str>,
    ) -> BridgeResult<Value> {
        let operation = used_string(&arguments, "operation")?;
        let payload = match arguments.get("arguments") {
            Some(Value::Object(map)) => map.clone(),
            Some(Value::Null) | None => Map::new(),
            Some(_) => {
                return Err(BridgeError::invalid("arguments must be an object"));
            }
        };
        let request_id = arguments
            .get("request_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let schema = schemas::operations()
            .get(&operation)
            .ok_or_else(|| BridgeError::invalid("unknown operation; discover its schema first"))?;
        let input = schema
            .get("inputSchema")
            .ok_or_else(|| BridgeError::storage("operation schema is missing inputSchema"))?;
        crate::schema::validate(input, &Value::Object(payload.clone())).map_err(|error| {
            let message = format!(
                "Invalid operation arguments at {}; discover this operation for its schema",
                if error.path.is_empty() {
                    "<args>".to_string()
                } else {
                    error.path.clone()
                }
            );
            let prefix = if direct_job_action.is_some() {
                ""
            } else {
                "/arguments"
            };
            let mut validation = if operation == "jms_fs" {
                crate::schema::fs_diagnostic(error, &payload, prefix)
            } else {
                error.diagnostic(prefix)
            };
            if matches!(direct_job_action, Some("logs" | "cancel")) && validation["path"] == "/host"
            {
                validation["path"] = json!("/target");
                if validation["message"] == "missing required: host" {
                    validation["message"] = json!("missing required: target");
                }
            }
            BridgeError::invalid_arguments(message, validation)
        })?;
        if let Some(request_id) = request_id {
            if operation != "jms_submit_job" {
                return Err(BridgeError::invalid(
                    "call request_id currently supports only jms_submit_job",
                ));
            }
            let runtime = self.clone();
            let work = Value::Object(payload.clone());
            let work_for_task = work.clone();
            let operation_for_task = operation.clone();
            let mut value = self
                .journal
                .execute(&request_id, &operation, &work, move |sink| async move {
                    let sink: Arc<dyn crate::storage::journal::ProgressSink> = sink;
                    runtime.submit_jobs(&work_for_task, Some(sink)).await
                })
                .await?;
            // The receipt path returns the same kind of payload as a direct call, so it
            // gets the same budget: a many-target submission must not bypass staging.
            if let Some(map) = value.as_object_mut() {
                map.insert("request_id".into(), Value::from(request_id.clone()));
            }
            if direct_job_action == Some("submit") {
                return stage_job_batch(
                    &self.store,
                    JobBatch::Submit,
                    project_job_submission(value),
                );
            }
            return self.stage_operation_result(&operation_for_task, value);
        }
        let value = self.dispatch_operation(&operation, payload).await?;
        // Bounded response: a large operation payload is saved whole and the model gets
        // a summary plus a result id instead of the entire object in context.
        self.stage_operation_result(&operation, value)
    }

    /// Keep every `call` response inside a fixed budget; overflow is saved, not truncated.
    fn stage_operation_result(&self, operation: &str, value: Value) -> BridgeResult<Value> {
        crate::runtime::stage_if_large(&self.store, operation, value)
    }

    async fn dispatch_operation(
        self: &Arc<Self>,
        operation: &str,
        arguments: Map<String, Value>,
    ) -> BridgeResult<Value> {
        match operation {
            "jms_fs" => self
                .tool_fs(arguments)
                .await
                .map_err(|error| error.with_validation_prefix("/arguments")),
            "jms_accelerator_status" => {
                let targets = string_list(arguments.get("targets"));
                let timeout = arguments
                    .get("timeout")
                    .and_then(Value::as_u64)
                    .unwrap_or(90);
                self.inspector.inspect(&targets, timeout).await
            }
            "jms_exec" => self.legacy_exec(arguments).await,
            "jms_list_assets" => {
                let search = arguments
                    .get("search")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                // Page the inventory like every other listing: an unpaged dump of the
                // whole permitted inventory is both a token cost and a latency cost.
                let offset = arguments.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let limit = arguments
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(20)
                    .clamp(1, 100) as usize;
                let mut value = self.catalog.search(&search, offset, limit);
                let matched = value.get("matched").cloned().unwrap_or(json!(0));
                if let Some(map) = value.as_object_mut() {
                    map.insert("ok".into(), Value::Bool(true));
                    map.insert("count".into(), matched.clone());
                    let shown = map
                        .get("assets")
                        .and_then(Value::as_array)
                        .map(|rows| rows.len())
                        .unwrap_or(0);
                    map.insert("returned".into(), json!(shown));
                    map.insert(
                        "next_offset".into(),
                        if offset + shown < matched.as_u64().unwrap_or(0) as usize {
                            json!(offset + shown)
                        } else {
                            Value::Null
                        },
                    );
                }
                Ok(value)
            }
            "jms_asset_detail" => {
                let asset_id = used_string(&arguments, "asset_id")?;
                let asset = self
                    .catalog
                    .snapshot_assets()
                    .into_iter()
                    .find(|asset| {
                        asset.get("id").and_then(Value::as_str) == Some(asset_id.as_str())
                    })
                    .ok_or_else(|| {
                        BridgeError::invalid("asset is not in the permitted REST snapshot")
                    })?;
                let mut asset = asset;
                if let Some(map) = asset.as_object_mut() {
                    map.remove("login");
                }
                Ok(json!({"ok": true, "asset": asset}))
            }
            "jms_inventory_reload" => Ok(self.catalog.refresh().await),
            "session_list" => {
                // Both session kinds are listed with an explicit kind so a handle is
                // never passed to the wrong close path.
                let mut rows: Vec<Value> = self
                    .terminals
                    .sessions()
                    .await
                    .get("sessions")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|mut row| {
                        if let Some(map) = row.as_object_mut() {
                            map.insert("kind".into(), Value::from("terminal"));
                        }
                        row
                    })
                    .collect();
                for mut row in self.runner.sessions().await {
                    if let Some(map) = row.as_object_mut() {
                        map.insert("kind".into(), Value::from("shell"));
                    }
                    rows.push(row);
                }
                Ok(json!({"sessions": rows}))
            }
            "session_close" => {
                let target = used_string(&arguments, "target")?;
                let session_id = used_string(&arguments, "session_id")?;
                let kind = arguments
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let host = self.resolve_one(&target).await?;
                match kind.as_str() {
                    "terminal" => self.terminals.close(&session_id).await,
                    "shell" => self.runner.close_session(&host, &session_id, false).await,
                    "" => {
                        // Without a kind, close whichever registry owns the handle.
                        match self.terminals.close(&session_id).await {
                            Ok(value) => Ok(value),
                            Err(_) => self.runner.close_session(&host, &session_id, false).await,
                        }
                    }
                    other => Err(BridgeError::invalid(format!(
                        "session kind must be terminal or shell, got {other:?}"
                    ))),
                }
            }
            "request_status" => {
                let request_id = used_string(&arguments, "request_id")?;
                self.request_status(&request_id).await
            }
            "result_metadata" => self.tool_meta(&arguments).await,
            "script_guard_check" => {
                let script = used_string(&arguments, "script")?;
                Ok(guard::check(&script))
            }
            operation if operation.starts_with("terminal_") => {
                let action = operation.trim_start_matches("terminal_").to_string();
                self.tool_terminal(&action, arguments).await
            }
            "jms_submit_job" => {
                let value = Value::Object(arguments);
                self.submit_jobs(&value, None).await
            }
            "jms_job_status" => {
                let targets = string_list(arguments.get("targets"));
                let job_id = used_string(&arguments, "job_id")?;
                if let Some(error) = validate_job_id(&job_id) {
                    return Ok(json!({"ok": false, "error": error}));
                }
                let hosts = self.resolve_many(&targets).await?;
                let pairs: Vec<(Host, String)> = hosts
                    .into_iter()
                    .map(|host| (host, job_id.clone()))
                    .collect();
                let status = self.jobs.status_many(&pairs).await;
                let ok = status
                    .iter()
                    .all(|row| row.get("ok").and_then(Value::as_bool).unwrap_or(false));
                Ok(json!({"ok": ok, "status": status}))
            }
            "jms_job_logs" => {
                let target = used_string(&arguments, "host")?;
                let job_id = used_string(&arguments, "job_id")?;
                let offset = arguments.get("offset").and_then(Value::as_u64).unwrap_or(0);
                let max_bytes = arguments
                    .get("max_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(4096)
                    .clamp(1024, 16384);
                let tail = arguments
                    .get("tail")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if tail && arguments.contains_key("offset") {
                    return Err(BridgeError::invalid(
                        "job logs takes tail or offset, not both",
                    ));
                }
                let pattern = arguments.get("pattern").and_then(Value::as_str);
                let cursor = arguments.get("cursor").and_then(Value::as_str);
                if tail && pattern.is_some() {
                    return Err(BridgeError::invalid(
                        "job logs takes tail or pattern, not both",
                    ));
                }
                if tail && cursor.is_some() {
                    return Err(BridgeError::invalid(
                        "job logs takes tail or cursor, not both",
                    ));
                }
                if let Some(cursor) = cursor {
                    if cursor == crate::jobs::JOB_LOG_CURSOR_START && pattern.is_some() {
                        return Err(BridgeError::invalid(
                            "job log search starts with offset, not cursor=start",
                        ));
                    }
                    if cursor != crate::jobs::JOB_LOG_CURSOR_START
                        && arguments.contains_key("offset")
                    {
                        return Err(BridgeError::invalid(
                            "job log continuation cursor cannot be combined with offset",
                        ));
                    }
                }
                if pattern
                    .is_some_and(|p| p.is_empty() || p.len() > crate::jobs::JOB_LOG_PATTERN_BYTES)
                {
                    return Err(BridgeError::invalid(
                        "job log search pattern must be 1–1024 UTF-8 bytes",
                    ));
                }
                let host = self.resolve_one(&target).await?;
                if let Some(pattern) = pattern {
                    return self
                        .jobs
                        .search_logs(&host, &job_id, offset, max_bytes as usize, pattern, cursor)
                        .await;
                }
                self.jobs
                    .logs(&host, &job_id, offset, max_bytes, tail, cursor)
                    .await
            }
            "jms_job_cancel" => {
                let host = self.resolve_one(&used_string(&arguments, "host")?).await?;
                let job_id = used_string(&arguments, "job_id")?;
                let value = self.jobs.cancel(&host, &job_id).await?;
                // Keep the underlying verdict: a queued or failed cancellation must not
                // be reported as success just because the call reached the host.
                Ok(value)
            }
            "jms_job_wait" => {
                let targets = string_list(arguments.get("targets"));
                let job_id = used_string(&arguments, "job_id")?;
                if let Some(error) = validate_job_id(&job_id) {
                    return Ok(json!({"ok": false, "error": error}));
                }
                let timeout = arguments
                    .get("timeout")
                    .and_then(Value::as_f64)
                    .unwrap_or(50.0);
                let interval = arguments
                    .get("interval")
                    .and_then(Value::as_f64)
                    .unwrap_or(2.0);
                let hosts = self.resolve_many(&targets).await?;
                let pairs: Vec<(Host, String)> = hosts
                    .into_iter()
                    .map(|host| (host, job_id.clone()))
                    .collect();
                let (status, finished) = self.jobs.wait(&pairs, timeout, interval).await;
                Ok(json!({
                    "ok": finished,
                    "finished": finished,
                    "job_id": job_id,
                    "status": status,
                }))
            }
            "jms_job_list" => {
                let targets = string_list(arguments.get("targets"));
                let hosts = self.resolve_many(&targets).await?;
                let mut rows: Vec<Value> = Vec::new();
                for host in hosts {
                    match self.jobs.list_jobs(&host).await {
                        Ok(ids) => rows.push(json!({"host": host.name, "job_ids": ids})),
                        Err(error) => {
                            rows.push(json!({"host": host.name, "error": error.message()}))
                        }
                    }
                }
                let ok = !rows.is_empty() && rows.iter().all(|row| row.get("error").is_none());
                Ok(json!({"ok": ok, "hosts": rows}))
            }
            other => Err(BridgeError::invalid(format!(
                "unknown operation {other:?}; discover its schema first"
            ))),
        }
    }

    async fn submit_jobs(
        self: &Arc<Self>,
        arguments: &Value,
        progress: Option<Arc<dyn crate::storage::journal::ProgressSink>>,
    ) -> BridgeResult<Value> {
        let map = arguments
            .as_object()
            .ok_or_else(|| BridgeError::invalid("arguments must be an object"))?;
        let command = used_string(map, "command")?;
        let allow_dangerous = map
            .get("allow_dangerous")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if guard::is_dangerous(&command) && !allow_dangerous {
            return Ok(json!({
                "ok": false,
                "error": "command matched the safety denylist; pass allow_dangerous=true to override",
                "command": command,
            }));
        }
        let targets = string_list(map.get("targets"));
        let hosts = self.resolve_many(&targets).await?;
        // Independent targets are launched side by side: each one pays its own channel
        // setup and acknowledgement wait, which used to add up linearly.
        const MAX_IN_FLIGHT: usize = 4;
        let limit = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        let mut set = tokio::task::JoinSet::new();
        let command: Arc<str> = Arc::from(command.as_str());
        for (index, host) in hosts.into_iter().enumerate() {
            let runtime = self.clone();
            let command = command.clone();
            let progress = progress.clone();
            let permit = limit.clone();
            set.spawn(async move {
                let _permit = permit.acquire_owned().await;
                let name = host.name.clone();
                let asset_id = host.asset_id.clone();
                let submitted = runtime
                    .jobs
                    .submit(&host, command.as_ref(), progress.as_deref())
                    .await;
                (index, name, asset_id, submitted)
            });
        }
        let mut launched: Vec<(usize, Value)> = Vec::new();
        let mut all_launched = true;
        let mut any_unknown = false;
        while let Some(joined) = set.join_next().await {
            let (index, name, asset_id, submitted) = match joined {
                Ok(entry) => entry,
                Err(error) => {
                    all_launched = false;
                    launched.push((
                        usize::MAX,
                        json!({"host": "<cancelled>", "job_id": Value::Null,
                               "launch_state": "unknown", "launched": false,
                               "completion_unknown": true,
                               "error": format!("submission task failed: {error}")}),
                    ));
                    continue;
                }
            };
            let mut row = match submitted {
                Ok((handle, outcome)) => {
                    all_launched &= handle.state == crate::jobs::LaunchState::Acknowledged;
                    any_unknown |= handle.state == crate::jobs::LaunchState::Unknown;
                    job_row(&handle, &outcome)
                }
                Err(error) => {
                    // The receipt could not be persisted, so nothing was transmitted.
                    all_launched = false;
                    json!({
                        "host": name,
                        "job_id": Value::Null,
                        "launch_state": "rejected",
                        "launched": false,
                        "execution_state": "not_started",
                        "completion_unknown": false,
                        "error": error.message(),
                    })
                }
            };
            if let Some(asset_id) = asset_id {
                row["asset_id"] = json!(asset_id);
            }
            launched.push((index, row));
        }
        launched.sort_by_key(|(index, _)| *index);
        let rows: Vec<Value> = launched.into_iter().map(|(_, row)| row).collect();
        let mut value = json!({"ok": all_launched, "jobs": rows});
        if let Some(map) = value.as_object_mut() {
            if any_unknown {
                map.insert("completion_unknown".into(), Value::Bool(true));
            }
        }
        Ok(value)
    }

    async fn legacy_exec(&self, arguments: Map<String, Value>) -> BridgeResult<Value> {
        let command = used_string(&arguments, "command")?;
        let allow_dangerous = arguments
            .get("allow_dangerous")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if guard::is_dangerous(&command) && !allow_dangerous {
            return Ok(json!({
                "ok": false,
                "error": "command matched the safety denylist; pass allow_dangerous=true to override",
                "command": command,
            }));
        }
        let targets = string_list(arguments.get("targets"));
        let timeout = arguments
            .get("timeout")
            .and_then(Value::as_f64)
            .unwrap_or(60.0);
        let hosts = self.resolve_many(&targets).await?;
        let mut outcomes = Vec::new();
        for host in hosts {
            outcomes.push(
                self.runner
                    .exec_on(&host, &command, timeout, true, true, true)
                    .await?,
            );
        }
        let rows = crate::filesystem::exec_rows(&self.store, &outcomes, 4096);
        let ok = rows
            .iter()
            .all(|row| row.get("ok").and_then(Value::as_bool).unwrap_or(false));
        Ok(json!({"ok": ok, "results": rows}))
    }

    // --- request receipts ----------------------------------------------------

    pub async fn request_status(&self, request_id: &str) -> BridgeResult<Value> {
        let mut receipt = self.journal.status(request_id, false)?;
        if let Some(rows) = receipt
            .get("execution_results")
            .and_then(Value::as_array)
            .cloned()
        {
            let mut enriched: Vec<Value> = Vec::new();
            for row in rows {
                let mut row = row;
                let result_id = row
                    .get("result_id")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if let Some(result_id) = result_id {
                    if let Some(map) = row.as_object_mut() {
                        map.insert(
                            "result_status".into(),
                            self.project_result_status(&result_id),
                        );
                    }
                }
                enriched.push(row);
            }
            if let Some(map) = receipt.as_object_mut() {
                map.insert("execution_results".into(), Value::Array(enriched));
            }
        }
        // The response of the original call recorded one result id before the work
        // finished (a terminal command, for instance). Project its *current* state so
        // `request_status` never keeps reporting the frozen "queued"/"running" value.
        if let Some(result_id) = receipt
            .get("result_id")
            .and_then(Value::as_str)
            .map(str::to_string)
        {
            let status = self.project_result_status(&result_id);
            if let Some(map) = receipt.as_object_mut() {
                map.insert("result_status".into(), status);
            }
        }
        Ok(receipt)
    }

    /// Current state of one saved result, as reported inside a receipt.
    fn project_result_status(&self, result_id: &str) -> Value {
        match self.store.metadata(result_id) {
            Ok(meta) => {
                let mut status = Map::new();
                for key in [
                    "status",
                    "ok",
                    "exit_code",
                    "executed",
                    "execution_state",
                    "completion_unknown",
                    "timed_out",
                    "queue_timed_out",
                    "reason",
                    "retryable",
                    "queue",
                    "failure_stage",
                    "error",
                    "startup_retry_result_id",
                    "connection_recovery",
                    "finished_at",
                ] {
                    if let Some(value) = meta.get(key) {
                        status.insert(key.to_string(), value.clone());
                    }
                }
                Value::Object(status)
            }
            Err(_) => json!({"status": "unavailable"}),
        }
    }

    // --- meta ----------------------------------------------------------------

    pub async fn tool_meta(&self, arguments: &Map<String, Value>) -> BridgeResult<Value> {
        let reference = arguments
            .get("ref")
            .and_then(Value::as_str)
            .unwrap_or("service");
        let section = arguments
            .get("section")
            .and_then(Value::as_str)
            .unwrap_or("summary");
        if !matches!(
            section,
            "summary" | "all" | "timing" | "transport" | "progress" | "request" | "policy"
        ) {
            return Err(BridgeError::invalid("unknown metadata section"));
        }
        if reference == "service" {
            if section == "summary" {
                let mut value = json!({
                    "version": crate::version(),
                    "response_detail": "compact",
                    "active_requests": self.journal.active_tasks(),
                });
                if self.catalog.status()["stale"].as_bool().unwrap_or(false) {
                    value["inventory_stale"] = Value::Bool(true);
                }
                return Ok(value);
            }
            let status = self.status().await;
            let pick = |keys: &[&str]| -> Value {
                let mut out = Map::new();
                for key in keys {
                    if let Some(value) = status.get(*key) {
                        out.insert((*key).to_string(), value.clone());
                    }
                }
                Value::Object(out)
            };
            return Ok(match section {
                "transport" => pick(&["ssh_connections", "persistent_shells", "execution"]),
                "policy" => pick(&["result_retention", "inventory", "execution", "login"]),
                _ => status,
            });
        }
        if let Some(request_id) = reference.strip_prefix("request:") {
            let value = self.request_status(request_id).await?;
            let mut out = Map::new();
            for key in [
                "request_id",
                "operation",
                "request_state",
                "completion_unknown",
                "accepted_at",
                "finished_at",
                "duplicate",
                "execution_replayed",
                "execution_results",
                "submission_receipts",
                "error",
            ] {
                if let Some(item) = value.get(key) {
                    out.insert(key.to_string(), item.clone());
                }
            }
            return Ok(Value::Object(out));
        }
        let result_id = reference.strip_prefix("result:").unwrap_or(reference);
        let meta = self.store.metadata(result_id)?;
        let keys = meta_section_keys(section);
        if keys.is_empty() {
            return Ok(Value::Object(meta));
        }
        let mut out = Map::new();
        for key in keys {
            if let Some(value) = meta.get(*key) {
                out.insert((*key).to_string(), value.clone());
            }
        }
        Ok(Value::Object(out))
    }
}

pub struct PageOptions {
    pub wait_ms: u64,
    wait_for_completion: bool,
    pub max_bytes: usize,
    pub cursor: Option<Value>,
}

impl PageOptions {
    fn from(arguments: &Map<String, Value>) -> Self {
        let wait_ms = arguments
            .get("wait_ms")
            .and_then(Value::as_u64)
            .unwrap_or(crate::terminal::DEFAULT_TERMINAL_WAIT_MS)
            .min(30_000);
        let max_bytes = arguments
            .get("max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(4096)
            .clamp(1, 16_384) as usize;
        Self {
            wait_ms,
            wait_for_completion: arguments.get("wait_for").and_then(Value::as_str)
                == Some("completed"),
            max_bytes,
            cursor: arguments.get("cursor").cloned(),
        }
    }

    fn read_wait(&self) -> ReadWait {
        if self.wait_for_completion {
            ReadWait::Completed(self.wait_ms)
        } else {
            ReadWait::Output(self.wait_ms)
        }
    }
}

pub fn used_string(map: &Map<String, Value>, key: &str) -> BridgeResult<String> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| BridgeError::invalid(format!("missing required: {key}")))
}

pub fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// A per-target row built from the evidence the execution layer captured.
///
/// The classification comes from the failure itself: a local write after a successful
/// run keeps `completed`/`unknown` and its exit code, while only a proven pre-send
/// failure is reported as `not_started`.
fn failure_row(host: &str, failure: &crate::execution::ExecFailure) -> Map<String, Value> {
    let mut row = Map::new();
    row.insert("host".into(), Value::from(host));
    for key in [
        "result_id",
        "exit_code",
        "executed",
        "execution_state",
        "completion_unknown",
        "timed_out",
        "queue_timed_out",
        "failure_stage",
        "session_state",
        "warning",
    ] {
        if let Some(value) = failure.meta.get(key) {
            row.insert(key.to_string(), value.clone());
        }
    }
    row.insert("ok".into(), Value::Bool(false));
    if !row.contains_key("executed") {
        row.insert("executed".into(), Value::Null);
    }
    if !row.contains_key("execution_state") {
        // No evidence at all: unknown is the only safe answer.
        row.insert("execution_state".into(), Value::from("unknown"));
        row.insert("completion_unknown".into(), Value::Bool(true));
    }
    row.insert("error".into(), Value::from(failure.error.message()));
    if failure.meta.get("local_error") == Some(&Value::Bool(true)) {
        row.insert("local_error".into(), Value::Bool(true));
    }
    row
}

/// A row for work whose outcome is not known (panicked task, cancelled join).
fn unknown_row(host: &str, message: &str) -> Map<String, Value> {
    json!({
        "host": host,
        "ok": false,
        "executed": Value::Null,
        "execution_state": "unknown",
        "completion_unknown": true,
        "error": message,
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
}

#[derive(Clone, Copy)]
enum JobBatch {
    Submit,
    Wait,
}

impl JobBatch {
    fn scope(self) -> (&'static str, &'static str) {
        match self {
            Self::Submit => ("jms_submit_job", "jobs"),
            Self::Wait => ("jms_job_wait", "pending"),
        }
    }
}

const JOB_BATCH_RESULT: &str = "job_batch";

/// Mark where each identifier is usable. Inline job handles are data, not
/// authorization; the receiving bridge still resolves the permitted asset.
fn mark_job_recovery(value: &mut Value, section: &str) {
    if value.get("request_id").is_some_and(Value::is_string) {
        value["request_id_scope"] = json!("bridge_local");
    }
    if value.get("result_id").is_some_and(Value::is_string) {
        value["result_id_scope"] = json!("bridge_local");
    }
    if let Some(handles) = value.get(section).and_then(Value::as_array) {
        if handles.is_empty() {
            return;
        }
        let next = if handles.len() == 1 {
            validate_job_handles(handles)
                .ok()
                .and_then(|mut pairs| pairs.pop())
                .map(|(target, job_id)| {
                    json!({"tool":"call","arguments":{
                        "operation":"jms_job_status",
                        "arguments":{"targets":[target],"job_id":job_id}
                    }})
                })
        } else {
            None
        };
        let key = format!("{section}_scope");
        value[key.as_str()] = json!("remote_job");
        if let Some(action) = next {
            value["next_action"] = action;
        }
    } else if value.get(section).is_some_and(Value::is_object) {
        let key = format!("{section}_scope");
        value[key.as_str()] = json!("bridge_local");
    }
}

/// Stage bulky diagnostic rows first. Pass the inline handles (or a typed
/// continuation reference when the handles alone are too large) directly to wait.
fn stage_job_batch(store: &ResultStore, scope: JobBatch, mut value: Value) -> BridgeResult<Value> {
    let (operation, section) = scope.scope();
    mark_job_recovery(&mut value, section);
    let bytes = serde_json::to_vec(&value)?;
    if bytes.len() <= OPERATION_BUDGET {
        return Ok(value);
    }
    // Optional diagnostics must not turn an inline status response into a
    // staged one. Never strip unrelated fields or change the primary verdicts.
    if matches!(scope, JobBatch::Wait)
        && value["status"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row.get("failure_tail").is_some()))
    {
        let mut status_only = value.clone();
        if let Some(rows) = status_only["status"].as_array_mut() {
            for row in rows.iter_mut().filter_map(Value::as_object_mut) {
                row.remove("failure_tail");
            }
        }
        if serde_json::to_vec(&status_only)?.len() <= OPERATION_BUDGET {
            return Ok(status_only);
        }
    }
    let metadata = json!({"kind":JOB_BATCH_RESULT,"operation":operation,
                          "handle_section":section,"bytes":bytes.len()})
    .as_object()
    .expect("object")
    .clone();
    let result_id = store.save_serialized(&value, &bytes, metadata)?;
    let mut result = json!({
        "staged": true,
        "result_id": result_id,
        "operation": operation,
        "bytes": bytes.len(),
        "note": "Full diagnostics: read_result with stream='result'."
    });
    for field in [
        "ok",
        "finished",
        "request_id",
        "request_state",
        "duplicate",
        "execution_replayed",
        "completion_unknown",
        "watch_timeout",
        "inventory_timed_out",
    ] {
        if let Some(item) = value.get(field) {
            result[field] = item.clone();
        }
    }
    if let Some(handles) = value.get(section) {
        result[section] = handles.clone();
    }
    mark_job_recovery(&mut result, section);
    if serde_json::to_vec(&result)?.len() > OPERATION_BUDGET {
        // Prefer the portable handle over duplicate convenience arguments.
        result
            .as_object_mut()
            .expect("staged object")
            .remove("next_action");
        if serde_json::to_vec(&result)?.len() > OPERATION_BUDGET {
            result[section] = json!({"ref": result_id});
            mark_job_recovery(&mut result, section);
        }
    }
    Ok(result)
}

fn load_job_handles(store: &ResultStore, input: &Value) -> BridgeResult<Vec<Value>> {
    if let Some(handles) = input.as_array() {
        return Ok(handles.clone());
    }
    crate::schema::validate(&schemas::job_batch_ref_schema(), input).map_err(|_| {
        BridgeError::invalid("jobs must be a handle array or a job continuation ref")
    })?;
    let id = input["ref"].as_str().expect("validated reference");
    let meta = store.metadata(id)?;
    let scope = (
        meta.get("operation").and_then(Value::as_str),
        meta.get("handle_section").and_then(Value::as_str),
    );
    let section = match scope {
        (Some("jms_submit_job"), Some("jobs")) => "jobs",
        (Some("jms_job_wait"), Some("pending")) => "pending",
        _ => {
            return Err(BridgeError::invalid(
                "result is not a reusable job continuation",
            ))
        }
    };
    if meta.get("kind").and_then(Value::as_str) != Some(JOB_BATCH_RESULT)
        || meta.get("status").and_then(Value::as_str) != Some("complete")
    {
        return Err(BridgeError::invalid(
            "result is not a reusable job continuation",
        ));
    }
    let value: Value = serde_json::from_slice(&std::fs::read(store.path(id, "result")?)?)?;
    value
        .get(section)
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| BridgeError::invalid("job continuation has no saved handle array"))
}

fn validate_job_handles(jobs: &[Value]) -> BridgeResult<Vec<(String, String)>> {
    if jobs.is_empty() {
        return Err(BridgeError::invalid("job wait requires nonempty handles"));
    }
    jobs.iter()
        .map(|handle| {
            let fields = handle
                .as_object()
                .filter(|fields| fields.len() == 2)
                .ok_or_else(|| BridgeError::invalid("job handle must contain target and job_id"))?;
            let target = used_string(fields, "target")?;
            let id = used_string(fields, "job_id")?;
            if let Some(error) = validate_job_id(&id) {
                return Err(BridgeError::invalid(error));
            }
            if target.trim().is_empty()
                || target.eq_ignore_ascii_case("all")
                || target.contains(['*', '?', '[', ']'])
            {
                return Err(BridgeError::invalid(
                    "job handles require an exact permitted target",
                ));
            }
            Ok((target, id))
        })
        .collect()
}

async fn job_wait_inventory(
    deadline: tokio::time::Instant,
    inventory: impl std::future::Future<Output = BridgeResult<crate::inventory::Inventory>>,
) -> BridgeResult<Option<crate::inventory::Inventory>> {
    if tokio::time::Instant::now() >= deadline {
        return Ok(None);
    }
    match tokio::time::timeout_at(deadline, inventory).await {
        Ok(Err(error)) => Err(error),
        Ok(Ok(inventory)) if tokio::time::Instant::now() < deadline => Ok(Some(inventory)),
        Ok(Ok(_)) | Err(_) => Ok(None),
    }
}

fn inventory_timeout_rows(jobs: Vec<Value>) -> Value {
    let status: Vec<_> = jobs
        .iter()
        .map(|handle| {
            json!({
                "target":handle["target"], "job_id":handle["job_id"],
                "status":"unknown", "ok":false, "watch_timeout":true, "probed":false,
                "reason":"inventory_timeout",
            })
        })
        .collect();
    json!({"ok":false,"finished":false,"watch_timeout":true,"inventory_timed_out":true,
           "status":status,"pending":jobs})
}

fn project_job_wait(
    jobs: &[Value],
    pairs: &[(Host, String)],
    mut status: Vec<Value>,
    finished: bool,
) -> Value {
    let mut pending = Vec::new();
    for ((row, handle), (host, _)) in status.iter_mut().zip(jobs).zip(pairs) {
        let known = crate::jobs::is_terminal_status(row);
        row["target"] = handle["target"].clone();
        row["host"] = json!(host.name);
        row["job_id"] = handle["job_id"].clone();
        if !known {
            pending.push(handle.clone());
        }
    }
    json!({"ok":finished,"finished":finished,"status":status,"pending":pending})
}

/// Present directly reusable handles without changing the durable legacy response.
fn project_job_submission(mut value: Value) -> Value {
    let Some(map) = value.as_object_mut() else {
        return value;
    };
    let running = map.get("request_state").and_then(Value::as_str) == Some("running");
    let rows = map
        .remove("jobs")
        .and_then(|value| value.as_array().cloned());
    let receipts = map
        .remove("submission_receipts")
        .and_then(|value| value.as_array().cloned());
    let mut submissions = rows.unwrap_or_default();
    if submissions.is_empty() {
        submissions = receipts.unwrap_or_default();
    }
    let mut jobs = Vec::new();
    for row in &mut submissions {
        let Some(row) = row.as_object_mut() else {
            continue;
        };
        let Some(target) = row
            .get("asset_id")
            .and_then(Value::as_str)
            .or_else(|| row.get("host").and_then(Value::as_str))
            .map(str::to_string)
        else {
            continue;
        };
        row.insert("target".into(), json!(target));
        let confirmed_or_unknown = match row.get("launch_state").and_then(Value::as_str) {
            Some("acknowledged" | "unknown") => true,
            Some(_) => false,
            None => {
                // A live request can still launch this prepared ID. Do not offer an
                // immediately watchable handle that might falsely report missing.
                row.insert(
                    "launch_state".into(),
                    json!(if running { "pending" } else { "unknown" }),
                );
                !running
            }
        };
        let Some(id) = row.get("job_id").and_then(Value::as_str) else {
            continue;
        };
        if confirmed_or_unknown && validate_job_id(id).is_none() {
            jobs.push(json!({"target":target,"job_id":id}));
        }
    }
    map.remove("execution_results");
    map.insert("jobs".into(), json!(jobs));
    map.insert("submissions".into(), json!(submissions));
    value
}

/// One job row: the id is always reported, `launched` only when the launcher said so.
fn job_row(handle: &crate::jobs::JobHandle, outcome: &crate::execution::ExecOutcome) -> Value {
    let acknowledged = handle.state == crate::jobs::LaunchState::Acknowledged;
    let mut row = Map::new();
    row.insert("host".into(), Value::from(handle.host.clone()));
    // The id stays visible for every outcome: it is how a lost reply is reconciled.
    row.insert("job_id".into(), Value::from(handle.job_id.clone()));
    row.insert("session".into(), Value::from(handle.session.clone()));
    row.insert("launcher".into(), Value::from(handle.launcher.clone()));
    row.insert("launch_state".into(), Value::from(handle.state.as_str()));
    row.insert("launched".into(), Value::Bool(acknowledged));
    row.insert("result_id".into(), Value::from(outcome.result_id.clone()));
    if !acknowledged {
        // Keep the reason: the launcher's own message is the useful part.
        row.insert(
            "stderr".into(),
            Value::from(outcome.stderr.trim().chars().take(400).collect::<String>()),
        );
        row.insert(
            "execution_state".into(),
            outcome
                .meta
                .get("execution_state")
                .cloned()
                .unwrap_or(Value::from("unknown")),
        );
        row.insert(
            "completion_unknown".into(),
            Value::Bool(handle.state == crate::jobs::LaunchState::Unknown),
        );
    }
    for (key, value) in queue_rejection(&outcome.meta) {
        row.insert(key, value);
    }
    Value::Object(row)
}

const OPERATION_BUDGET: usize = 8 * 1024;

/// Save an oversized operation payload and return a bounded summary of it.
pub fn stage_if_large(
    store: &crate::storage::results::ResultStore,
    operation: &str,
    value: Value,
) -> BridgeResult<Value> {
    let budget = OPERATION_BUDGET;
    // Serialize once: the same bytes decide the budget, feed the preview and get saved.
    let bytes = serde_json::to_vec(&value)?;
    if bytes.len() <= budget {
        return Ok(value);
    }
    // `serde_json` output is UTF-8; borrow it instead of copying the whole payload.
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| BridgeError::storage("serialized payload is not valid UTF-8"))?;
    let mut metadata = Map::new();
    metadata.insert("kind".into(), Value::from("operation"));
    metadata.insert("operation".into(), Value::from(operation));
    metadata.insert("bytes".into(), json!(bytes.len()));
    let result_id = store.save_serialized(&value, &bytes, metadata)?;
    let mut summary = Map::new();
    summary.insert(
        "ok".into(),
        value.get("ok").cloned().unwrap_or(Value::Bool(true)),
    );
    summary.insert("staged".into(), Value::Bool(true));
    summary.insert("operation".into(), Value::from(operation));
    summary.insert("result_id".into(), Value::from(result_id.clone()));
    summary.insert("bytes".into(), json!(bytes.len()));

    // Business-level shape the caller usually needs, without the bulk.
    // Short state fields stay on top: a staged reply must still tell the caller whether
    // the work finished and how to continue.
    for key in [
        "request_id",
        "request_state",
        "execution_state",
        "completion_unknown",
        "duplicate",
        "execution_replayed",
        "failure_stage",
        "host",
        "job_id",
        "launch_state",
        "launched",
        "count",
        "matched",
        "returned",
        "next_offset",
        "next_cursor",
        "eof",
        "reset",
        "finished",
        "status",
    ] {
        if let Some(item) = value.get(key) {
            if item.to_string().len() <= 512 {
                summary.insert(key.to_string(), item.clone());
            }
        }
    }
    summary.insert(
        "preview".into(),
        Value::from(text.chars().take(1024).collect::<String>()),
    );
    summary.insert(
        "note".into(),
        Value::from(format!(
            "response exceeded {budget} bytes; full payload saved as {result_id} (read_result with stream='result')"
        )),
    );
    Ok(Value::Object(summary))
}

/// Canonical `run` arguments used for the request fingerprint.
///
/// Mirrors the Python bridge: every option is present, unset optionals are `null`,
/// and the documented defaults are filled in. A `script_path` call is normalized to
/// the script text it resolved to, so both implementations produce one identity per
/// logical request.
fn normalize_run_arguments(arguments: &Map<String, Value>) -> Value {
    let optional = |key: &str| arguments.get(key).cloned().unwrap_or(Value::Null);
    let mut out = Map::new();
    out.insert("targets".into(), optional("targets"));
    out.insert(
        "script".into(),
        arguments.get("script").cloned().unwrap_or(Value::Null),
    );
    out.insert("cwd".into(), optional("cwd"));
    out.insert("env".into(), optional("env"));
    out.insert("container".into(), optional("container"));
    out.insert("image".into(), optional("image"));
    out.insert("docker_args".into(), optional("docker_args"));
    out.insert("session_id".into(), optional("session_id"));
    out.insert(
        "timeout".into(),
        arguments
            .get("timeout")
            .cloned()
            .unwrap_or_else(|| json!(60)),
    );
    out.insert(
        "max_output_bytes".into(),
        arguments
            .get("max_output_bytes")
            .cloned()
            .unwrap_or_else(|| json!(4096)),
    );
    out.insert(
        "allow_dangerous".into(),
        arguments
            .get("allow_dangerous")
            .cloned()
            .unwrap_or_else(|| json!(false)),
    );
    Value::Object(out)
}

fn string_pairs(value: Option<&Value>) -> Vec<(String, String)> {
    value
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|text| (key.clone(), text.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Description used by both the advertised schema and diagnostics.
pub fn dangerous_flag_description() -> &'static str {
    DANGEROUS_FLAG_DESCRIPTION
}

fn meta_section_keys(section: &str) -> &'static [&'static str] {
    match section {
        "summary" => &[
            "result_id",
            "kind",
            "operation",
            "host",
            "status",
            "ok",
            "exit_code",
            "executed",
            "execution_state",
            "completion_unknown",
            "failure_stage",
            "error",
            "producer",
            "expires_at",
        ],
        "timing" => &[
            "result_id",
            "host",
            "created_at",
            "finished_at",
            "elapsed_seconds",
            "timing",
            "connection_timing",
        ],
        "progress" => &[
            "result_id",
            "kind",
            "operation",
            "host",
            "status",
            // The verdict travels with the numbers: a partial percentage alone does
            // not say whether the transfer succeeded, failed or timed out.
            "ok",
            "exit_code",
            "completion_unknown",
            "execution_state",
            "bytes_done",
            "total_bytes",
            "progress_pct",
            "progress_source",
            "protocol_bytes",
            "protocol_rate_bps",
            "rate_bps",
            "eta_seconds",
            "created_at",
            "finished_at",
            "expires_at",
        ],
        "transport" => &[
            "result_id",
            "host",
            "asset_id",
            "container",
            "image",
            "lane",
            "session_id",
            "connection_state",
            "session_state",
            "reconnected",
            "executed",
            "execution_state",
            "completion_unknown",
            "timed_out",
            "queue_timed_out",
            "failure_stage",
            "reason",
            "retryable",
            "queue",
            "startup_retry_result_id",
            "connection_recovery",
            "warning",
        ],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job_test_store() -> (tempfile::TempDir, ResultStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ResultStore::new(dir.path().to_path_buf(), 3600.0, 3600.0).unwrap();
        (dir, store)
    }

    fn job_test_handles(count: u32) -> Vec<Value> {
        (0..count)
            .map(|i| json!({"target":format!("asset-{i:012}"),"job_id":format!("{i:08x}")}))
            .collect()
    }

    #[test]
    fn stage_keeps_large_submit_handles_inline_when_only_diagnostics_overflow() {
        let (_dir, store) = job_test_store();
        let handles = job_test_handles(30);
        let submissions: Vec<_> = handles.iter().map(|h| json!({
            "host": h["target"], "job_id":h["job_id"], "launch_state":"acknowledged", "diagnostic":"x".repeat(500),
        })).collect();
        let raw =
            json!({"ok":true,"request_id":"original","jobs":handles,"submissions":submissions});
        let staged = stage_job_batch(&store, JobBatch::Submit, raw.clone()).unwrap();
        assert_eq!(staged["staged"], true);
        assert_eq!(staged["request_id"], "original");
        assert_eq!(staged["jobs"], raw["jobs"]);
        assert!(staged.get("submissions").is_none());
        assert!(staged.to_string().len() <= OPERATION_BUDGET);
        let full: Value = serde_json::from_slice(
            &std::fs::read(
                store
                    .path(staged["result_id"].as_str().unwrap(), "result")
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut raw = raw;
        mark_job_recovery(&mut raw, "jobs");
        assert_eq!(full, raw);
    }

    #[test]
    fn optional_tails_cannot_push_primary_wait_rows_into_staging() {
        let (_dir, store) = job_test_store();
        let original = json!({
            "ok":true,"finished":true,"pending":[],
            "status":[{"status":"failed","exit_code":7,"note":"x".repeat(OPERATION_BUDGET - 200)}]
        });
        let mut annotated = original.clone();
        annotated["status"][0]["failure_tail"] = json!({"offset":10,"next_offset":266,
            "text":"x".repeat(256)});
        let retained = stage_job_batch(&store, JobBatch::Wait, annotated).unwrap();
        assert_eq!(retained, original);
    }

    #[test]
    fn portable_job_recovery_emits_a_read_only_valid_action_without_local_ids() {
        let (_dir, store) = job_test_store();
        let response = stage_job_batch(
            &store,
            JobBatch::Submit,
            json!({"ok":true,"request_id":"bridge-a-local-id","jobs":job_test_handles(1)}),
        )
        .unwrap();
        assert_eq!(response["jobs_scope"], "remote_job");
        assert_eq!(response["request_id_scope"], "bridge_local");
        let action = &response["next_action"];
        assert_eq!(action["tool"], "call");
        let invocation = &action["arguments"];
        let operation = invocation["operation"].as_str().unwrap();
        assert_eq!(operation, "jms_job_status");
        let operations = schemas::operations();
        let spec = &operations[operation];
        assert_eq!(spec["annotations"]["readOnlyHint"], true);
        crate::schema::validate(&spec["inputSchema"], &invocation["arguments"]).unwrap();
        assert_eq!(
            invocation["arguments"],
            json!({"targets":["asset-000000000000"],"job_id":"00000000"})
        );
        let (_other_dir, other_store) = job_test_store();
        let inline = load_job_handles(&other_store, &response["jobs"]).unwrap();
        assert_eq!(
            validate_job_handles(&inline).unwrap(),
            vec![("asset-000000000000".into(), "00000000".into())]
        );
    }

    #[test]
    fn no_remote_action_without_an_exact_job_handle() {
        let (_dir, store) = job_test_store();
        for jobs in [json!([]), json!([{"target":"all","job_id":"abcd1234"}])] {
            let response = stage_job_batch(
                &store,
                JobBatch::Submit,
                json!({"completion_unknown":true,"jobs":jobs}),
            )
            .unwrap();
            assert!(response.get("next_action").is_none());
        }
    }

    #[test]
    fn portable_handle_is_retained_before_the_optional_action() {
        let (_dir, store) = job_test_store();
        let handles = json!([{"target":"x".repeat(4500),"job_id":"abcd1234"}]);
        let response = stage_job_batch(
            &store,
            JobBatch::Submit,
            json!({"jobs":handles,"submissions":["x".repeat(9000)]}),
        )
        .unwrap();
        assert_eq!(response["staged"], true);
        assert_eq!(response["jobs"], handles);
        assert_eq!(response["jobs_scope"], "remote_job");
        assert_eq!(response["result_id_scope"], "bridge_local");
        assert!(response.get("next_action").is_none());
    }

    #[test]
    fn stage_keeps_single_pending_handle_when_many_rows_finish() {
        let (_dir, store) = job_test_store();
        let handles = job_test_handles(200);
        let pending = json!([handles.last().unwrap()]);
        let status: Vec<_> = handles
            .iter()
            .map(|h| {
                json!({
                    "target":h["target"],"job_id":h["job_id"],"status":"done","exit_code":"0",
                })
            })
            .collect();
        let staged = stage_job_batch(
            &store,
            JobBatch::Wait,
            json!({
                "ok":false,"finished":false,"pending":pending,"status":status,
            }),
        )
        .unwrap();
        assert_eq!(staged["staged"], true);
        assert_eq!(staged["pending"], pending);
        assert_eq!(staged["finished"], false);
    }

    #[test]
    fn oversized_handles_roundtrip_only_through_typed_job_continuations() {
        let (_dir, store) = job_test_store();
        let handles = job_test_handles(220);
        for scope in [JobBatch::Submit, JobBatch::Wait] {
            let (operation, field) = scope.scope();
            let mut raw = json!({"ok":true});
            raw[field] = json!(handles);
            let staged = stage_job_batch(&store, scope, raw.clone()).unwrap();
            assert!(staged.to_string().len() <= OPERATION_BUDGET);
            assert_eq!(staged[field]["ref"], staged["result_id"]);
            assert_eq!(staged[format!("{field}_scope").as_str()], "bridge_local");
            assert!(staged.get("next_action").is_none());
            let restored = load_job_handles(&store, &staged[field]).unwrap();
            assert_eq!(restored, handles);
            assert!(validate_job_handles(&restored).is_ok());
            let reconstructed: Value = json!({"action":"wait","jobs":staged[field]});
            let schema = schemas::full_specs()
                .into_iter()
                .find(|s| s.name == "job")
                .unwrap();
            assert!(crate::schema::validate(&schema.input_schema, &reconstructed).is_ok());
            let arbitrary = stage_if_large(&store, operation, raw).unwrap();
            assert!(load_job_handles(&store, &json!({"ref":arbitrary["result_id"]})).is_err());
        }
        assert!(validate_job_handles(&[json!({"target":"*","job_id":"aabbccdd"})]).is_err());
        assert!(validate_job_handles(&[json!({"target":"asset","job_id":"bad"})]).is_err());
    }

    #[tokio::test]
    async fn inventory_timeout_keeps_original_handles_but_real_errors_are_not_timeouts() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(20);
        let found = job_wait_inventory(deadline, std::future::pending())
            .await
            .unwrap();
        assert!(found.is_none());
        let handles = job_test_handles(3);
        let response = inventory_timeout_rows(handles.clone());
        assert_eq!(response["finished"], false);
        assert_eq!(response["pending"], json!(handles));
        assert_eq!(response["status"][1]["probed"], false);
        assert_eq!(response["status"][1]["target"], handles[1]["target"]);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        let denied =
            job_wait_inventory(deadline, async { Err(BridgeError::inventory("denied")) }).await;
        assert!(matches!(denied, Err(BridgeError::Inventory(_))));
    }

    #[test]
    fn batch_wait_returns_only_unfinished_handles_for_followup() {
        let jobs = [
            json!({"target":"asset-a","job_id":"aaaaaaaa"}),
            json!({"target":"asset-b","job_id":"bbbbbbbb"}),
            json!({"target":"asset-c","job_id":"cccccccc"}),
        ];
        let pairs: Vec<_> = jobs
            .iter()
            .map(|row| {
                (
                    Host {
                        name: row["target"].as_str().unwrap().into(),
                        ..Host::default()
                    },
                    row["job_id"].as_str().unwrap().into(),
                )
            })
            .collect();
        let value = project_job_wait(
            &jobs,
            &pairs,
            vec![
                json!({"status":"done","exit_code":"0"}),
                json!({"status":"failed","exit_code":"7"}),
                json!({"status":"running","watch_timeout":true}),
            ],
            false,
        );
        assert_eq!(value["pending"], json!([jobs[2]]));
        assert_eq!(value["status"][1]["exit_code"], "7");
        assert_eq!(value["status"][1]["job_id"], "bbbbbbbb");
        assert_eq!(value["status"][2]["target"], "asset-c");
    }

    #[test]
    fn terminal_page_wait_defaults_to_fifteen_seconds() {
        assert!(matches!(
            PageOptions::from(&Map::new()).read_wait(),
            ReadWait::Output(15_000)
        ));
        let completed = json!({"wait_for":"completed","wait_ms":u64::MAX});
        assert!(matches!(
            PageOptions::from(completed.as_object().unwrap()).read_wait(),
            ReadWait::Completed(30_000)
        ));
        assert_eq!(PageOptions::from(&Map::new()).wait_ms, 15_000);
        assert_eq!(
            PageOptions::from(json!({"wait_ms": 0}).as_object().unwrap()).wait_ms,
            0
        );
    }

    /// Everything the transfer snapshot emits must survive the projection.
    ///
    /// `protocol_rate_bps` was generated but missing from the whitelist, so the usual
    /// progress poll showed protocol bytes without the rate that goes with them.
    #[test]
    fn the_progress_projection_carries_every_snapshot_field() {
        use crate::transport::rsync::TransferProgress;
        let keys = meta_section_keys("progress");

        let with_rsync = TransferProgress::default();
        with_rsync.start();
        with_rsync.set_total(1_000);
        with_rsync.add_bytes(120);
        with_rsync.observe("     500  50%  1MB/s  0:00:01");
        for key in with_rsync.snapshot().keys() {
            assert!(
                keys.contains(&key.as_str()),
                "`meta(section=progress)` drops {key}; the whitelist is out of date"
            );
        }

        let protocol_only = TransferProgress::default();
        protocol_only.start();
        protocol_only.set_total(1_000);
        protocol_only.add_bytes(64);
        for key in protocol_only.snapshot().keys() {
            assert!(
                keys.contains(&key.as_str()),
                "`meta(section=progress)` drops {key} for a transfer without rsync progress"
            );
        }
    }

    /// A local persistence failure after a successful run must not read as "not run".
    #[test]
    fn a_store_failure_after_the_run_keeps_the_execution_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(
            crate::storage::results::ResultStore::new(
                directory.path().to_path_buf(),
                3600.0,
                3600.0,
            )
            .unwrap(),
        );
        let result_id = store
            .create(
                json!({"kind": "run", "host": "asset-1"})
                    .as_object()
                    .cloned()
                    .unwrap(),
            )
            .unwrap();
        // Simulate "the remote command ran, then the metadata write failed": the result
        // directory disappears before `finish`.
        std::fs::remove_dir_all(store.root.join(&result_id)).unwrap();
        let mut values = Map::new();
        values.insert("result_id".into(), Value::from(result_id.clone()));
        values.insert("ok".into(), Value::Bool(true));
        values.insert("exit_code".into(), json!(0));
        values.insert("executed".into(), Value::Bool(true));
        values.insert("execution_state".into(), Value::from("completed"));
        values.insert("completion_unknown".into(), Value::Bool(false));
        let error = store
            .finish(&result_id, values.clone())
            .err()
            .expect("finish must fail on a missing result");
        let failure = crate::execution::ExecFailure::after(values, error);
        let row = failure_row("asset-1", &failure);
        assert_eq!(
            row["execution_state"], "completed",
            "must not become not_started"
        );
        assert_eq!(row["executed"], true);
        assert_eq!(row["exit_code"], 0);
        assert_eq!(row["result_id"], result_id);
        assert_eq!(row["ok"], false);
        assert!(
            row["error"].as_str().unwrap().contains("unknown")
                || !row["error"].as_str().unwrap().is_empty()
        );
        // The active slot is released even though the write failed.
        assert_eq!(store.retention_status()["active_results"], 0);
    }

    /// A local write after a successful retry must not un-prove the run.
    #[test]
    fn a_late_annotation_failure_keeps_the_completed_verdict() {
        let mut meta = Map::new();
        meta.insert("result_id".into(), Value::from("abc123"));
        meta.insert("ok".into(), Value::Bool(true));
        meta.insert("executed".into(), Value::Bool(true));
        meta.insert("execution_state".into(), Value::from("completed"));
        meta.insert("completion_unknown".into(), Value::Bool(false));
        meta.insert("exit_code".into(), json!(0));
        let failure = crate::execution::ExecFailure::after_local_write(
            meta,
            crate::errors::BridgeError::storage("metadata write failed"),
        );
        let row = failure_row("asset-1", &failure);
        assert_eq!(row["execution_state"], "completed");
        assert_eq!(row["executed"], true);
        assert_eq!(row["result_id"], "abc123");
        assert_eq!(row["local_error"], true);
        assert_eq!(row["ok"], false);
    }

    /// An error with no transmission evidence must never claim "nothing was sent".
    #[test]
    fn an_unclassified_error_is_unknown_not_not_started() {
        let failure: crate::execution::ExecFailure =
            crate::errors::BridgeError::storage("something failed").into();
        let row = failure_row("asset-1", &failure);
        assert_eq!(row["execution_state"], "unknown");
        assert_eq!(row["completion_unknown"], true);
        assert!(row["executed"].is_null());
    }

    /// Only a proven pre-send failure may be reported as "not executed".
    #[test]
    fn a_presend_failure_is_still_reported_as_not_started() {
        let failure = crate::execution::ExecFailure::before_send(
            "channel",
            crate::errors::BridgeError::ssh("channel refused"),
        );
        let row = failure_row("asset-1", &failure);
        assert_eq!(row["execution_state"], "not_started");
        assert_eq!(row["executed"], false);
        assert_eq!(row["completion_unknown"], false);
        assert_eq!(row["failure_stage"], "channel");
    }

    /// A staged summary must not swallow the fields that say whether the work finished.
    #[test]
    fn staged_summary_keeps_the_short_state_fields() {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::storage::results::ResultStore::new(
            directory.path().to_path_buf(),
            3600.0,
            3600.0,
        )
        .unwrap();
        let rows: Vec<Value> = (0..500)
            .map(|index| json!({"host": format!("h{index}"), "pad": "x".repeat(40)}))
            .collect();
        let value = json!({
            "ok": false,
            "request_id": "req-1",
            "request_state": "interrupted",
            "completion_unknown": true,
            "jobs": rows,
        });
        let out = stage_if_large(&store, "jms_submit_job", value).unwrap();
        assert_eq!(out["staged"], true);
        assert_eq!(out["request_id"], "req-1");
        assert_eq!(out["request_state"], "interrupted");
        assert_eq!(out["completion_unknown"], true);
        assert!(out["note"].as_str().unwrap().contains("read_result"));
        assert!(out.to_string().len() < 4096);
    }

    /// The full chain the review asked for: execution evidence -> classifier -> row.
    #[test]
    fn evidence_flows_through_the_classifier_into_the_row() {
        let handle_for = |state| crate::jobs::JobHandle {
            job_id: "abcd1234".into(),
            host: "asset-1".into(),
            session: "jms-abcd1234".into(),
            launcher: "unknown".into(),
            state,
        };
        let outcome_with = |meta: Value| crate::execution::ExecOutcome {
            host: "asset-1".into(),
            exit_code: meta.get("exit_code").and_then(Value::as_i64).unwrap_or(75),
            stdout: String::new(),
            stderr: "job did not start\n".into(),
            timed_out: false,
            result_id: "r1".into(),
            preview: None,
            rejection: Map::new(),
            recovery: Map::new(),
            meta: meta.as_object().cloned().unwrap_or_default(),
        };

        // Sent, no completion evidence: unknown, and the row must say so.
        let sent = outcome_with(json!({
            "executed": false,
            "execution_state": "unknown",
            "completion_unknown": true,
        }));
        let state = crate::jobs::derive_launch_state(false, &sent.meta);
        let row = job_row(&handle_for(state), &sent);
        assert_eq!(row["launch_state"], "unknown");
        assert_eq!(row["launched"], false);
        assert_eq!(row["completion_unknown"], true);
        assert_eq!(row["job_id"], "abcd1234");

        // Launcher exit 5 (waited, saw nothing): still unknown, never rejected.
        let waited = outcome_with(json!({
            "executed": true,
            "exit_code": 5,
            "execution_state": "completed",
            "completion_unknown": false,
        }));
        let row = job_row(
            &handle_for(crate::jobs::derive_launch_state(false, &waited.meta)),
            &waited,
        );
        assert_eq!(row["launch_state"], "unknown");
        assert_eq!(row["completion_unknown"], true);

        // A pre-send failure is the only path that may claim "rejected".
        let refused = outcome_with(json!({
            "executed": false,
            "execution_state": "not_started",
            "completion_unknown": false,
            "failure_stage": "channel",
        }));
        let row = job_row(
            &handle_for(crate::jobs::derive_launch_state(false, &refused.meta)),
            &refused,
        );
        assert_eq!(row["launch_state"], "rejected");
        assert_eq!(row["launched"], false);
        assert_eq!(row["completion_unknown"], false);
        assert!(row["stderr"].as_str().unwrap().contains("did not start"));
    }

    /// The full chain: a launcher that refused must never look like a running job.
    #[test]
    fn job_rows_distinguish_acknowledged_rejected_and_unknown() {
        let handle = |state| crate::jobs::JobHandle {
            job_id: "abcd1234".into(),
            host: "asset-1".into(),
            session: "jms-abcd1234".into(),
            launcher: "unknown".into(),
            state,
        };
        let outcome = |executed: bool| crate::execution::ExecOutcome {
            host: "asset-1".into(),
            exit_code: 3,
            stdout: String::new(),
            stderr: "no tmux and no setsid\n".into(),
            timed_out: false,
            result_id: "r1".into(),
            preview: None,
            rejection: Map::new(),
            recovery: Map::new(),
            meta: json!({"executed": executed, "execution_state": "completed"})
                .as_object()
                .cloned()
                .unwrap_or_default(),
        };

        let acknowledged = job_row(
            &handle(crate::jobs::LaunchState::Acknowledged),
            &outcome(true),
        );
        assert_eq!(acknowledged["launched"], true);
        assert_eq!(acknowledged["launch_state"], "acknowledged");
        assert!(acknowledged.get("stderr").is_none());

        let rejected = job_row(&handle(crate::jobs::LaunchState::Rejected), &outcome(true));
        assert_eq!(rejected["launched"], false);
        assert_eq!(rejected["launch_state"], "rejected");
        assert_eq!(rejected["job_id"], "abcd1234");
        assert_eq!(rejected["result_id"], "r1");
        assert!(rejected["stderr"].as_str().unwrap().contains("no tmux"));

        let unknown = job_row(&handle(crate::jobs::LaunchState::Unknown), &outcome(true));
        assert_eq!(unknown["launched"], false);
        assert_eq!(unknown["launch_state"], "unknown");
        assert_eq!(unknown["completion_unknown"], true);
    }

    #[test]
    fn small_operation_payloads_are_returned_as_is() {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::storage::results::ResultStore::new(
            directory.path().to_path_buf(),
            3600.0,
            3600.0,
        )
        .unwrap();
        let value = json!({"ok": true, "host": "h1"});
        let out = stage_if_large(&store, "jms_job_status", value.clone()).unwrap();
        assert_eq!(out, value);
    }

    #[test]
    fn oversized_operation_payloads_are_saved_and_summarised() {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::storage::results::ResultStore::new(
            directory.path().to_path_buf(),
            3600.0,
            3600.0,
        )
        .unwrap();
        let rows: Vec<Value> = (0..400)
            .map(|index| json!({"host": format!("h{index}"), "x": "y".repeat(40)}))
            .collect();
        let value = json!({"ok": true, "count": 400, "hosts": rows});
        let out = stage_if_large(&store, "jms_accelerator_status", value.clone()).unwrap();
        assert_eq!(out["staged"], true);
        assert!(out.to_string().len() < 4096, "summary must stay bounded");
        let result_id = out["result_id"].as_str().unwrap();
        let saved = std::fs::read_to_string(store.path(result_id, "result").unwrap()).unwrap();
        assert_eq!(saved.len(), value.to_string().len());
        assert!(saved.contains("h399"));
    }
}
