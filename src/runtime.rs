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
use crate::terminal::Interactive;

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
            for key in ["request_id", "wait_ms", "max_bytes", "cursor"] {
                identity.remove(key);
            }
            identity
        };
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
                                    .execute(
                                        &session,
                                        &script,
                                        allow,
                                        page.wait_ms,
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
                    .execute(
                        &session,
                        &script,
                        allow,
                        page.wait_ms,
                        page.max_bytes,
                        page.cursor.as_ref(),
                        None,
                    )
                    .await
            }
            "read" => {
                let session = used_string(&arguments, "session")?;
                self.terminals
                    .read(&session, page.wait_ms, page.max_bytes, page.cursor.as_ref())
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
                    let (wait_ms, max_bytes) = (page.wait_ms, page.max_bytes);
                    return self
                        .journal
                        .execute(
                            &request_id,
                            "terminal_write",
                            &Value::Object(work),
                            move |_progress| async move {
                                terminals
                                    .write(
                                        &session,
                                        input.as_deref(),
                                        signal.as_deref(),
                                        eof,
                                        allow,
                                        wait_ms,
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
                    .write(
                        &session,
                        input,
                        signal,
                        eof,
                        allow,
                        page.wait_ms,
                        page.max_bytes,
                        page.cursor.as_ref(),
                    )
                    .await
            }
            "close" => {
                let session = used_string(&arguments, "session")?;
                self.terminals.close(&session).await
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
        self.store
            .read(&result_id, stream, offset, limit, tail, pattern)
    }

    // --- discover ------------------------------------------------------------

    pub async fn tool_discover(&self, arguments: &Map<String, Value>) -> BridgeResult<Value> {
        let query = arguments
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
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
        if topic == "assets" {
            self.catalog.ensure().await?;
            return Ok(self.catalog.search(&query, offset, limit));
        }
        let operations = schemas::operations();
        if let Some(operation) = arguments.get("operation").and_then(Value::as_str) {
            if operation.is_empty() {
                return Err(BridgeError::invalid(
                    "unknown operation; use discover(query=...)",
                ));
            }
            if operation == "jms_fs" && !query.is_empty() {
                return schemas::fs_action_schema(&query).map_err(BridgeError::invalid);
            }
            // A tool name returns its complete schema: this is where the fields kept out
            // of the advertised `options` bag are documented.
            if let Some(spec) = schemas::full_specs()
                .into_iter()
                .find(|spec| spec.name == operation)
            {
                return Ok(json!({
                    "name": spec.name,
                    "description": spec.description,
                    "inputSchema": spec.input_schema,
                    "annotations": {
                        "readOnlyHint": spec.read_only,
                        "destructiveHint": spec.destructive,
                        "openWorldHint": spec.open_world,
                    },
                    "advertised": true,
                }));
            }
            let schema = operations.get(operation).ok_or_else(|| {
                BridgeError::invalid("unknown operation; use discover(query=...)")
            })?;
            return Ok(schema.clone());
        }
        if query.is_empty() {
            let categories: Map<String, Value> = schemas::categories()
                .into_iter()
                .map(|(name, members)| (name.to_string(), json!(members.len())))
                .collect();
            return Ok(json!({
                "categories": categories,
                "hint": "Pass a category/search query, then operation for one full schema.",
            }));
        }
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
                let description = operations
                    .get(name)
                    .and_then(|schema| schema.get("description"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                json!({"name": name, "description": description})
            })
            .collect();
        let next = offset + selected.len();
        Ok(json!({
            "operations": selected,
            "matched": names.len(),
            "next_offset": if next < names.len() { json!(next) } else { Value::Null },
        }))
    }

    // --- call ----------------------------------------------------------------

    pub async fn tool_call(self: &Arc<Self>, arguments: Map<String, Value>) -> BridgeResult<Value> {
        let operation = used_string(&arguments, "operation")?;
        let mut payload = match arguments.get("arguments") {
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
            BridgeError::invalid(format!(
                "Invalid operation arguments at {}; discover this operation for its schema",
                if error.path.is_empty() {
                    "<args>".to_string()
                } else {
                    error.path.clone()
                }
            ))
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
            return self.stage_operation_result(&operation_for_task, value);
        }
        let _ = &mut payload;
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
            "jms_fs" => self.tool_fs(arguments).await,
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
                let host = self.resolve_one(&used_string(&arguments, "host")?).await?;
                let job_id = used_string(&arguments, "job_id")?;
                let offset = arguments.get("offset").and_then(Value::as_u64).unwrap_or(0);
                let max_bytes = arguments
                    .get("max_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(4096)
                    .clamp(1024, 16384);
                self.jobs.logs(&host, &job_id, offset, max_bytes).await
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
                let submitted = runtime
                    .jobs
                    .submit(&host, command.as_ref(), progress.as_deref())
                    .await;
                (index, name, submitted)
            });
        }
        let mut launched: Vec<(usize, Value)> = Vec::new();
        let mut all_launched = true;
        let mut any_unknown = false;
        while let Some(joined) = set.join_next().await {
            let (index, name, submitted) = match joined {
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
            let row = match submitted {
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
        let keys: &[&str] = match section {
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
        };
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
    pub max_bytes: usize,
    pub cursor: Option<Value>,
}

impl PageOptions {
    fn from(arguments: &Map<String, Value>) -> Self {
        let wait_ms = arguments
            .get("wait_ms")
            .and_then(Value::as_u64)
            .unwrap_or(1000)
            .min(30_000);
        let max_bytes = arguments
            .get("max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(4096)
            .clamp(1, 16_384) as usize;
        Self {
            wait_ms,
            max_bytes,
            cursor: arguments.get("cursor").cloned(),
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

/// Save an oversized operation payload and return a bounded summary of it.
pub fn stage_if_large(
    store: &crate::storage::results::ResultStore,
    operation: &str,
    value: Value,
) -> BridgeResult<Value> {
    const BUDGET: usize = 8 * 1024;
    // Serialize once: the same bytes decide the budget, feed the preview and get saved.
    let bytes = serde_json::to_vec(&value)?;
    if bytes.len() <= BUDGET {
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
            "response exceeded {BUDGET} bytes; full payload saved as {result_id} (read_result with stream='result')"
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

#[cfg(test)]
mod tests {
    use super::*;

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
