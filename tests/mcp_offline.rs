//! Offline contract tests: validation, receipts and pairing without a bastion.

use serde_json::{json, Map, Value};

use jms_bridge::mcp::BridgeServer;
use jms_bridge::runtime::BridgeRuntime;

fn temp_root() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("jms-offline-{}", std::process::id()));
    std::fs::create_dir_all(&base).expect("temp root");
    base
}

/// One runtime for the whole test: `JMS_*` overrides are process global.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_contracts_hold_end_to_end() {
    let root = temp_root();
    let config_path = root.join("config.toml");
    std::fs::write(
        &config_path,
        "[bastion]\nurl = \"http://127.0.0.1:1\"\nssh_port = 2224\nlogin_user = \"tester\"\n\
max_parallel = 2\n",
    )
    .expect("config");
    std::fs::write(
        root.join("credentials.toml"),
        "[credentials]\nsession_token = \"offline-token\"\n",
    )
    .expect("credentials");
    std::env::set_var("JMS_BRIDGE_CONFIG", &config_path);
    std::env::set_var("JMS_BRIDGE_STATE_DIR", root.join("state"));
    std::env::remove_var("JMS_BRIDGE_URL");

    let runtime = BridgeRuntime::start(Some(&config_path), false)
        .await
        .expect("runtime starts without network");
    let server = BridgeServer::new(runtime.clone());

    // Eight tools stay advertised, with closed schemas.
    let tools = server.tool_specs();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(
        names,
        vec![
            "run",
            "fs",
            "terminal",
            "job",
            "read_result",
            "discover",
            "call",
            "meta"
        ]
    );
    for tool in &tools {
        assert_eq!(
            tool.input_schema.get("additionalProperties"),
            Some(&json!(false))
        );
    }

    for (tool, args) in [
        (
            "job",
            json!({"action":"logs","target":"worker","job_id":"abcd1234","offset":0,"tail":true}),
        ),
        (
            "call",
            json!({"operation":"jms_job_logs","arguments":{
                "host":"worker","job_id":"abcd1234","offset":0,"tail":true
            }}),
        ),
    ] {
        let error = server.dispatch(tool, object(args)).await.unwrap_err();
        assert!(error.message().contains("tail or offset"), "{error}");
    }

    for (tool, args) in [
        (
            "job",
            json!({"action":"logs","target":"worker","job_id":"abcd1234",
            "pattern":"[$?]","tail":true}),
        ),
        (
            "call",
            json!({"operation":"jms_job_logs","arguments":{
                "host":"worker","job_id":"abcd1234","pattern":"[$?]","tail":true
            }}),
        ),
    ] {
        let error = server.dispatch(tool, object(args)).await.unwrap_err();
        assert!(error.message().contains("tail or pattern"), "{error}");
    }

    for (tool, args) in [
        (
            "job",
            json!({"action":"logs","target":"worker","job_id":"abcd1234",
            "cursor":"v1:5:10:1:2:scope","offset":5}),
        ),
        (
            "call",
            json!({"operation":"jms_job_logs","arguments":{
                "host":"worker","job_id":"abcd1234","cursor":"v1:5:10:1:2:scope","offset":5
            }}),
        ),
    ] {
        let error = server.dispatch(tool, object(args)).await.unwrap_err();
        assert!(
            error.message().contains("cannot be combined with offset"),
            "{error}"
        );
    }

    let paired_tail_error = server
        .dispatch(
            "job",
            object(json!({
                "action":"wait","jobs":[{"target":"all","job_id":"abcd1234"}],"tail":true
            })),
        )
        .await
        .unwrap_err();
    assert!(
        paired_tail_error
            .message()
            .contains("exact permitted target"),
        "{paired_tail_error}"
    );

    // Seed a mocked launch under the legacy operation, keeping it in-flight.
    // Both public entry points must attach to that receipt, not call a launcher.
    let request_id = "facade-legacy-shared-id";
    let business = json!({"targets":["a","b","c"],"command":"printf hello"});
    let seeded_business = business.clone();
    let journal = runtime.journal.clone();
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let worker_gate = gate.clone();
    let launched = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_launched = launched.clone();
    let worker = tokio::spawn(async move {
        journal.execute(request_id, "jms_submit_job", &seeded_business, move |_sink| async move {
            worker_launched.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            worker_gate.notified().await;
            Ok(json!({"ok":false,"jobs":[
                {"host":"a","asset_id":"mock-asset-a","job_id":"11111111","launch_state":"acknowledged"},
                {"host":"b","job_id":"22222222","launch_state":"unknown"},
                {"host":"c","job_id":"33333333","launch_state":"rejected","stderr":"mock refusal"}
            ]}))
        }).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while launched.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let facade = || {
        server.dispatch(
            "job",
            object(json!({
                "action":"submit", "targets":["a","b","c"], "command":"printf hello",
                "allow_dangerous":false, "request_id":request_id
            })),
        )
    };
    let legacy = || {
        server.dispatch(
            "call",
            object(json!({
                "operation":"jms_submit_job","arguments":business,"request_id":request_id,
                "detail":"full"
            })),
        )
    };
    let (new_running, old_running) = tokio::join!(facade(), legacy());
    for value in [new_running.unwrap(), old_running.unwrap()] {
        assert_eq!(value["duplicate"], true);
        assert_eq!(value["request_state"], "running");
        assert_eq!(value["execution_replayed"], false);
    }
    gate.notify_one();
    worker.await.unwrap().unwrap();
    let recovered = facade().await.unwrap();
    assert_eq!(
        recovered["jobs"],
        json!([
            {"target":"mock-asset-a","job_id":"11111111"}, {"target":"b","job_id":"22222222"}
        ])
    );
    assert_eq!(recovered["submissions"][2]["stderr"], "mock refusal");
    assert_eq!(legacy().await.unwrap()["jobs"][2]["job_id"], "33333333");
    assert_eq!(launched.load(std::sync::atomic::Ordering::SeqCst), 1);
    let changed = server
        .dispatch(
            "job",
            object(json!({
                "action":"submit","targets":["a","b","c"],"command":"printf changed",
                "request_id":request_id
            })),
        )
        .await
        .unwrap_err();
    assert!(changed.message().contains("arguments cannot change"));
    assert!(server
        .dispatch(
            "job",
            object(json!({
                "action":"submit","targets":["a"],"command":"printf hello"
            }))
        )
        .await
        .unwrap_err()
        .message()
        .contains("requires request_id"));

    // Guard: an unauthorized destructive script is refused before any connection.
    let error = server
        .dispatch(
            "run",
            object(json!({"targets": ["all"], "script": "shutdown -h now"})),
        )
        .await
        .unwrap_err();
    assert!(
        error.message().contains("destructive-pattern guard"),
        "{}",
        error.message()
    );

    // Exactly one of script/script_path is required.
    let error = server
        .dispatch("run", object(json!({"targets": ["all"]})))
        .await
        .unwrap_err();
    assert!(
        error.message().contains("script or script_path"),
        "{}",
        error.message()
    );

    // Advanced options merge into the flat argument namespace.
    let error = server
        .dispatch(
            "run",
            object(json!({"targets": ["all"], "script": "true", "options": {"timeout": 9999}})),
        )
        .await
        .unwrap_err();
    assert!(
        error.message().contains("Invalid arguments"),
        "{}",
        error.message()
    );

    // Unknown operation must name the discovery path.
    let error = server
        .dispatch(
            "call",
            object(json!({"operation": "jms_cluster_submit", "arguments": {}})),
        )
        .await
        .unwrap_err();
    assert!(error.message().contains("discover its schema"));

    // Hidden operations are validated against their own schema.
    let error = server
        .dispatch(
            "call",
            object(json!({"operation": "jms_exec", "arguments": {"targets": ["all"]}})),
        )
        .await
        .unwrap_err();
    assert!(error.message().contains("Invalid operation arguments"));

    // Filesystem actions validate before touching a connection.
    let error = server
        .dispatch(
            "fs",
            object(json!({"target": "a", "action": "teleport", "path": "/tmp"})),
        )
        .await
        .unwrap_err();
    assert!(error.message().contains("action"), "{}", error.message());

    // Terminal sessions are explicit: an unknown handle is a clean error.
    let error = server
        .dispatch(
            "terminal",
            object(json!({"action": "read", "session": "deadbeef"})),
        )
        .await
        .unwrap_err();
    assert!(error.message().contains("unknown terminal session"));

    // Historical command output is addressable through both terminal entry
    // points without creating a shell, even when its old handle is absent.
    let command_id = runtime
        .store
        .create(object(json!({
            "kind": "terminal", "session_id": "previous-shell"
        })))
        .unwrap();
    std::fs::write(
        runtime.store.path(&command_id, "stdout").unwrap(),
        b"recorded",
    )
    .unwrap();
    runtime
        .store
        .finish(
            &command_id,
            object(json!({
                "execution_state": "completed", "exit_code": 0, "ok": true
            })),
        )
        .unwrap();
    let first = server
        .dispatch(
            "terminal",
            object(json!({
                "action": "read", "session": "previous-shell",
                "options": {"result_id": command_id, "max_bytes": 3,
                            "cursor":{"stdout":0,"stderr":0}}
            })),
        )
        .await
        .unwrap();
    assert_eq!(first["stdout"], "rec");
    let second = server
        .dispatch(
            "call",
            object(json!({
                "operation": "terminal_read", "arguments": {
                    "session": "previous-shell", "result_id": command_id, "cursor": first["cursor"]
                }
            })),
        )
        .await
        .unwrap();
    assert_eq!(second["stdout"], "orded");
    assert_eq!(first["cursor"]["next_stream"], "stderr");
    let replay = server
        .dispatch(
            "terminal",
            object(json!({
                "action": "read", "session": "previous-shell",
                "options": {"result_id": command_id, "cursor": first["cursor"]}
            })),
        )
        .await
        .unwrap();
    assert_eq!(replay, second);
    let wrong_session = server
        .dispatch(
            "terminal",
            object(json!({
                "action": "read", "session": "unrelated",
                "options": {"result_id": command_id}
            })),
        )
        .await
        .unwrap_err();
    assert!(wrong_session
        .message()
        .contains("not a command for this terminal"));

    // A pre-fix partial write was saved as executed=true even without START.
    // Both terminal and general metadata reads clarify it without migrating the file.
    run_saved_views_do_not_change_receipt_identity(&runtime, &server).await;
    legacy_partial_send_metadata_is_corrected_on_read(&runtime, &server).await;
    terminal_request_identity_is_shared(&runtime, &server).await;

    // Failure counters stay visible in the receipts surface.
    let status = runtime.status().await;
    assert!(status.get("execution").is_some());
    assert!(status.get("service").is_some());

    // A saved result is readable by byte offset and never re-executed.
    let mut metadata = Map::new();
    metadata.insert("kind".into(), Value::from("run"));
    metadata.insert("host".into(), Value::from("h1"));
    let result_id = runtime.store.create(metadata).expect("create result");
    std::fs::write(
        runtime.store.path(&result_id, "stdout").unwrap(),
        b"alpha\nbeta\ngamma\n",
    )
    .unwrap();
    let mut values = Map::new();
    values.insert("ok".into(), Value::Bool(true));
    values.insert("status".into(), Value::from("complete"));
    runtime.store.finish(&result_id, values).expect("finish");

    let page = server
        .dispatch(
            "read_result",
            object(json!({"result_id": result_id, "offset": 6, "limit": 5})),
        )
        .await
        .expect("read saved result");
    assert_eq!(page["text"], json!("beta\n"));
    assert_eq!(page["next_offset"], json!(11));

    let first_lines = server
        .dispatch(
            "read_result",
            object(json!({"result_id": result_id, "head_lines": 2})),
        )
        .await
        .expect("read first two saved lines");
    assert_eq!(first_lines["text"], "alpha\nbeta\n");
    assert_eq!(first_lines["next_offset"], 11);
    assert_eq!(first_lines["eof"], false);
    for args in [
        json!({"result_id": result_id, "head_lines": 1, "pattern": "alpha"}),
        json!({"result_id": result_id, "head_lines": 1, "tail": true}),
    ] {
        let error = server
            .dispatch("read_result", object(args))
            .await
            .unwrap_err();
        assert!(error.message().contains("head_lines cannot be combined"));
    }

    let meta = server
        .dispatch(
            "meta",
            object(json!({"ref": format!("result:{result_id}")})),
        )
        .await
        .expect("meta");
    assert_eq!(meta["kind"], json!("run"));
    assert_eq!(meta["status"], json!("complete"));

    // Result ids are validated, so path traversal never reaches the store.
    let error = server
        .dispatch(
            "read_result",
            object(json!({"result_id": "../../etc/passwd"})),
        )
        .await
        .unwrap_err();
    assert!(error.message().contains("invalid result_id"));

    // Unknown requests leave no receipt behind.
    let error = runtime.request_status("never-issued").await.unwrap_err();
    assert!(
        error.message().contains("unknown") || error.message().contains("not"),
        "{}",
        error.message()
    );

    // Discovery serves the hidden operation schema on demand.
    let schema = server
        .dispatch(
            "discover",
            object(json!({"query": "read", "operation": "jms_fs"})),
        )
        .await
        .expect("discover operation");
    assert_eq!(
        schema["inputSchema"]["properties"]["action"]["const"],
        json!("read")
    );

    let signature = server
        .dispatch(
            "discover",
            object(json!({"query": "read", "operation": "jms_fs", "view": "signature"})),
        )
        .await
        .expect("discover filesystem signature");
    let line = signature["signature"].as_str().unwrap();
    assert!(
        line.starts_with(r#"jms_fs(action="read", path, target, "#),
        "{line}"
    );
    assert!(line.contains("byte_offset?"));
    assert!(signature.get("inputSchema").is_none());
    assert_ne!(signature["etag"], schema["etag"]);
    assert_eq!(signature["catalog_version"], schema["catalog_version"]);

    // Action-specific discovery must match the pre-connection runtime validator.
    for (action, max, default) in [
        ("read", 120, 30),
        ("upload", 900, 900),
        ("download", 900, 900),
    ] {
        let full = server
            .dispatch(
                "discover",
                object(json!({"operation": "jms_fs", "query": action})),
            )
            .await
            .unwrap();
        let timeout = &full["inputSchema"]["properties"]["timeout"];
        assert_eq!(timeout["maximum"], max, "{action}");
        assert_eq!(timeout["default"], default, "{action}");

        let compact = server
            .dispatch(
                "discover",
                object(json!({
                    "operation": "jms_fs", "query": action, "view": "signature",
                })),
            )
            .await
            .unwrap();
        assert!(compact["signature"]
            .as_str()
            .unwrap()
            .contains(&format!("timeout?[1..{max}]")));

        let mut fs_args = json!({"target": "mock", "path": "/remote", "action": action});
        if action != "read" {
            fs_args["local_path"] = json!(config_path);
        }
        for (seconds, allowed) in [(max, true), (max + 1, false)] {
            fs_args["timeout"] = json!(seconds);
            assert_eq!(
                jms_bridge::schema::validate(&full["inputSchema"], &fs_args).is_ok(),
                allowed,
                "schema {action} {seconds}",
            );
            assert_eq!(
                jms_bridge::filesystem::validate(&object(fs_args.clone())).is_ok(),
                allowed,
                "runtime {action} {seconds}",
            );
        }
    }

    let resident = server
        .dispatch("discover", object(json!({"operation": "run"})))
        .await
        .unwrap();
    assert_eq!(resident["advertised"], true);
    assert!(resident["inputSchema"]["properties"]["script_path"].is_object());

    let page_args = json!({"query": "jobs", "view": "signature", "limit": 1, "offset": 0});
    let page = server
        .dispatch("discover", object(page_args.clone()))
        .await
        .unwrap();
    let row = &page["operations"][0];
    assert_eq!(row["name"], "jms_submit_job");
    assert_eq!(
        row["signature"],
        "jms_submit_job(command, targets, allow_dangerous?)"
    );
    let tag = page["etag"].clone();
    let mut cached = page_args;
    cached["if_none_match"] = tag.clone();
    let reply = server.dispatch("discover", object(cached)).await.unwrap();
    assert_eq!(reply, json!({"unchanged": true}));

    for different in [
        json!({"query": "jobs", "view": "signature", "limit": 1, "offset": 1}),
        json!({"query": "jobs", "view": "signature", "limit": 2}),
        json!({"query": "jobs", "limit": 1}),
        json!({"query": "JOBS", "view": "signature", "limit": 1}),
        json!({"query": "terminal", "view": "signature", "limit": 1}),
        json!({"operation": "jms_submit_job", "view": "signature", "limit": 1}),
    ] {
        let mut different = different;
        different["if_none_match"] = tag.clone();
        let reply = server
            .dispatch("discover", object(different))
            .await
            .unwrap();
        assert!(reply.get("unchanged").is_none());
        assert_ne!(reply["etag"], tag);
    }

    let wrong_token = server
        .dispatch(
            "discover",
            object(json!({
                "query": "jobs", "view": "signature", "limit": 1,
                "if_none_match": page["catalog_version"],
            })),
        )
        .await
        .unwrap();
    assert!(wrong_token.get("operations").is_some());

    let status = server
        .dispatch(
            "discover",
            object(json!({
                "topic": "status", "if_none_match": page["etag"],
            })),
        )
        .await
        .unwrap();
    assert!(status.get("unchanged").is_none());
    let asset_error = server
        .dispatch(
            "discover",
            object(json!({
                "topic": "assets", "if_none_match": page["etag"],
            })),
        )
        .await
        .unwrap_err();
    assert!(!asset_error.message().is_empty());

    // Real streamable HTTP service, using the same stateless runtime factory as the CLI.
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    let mut config = StreamableHttpServerConfig::default();
    config.legacy_session_mode = false;
    config.json_response = true;
    let service: StreamableHttpService<BridgeServer, LocalSessionManager> =
        StreamableHttpService::new(
            {
                let runtime = runtime.clone();
                move || Ok(BridgeServer::new(runtime.clone()))
            },
            std::sync::Arc::new(LocalSessionManager::default()),
            config,
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
    let http = tokio::spawn(async move {
        axum::serve(listener, axum::Router::new().nest_service("/mcp", service))
            .await
            .unwrap();
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    for (id, args, field) in [
        (
            1,
            json!({"operation": "jms_fs", "query": "read"}),
            "inputSchema",
        ),
        (
            2,
            json!({"operation": "jms_fs", "query": "read", "view": "signature"}),
            "signature",
        ),
        (
            3,
            json!({"operation": "jms_fs", "query": "read", "view": "signature",
                   "if_none_match": signature["etag"]}),
            "unchanged",
        ),
    ] {
        let reply: Value = client
            .post(&endpoint)
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-06-18")
            .json(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                          "params": {"name": "discover", "arguments": args}}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let body: Value = serde_json::from_str(
            reply["result"]["content"][0]["text"]
                .as_str()
                .expect("compact HTTP MCP tool reply"),
        )
        .unwrap();
        assert!(body.get(field).is_some(), "{body}");
        if field == "unchanged" {
            assert_eq!(body, json!({"unchanged": true}));
        }
    }
    // Invalid calls must fail before executing and retain isError and the
    // legacy error string while supplying a precise caller-visible pointer.
    for (name, arguments, path, expected, suggestion, old_error) in [
        (
            "run",
            json!({"targets":["worker"],"script":"printf test","max_output_bytes":255}),
            "/max_output_bytes",
            json!({"minimum":256, "maximum":16384}),
            Value::Null,
            "Invalid arguments at max_output_bytes: must be >= 256",
        ),
        (
            "run",
            json!({"targets":["worker"],"script":"printf test","options":{"max_output_bytes":16385}}),
            "/options/max_output_bytes",
            json!({"minimum":256, "maximum":16384}),
            Value::Null,
            "Invalid arguments at options.max_output_bytes: must be <= 16384",
        ),
        (
            "terminal",
            json!({"action":"read","session":"mock","options":{"wait_mss":1}}),
            "/options/wait_mss",
            Value::Null,
            json!("wait_ms"),
            "Invalid arguments at options: unexpected property: wait_mss",
        ),
        (
            "terminal",
            json!({"action":"raed","session":"mock"}),
            "/action",
            json!({"enum":["open","exec","read","write","close"]}),
            Value::Null,
            "Invalid arguments at action: value is not an allowed option",
        ),
        (
            "run",
            json!({"targets":["worker"],"script":"printf test","timeout":7,"options":{"timeout":12}}),
            "/options/timeout",
            Value::Null,
            Value::Null,
            "duplicate options: timeout",
        ),
        (
            "run",
            json!({"targets":["worker"],"script":"printf test","env":{"a/b~c":8}}),
            "/env/a~1b~0c",
            json!({"type":"string"}),
            Value::Null,
            "Invalid arguments at env.a/b~c: expected string, got integer",
        ),
        (
            "call",
            json!({"operation":"jms_job_wait","arguments":{"targets":["worker"],"job_id":"abcd1234","timeout":0}}),
            "/arguments/timeout",
            json!({"minimum":1,"maximum":180}),
            Value::Null,
            "Invalid operation arguments at timeout; discover this operation for its schema",
        ),
        (
            "call",
            json!({"operation":"jms_job_wait","arguments":{"targets":["worker"],"job_id":"abcd1234","timeoutt":3}}),
            "/arguments/timeoutt",
            Value::Null,
            json!("timeout"),
            "Invalid operation arguments at <args>; discover this operation for its schema",
        ),
        (
            "job",
            json!({"action":"wait","jobs":[{"target":"worker","jobid":"abcd1234"}]}),
            "/jobs/0/job_id",
            Value::Null,
            Value::Null,
            "Invalid arguments at jobs: value matches no allowed shape",
        ),
        (
            "job",
            json!({"action":"logs","job_id":"abcd1234"}),
            "/target",
            Value::Null,
            Value::Null,
            "Invalid operation arguments at <args>; discover this operation for its schema",
        ),
        (
            "fs",
            json!({"target":"worker","action":"read","path":"/fixture","timeout":121}),
            "/timeout",
            Value::Null,
            Value::Null,
            "Invalid arguments at <args>: unexpected property: timeout",
        ),
        (
            "fs",
            json!({"target":"worker","action":"read","path":"/fixture","options":{"timeout":121}}),
            "/options/timeout",
            json!({"minimum":1,"maximum":120}),
            Value::Null,
            "exploration timeout must be 1..=120 seconds",
        ),
        (
            "call",
            json!({"operation":"jms_fs","arguments":{"target":"worker","action":"read","path":"/fixture","timeout":901}}),
            "/arguments/timeout",
            json!({"minimum":1,"maximum":120}),
            Value::Null,
            "Invalid operation arguments at timeout; discover this operation for its schema",
        ),
        (
            "call",
            json!({"operation":"jms_fs","arguments":{"target":"worker","action":"read","path":"/fixture","timeout":121}}),
            "/arguments/timeout",
            json!({"minimum":1,"maximum":120}),
            Value::Null,
            "exploration timeout must be 1..=120 seconds",
        ),
        (
            "fs",
            json!({"target":"worker","action":"read","path":"/fixture","options":{"overwrit":false}}),
            "/options/overwrit",
            Value::Null,
            Value::Null,
            "Invalid arguments at options: unexpected property: overwrit",
        ),
        (
            "call",
            json!({"operation":"jms_fs","arguments":{"target":"worker","action":"read","path":"/fixture","overwrit":false}}),
            "/arguments/overwrit",
            Value::Null,
            Value::Null,
            "Invalid operation arguments at <args>; discover this operation for its schema",
        ),
        (
            "fs",
            json!({"target":"worker","action":"download","path":"/fixture","options":{"timeout":901}}),
            "/options/timeout",
            json!({"minimum":1,"maximum":900}),
            Value::Null,
            "Invalid arguments at options.timeout: must be <= 900",
        ),
        (
            "job",
            json!({"action":"wait","jobs":[{"target":"worker","job_id":"abcd1234"}],"targets":["worker"]}),
            "/targets",
            Value::Null,
            Value::Null,
            "job wait takes jobs or targets/job_id, not both",
        ),
        (
            "job",
            json!({"action":"wait","jobs":{"ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"job_id":"abcd1234"}),
            "/job_id",
            Value::Null,
            Value::Null,
            "job wait takes jobs or targets/job_id, not both",
        ),
        (
            "job",
            json!({"action":"wait","jobs":[{"target":"worker","job_id":"abcd1234"}],"pattern":"unused"}),
            "/pattern",
            Value::Null,
            Value::Null,
            "job wait takes jobs or targets/job_id, not both",
        ),
    ] {
        let reply: Value = client
            .post(&endpoint)
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-06-18")
            .json(&json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
                "params":{"name": name,"arguments": arguments}}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(reply["result"]["isError"], true, "{reply}");
        let body: Value =
            serde_json::from_str(reply["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(body["ok"], false, "{body}");
        assert_eq!(body["error"], old_error, "{body}");
        assert_eq!(body["validation"]["path"], path, "{body}");
        assert_eq!(body["validation"]["expected"], expected, "{body}");
        assert_eq!(body["validation"]["suggestion"], suggestion, "{body}");
        if old_error == "job wait takes jobs or targets/job_id, not both" {
            let message = match path {
                "/targets" => "targets cannot be combined with jobs",
                "/job_id" => "job_id cannot be combined with jobs",
                "/pattern" => "pattern is not applicable when waiting on jobs",
                _ => unreachable!(),
            };
            assert_eq!(body["validation"]["message"], message, "{body}");
        }
        if path == "/target" {
            assert_eq!(
                body["validation"]["message"], "missing required: target",
                "{body}"
            );
        }
        if path == "/arguments/timeout" && arguments["arguments"]["timeout"] == 901 {
            assert_eq!(body["validation"]["message"], "must be <= 120", "{body}");
        }
    }
    http.abort();

    runtime.shutdown().await;
}

async fn terminal_request_identity_is_shared(runtime: &BridgeRuntime, server: &BridgeServer) {
    let modern = server.dispatch(
        "terminal", object(json!({
            "action":"open", "target":"*", "options":{"request_id":"terminal-open-test","env":{"A":"one","Z":"two"}}
        })),
    );
    let legacy = server.dispatch(
        "call", object(json!({
            "operation":"terminal_open", "arguments":{
                "target":"*", "request_id":"terminal-open-test","env":{"Z":"two","A":"one"}
            }
        })),
    );
    let (modern, legacy) = tokio::join!(modern, legacy);
    let modern = modern.unwrap();
    let legacy = legacy.unwrap();
    assert_ne!(modern["duplicate"], legacy["duplicate"]);
    let receipt = runtime.request_status("terminal-open-test").await.unwrap();
    assert_eq!(receipt["request_state"], "failed");
    assert_eq!(receipt["state"], "lost");
    assert_eq!(receipt["session"].as_str().unwrap().len(), 32);
    let retry = server.dispatch(
        "terminal", object(json!({
            "action":"open", "target":"*", "options":{"request_id":"terminal-open-test","env":{"A":"one","Z":"two"}}
        })),
    ).await.unwrap();
    assert_eq!(retry["session"], receipt["session"]);
    assert_eq!(retry["execution_replayed"], false);

    let conflict = server.dispatch(
        "terminal", object(json!({
            "action":"open", "target":"*", "options":{
                "request_id":"terminal-open-test","env":{"Z":"two","A":"changed"}
            }
        })),
    ).await.unwrap_err();
    assert!(conflict.message().contains("already claimed"));

    // Simulate a process restart after persisting the reserved handle, but before
    // publishing a response. No task owns the running receipt in the new runtime.
    let interrupted = runtime.journal.directory("terminal-open-test")
        .unwrap().join("state.json");
    let mut saved: Value = serde_json::from_slice(&std::fs::read(&interrupted).unwrap()).unwrap();
    saved["request_state"] = json!("running");
    std::fs::write(&interrupted, serde_json::to_vec(&saved).unwrap()).unwrap();
    let after_restart = runtime.request_status("terminal-open-test").await.unwrap();
    assert_eq!(after_restart["request_state"], "interrupted");
    assert_eq!(after_restart["completion_unknown"], true);
    assert_eq!(after_restart["session"], receipt["session"]);
    assert_eq!(after_restart["state"], "lost");

    let meta = server.dispatch(
        "meta", object(json!({"ref":"request:terminal-open-test"})),
    ).await.unwrap();
    for key in ["session", "state", "terminal_sessions", "completion_unknown"] {
        assert_eq!(meta.get(key), after_restart.get(key), "{key}");
    }

    // Hold a real journal worker between durable reservation and completion.
    use jms_bridge::storage::journal::ProgressSink;
    let (reserved_tx, reserved_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
    let journal = runtime.journal.clone();
    let worker = tokio::spawn(async move {
        journal.execute("terminal-open-pending", "terminal_open", &json!({}), |progress| async move {
            progress.record("terminal_sessions", json!({"session":"unbound-mock-handle"}))?;
            reserved_tx.send(()).unwrap();
            finish_rx.await.unwrap();
            Ok(json!({"ok":true,"state":"idle","session":"unbound-mock-handle"}))
        }).await.unwrap()
    });
    reserved_rx.await.unwrap();
    let pending = runtime.request_status("terminal-open-pending").await.unwrap();
    let pending_meta = server.dispatch(
        "meta", object(json!({"ref":"request:terminal-open-pending"})),
    ).await.unwrap();
    for value in [&pending, &pending_meta] {
        assert_eq!(value["state"], "opening");
        assert!(value.get("session").is_none());
        assert!(value.get("terminal_sessions").is_none());
    }
    finish_tx.send(()).unwrap();
    worker.await.unwrap();
    let completed = runtime.request_status("terminal-open-pending").await.unwrap();
    let completed_meta = server.dispatch(
        "meta", object(json!({"ref":"request:terminal-open-pending"})),
    ).await.unwrap();
    assert_eq!(completed["request_state"], "complete");
    assert_eq!(completed["state"], "lost");
    for key in ["session", "state", "terminal_sessions"] {
        assert_eq!(completed_meta.get(key), completed.get(key), "{key}");
    }

    let exec = runtime.journal.execute(
        "terminal-exec-identity-test", "terminal_exec", &json!({
            "action":"exec", "session":"not-live", "script":":"
        }),
        |_| async { Ok(json!({"ok":true,"proof":"one-command"})) },
    ).await.unwrap();
    assert_eq!(exec["request_state"], "complete");
    let old_path = runtime.journal.directory("terminal-exec-identity-test")
        .unwrap().join("state.json");
    let mut old: Value = serde_json::from_slice(&std::fs::read(&old_path).unwrap()).unwrap();
    old["fingerprint"] = json!(jms_bridge::storage::journal::fingerprint_of(
        "terminal_exec",
        &json!({"action":"exec","session":"not-live","script":":"}),
    ));
    std::fs::write(old_path, serde_json::to_vec(&old).unwrap()).unwrap();
    for args in [
        json!({"session":"not-live","script":":","options":{"request_id":"terminal-exec-identity-test","wait_ms":0}}),
        json!({"action":"exec","session":"not-live","script":":","options":{"request_id":"terminal-exec-identity-test"}}),
    ] {
        let replay = server.dispatch("terminal", object(args)).await.unwrap();
        assert_eq!(replay["proof"], "one-command");
        assert_eq!(replay["duplicate"], true);
    }
}

async fn legacy_partial_send_metadata_is_corrected_on_read(
    runtime: &BridgeRuntime,
    server: &BridgeServer,
) {
    use jms_bridge::storage::journal::ProgressSink;

    let old_bytes = include_bytes!("fixtures/terminal_legacy_partial_send.json");
    let old: Value = serde_json::from_slice(old_bytes).unwrap();
    let id = old["result_id"].as_str().unwrap();
    let directory = runtime.store.directory(id).unwrap();
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("meta.json");
    std::fs::write(&path, old_bytes).unwrap();
    let terminal = server
        .dispatch(
            "terminal",
            object(json!({
                "action": "read", "session": old["session_id"],
                "options": {"result_id": id}
            })),
        )
        .await
        .unwrap();
    let meta = server
        .dispatch("meta", object(json!({"ref": format!("result:{id}")})))
        .await
        .unwrap();
    let receipt_id = "legacy-terminal-receipt";
    let receipt_result = id.to_string();
    runtime
        .journal
        .execute(
            receipt_id,
            "terminal",
            &json!({}),
            move |progress| async move {
                progress.record("execution_results", json!({"result_id": receipt_result}))?;
                Ok(json!({"result_id": receipt_result}))
            },
        )
        .await
        .unwrap();
    let receipt = runtime.request_status(receipt_id).await.unwrap();
    for projection in [
        &terminal,
        &meta,
        &receipt["execution_results"][0]["result_status"],
    ] {
        assert_eq!(projection.get("executed"), Some(&Value::Null));
        assert_eq!(projection["failure_stage"], "channel");
        assert_eq!(projection["completion_unknown"], true);
        assert_eq!(projection["error"], old["error"]);
    }
    assert_eq!(terminal["state"], "unknown");
    assert_eq!(meta["execution_state"], "unknown");
    assert_eq!(std::fs::read(&path).unwrap(), old_bytes);

    // Unrelated annotations must not bake the read-time correction into the record.
    runtime
        .store
        .annotate(id, object(json!({"diagnostic": "checked"})))
        .unwrap();
    let annotated: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(annotated["executed"], true);
    assert_eq!(runtime.store.metadata(id).unwrap()["executed"], Value::Null);

    // Actual START evidence from legacy capture used its own channel error and
    // could include exit_code=null. Neither that nor other kinds/stages match.
    for (key, value) in [
        (
            "error",
            json!("terminal command timed out; completion is unknown"),
        ),
        ("exit_code", Value::Null),
        ("kind", json!("run")),
        ("status", json!("running")),
        ("failure_stage", json!("closed_by_caller")),
    ] {
        let mut nonmatch = old.clone();
        nonmatch[key] = value;
        std::fs::write(&path, serde_json::to_vec(&nonmatch).unwrap()).unwrap();
        assert_eq!(
            runtime.store.metadata(id).unwrap()["executed"],
            true,
            "{key}"
        );
    }
}

async fn run_saved_views_do_not_change_receipt_identity(
    runtime: &BridgeRuntime,
    server: &BridgeServer,
) {
    let result_id = runtime.store.create(Map::new()).unwrap();
    std::fs::write(
        runtime.store.path(&result_id, "stdout").unwrap(),
        "alpha\nβeta\ngamma\n",
    )
    .unwrap();
    std::fs::write(
        runtime.store.path(&result_id, "stderr").unwrap(),
        "prefix [ERR] suffix\n",
    )
    .unwrap();
    runtime.store.finish(&result_id, Map::new()).unwrap();
    let id = "saved-run-view";
    // Deliberately seed the pre-view normalized journal payload.
    let business = json!({
        "targets":["offline"], "script":":", "cwd":null, "env":null,
        "container":null, "image":null, "docker_args":null, "session_id":null,
        "timeout":60, "max_output_bytes":4096, "allow_dangerous":false
    });
    let result = json!({"ok":true,"results":[{
        "host":"offline","ok":true,"exit_code":0,"execution_state":"completed",
        "result_id":result_id,"stdout":"legacy preview"
    }]});
    runtime
        .journal
        .execute(id, "run", &business, {
            let result = result.clone();
            move |_| async move { Ok(result) }
        })
        .await
        .unwrap();

    let head = server
        .dispatch(
            "run",
            object(json!({
                "targets":["offline"],"script":":","request_id":id,
                "options":{"output_view":{"head_lines":1}}
            })),
        )
        .await
        .unwrap();
    let row = &head["results"][0];
    assert_eq!(row["result_id"], result_id);
    assert_eq!(row["exit_code"], 0);
    assert!(row.get("stdout").is_none());
    assert_eq!(row["output_view"]["text"], "alpha\n");
    let next = &row["output_view"]["next_action"];
    let page = server
        .dispatch(
            next["tool"].as_str().unwrap(),
            object(next["arguments"].clone()),
        )
        .await
        .unwrap();
    assert_eq!(page["offset"], 6);
    assert_eq!(page["next_offset"], 12);
    assert_eq!(page["text"], "βeta\n");

    let search = server
        .dispatch(
            "run",
            object(json!({
                "targets":["offline"],"script":":","request_id":id,"detail":"full",
                "options":{"output_view":{"stream":"stderr","pattern":"[ERR]"}}
            })),
        )
        .await
        .unwrap();
    assert_eq!(search["duplicate"], true);
    assert_eq!(search["execution_replayed"], false);
    assert_eq!(search["results"][0]["result_id"], result_id);
    assert_eq!(
        search["results"][0]["output_view"]["matches"][0]["offset"],
        7
    );
    assert_eq!(search["results"][0]["output_view"]["eof"], true);
    let plain = server
        .dispatch(
            "run",
            object(json!({
                "targets":["offline"],"script":":","request_id":id,"detail":"full"
            })),
        )
        .await
        .unwrap();
    assert_eq!(plain["results"], result["results"]);
    assert!(plain["results"][0].get("output_view").is_none());

    let invalid = server
        .dispatch(
            "run",
            object(json!({
                "targets":["offline"],"script":":","request_id":id,
                "options":{"output_view":{"head_lines":1,"pattern":"[ERR]"}}
            })),
        )
        .await
        .unwrap_err();
    assert!(invalid.message().contains("output_view"));
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("object")
}
