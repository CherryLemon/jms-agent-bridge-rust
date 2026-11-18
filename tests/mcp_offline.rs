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

    // Six tools stay advertised, with closed schemas.
    let tools = server.tool_specs();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(
        names,
        vec![
            "run",
            "fs",
            "terminal",
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
    assert_eq!(
        reply,
        json!({
            "unchanged": true, "etag": tag, "catalog_version": page["catalog_version"],
        })
    );

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
    }
    http.abort();

    runtime.shutdown().await;
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("object")
}
