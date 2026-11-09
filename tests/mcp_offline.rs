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

    runtime.shutdown().await;
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("object")
}
