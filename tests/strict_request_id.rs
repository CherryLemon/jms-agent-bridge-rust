//! Strict-policy contract; this fixture has no real target or credentials.
use jms_bridge::{mcp::BridgeServer, runtime::BridgeRuntime};
use serde_json::json;

#[tokio::test]
async fn strict_policy_rejects_before_dispatch_and_reconciles_both_terminal_close_facades() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[bastion]\nurl = 'http://127.0.0.1:1'\n[bridge]\nstate_dir = '{}'\nrequire_request_id = true\n",
            dir.path().join("state").display()
        ),
    ).unwrap();
    let runtime = BridgeRuntime::start(Some(&config), false).await.unwrap();
    let server = BridgeServer::new(runtime.clone());
    assert!(runtime.settings.require_request_id);
    for (tool, args, path) in [
        ("run", json!({"targets":["fixture"],"script_path":"/never-read"}), "/request_id"),
        ("fs", json!({"action":"download","target":"fixture","path":"/source","options":{"local_path":"/unused","timeout":50}}), "/request_id"),
        ("terminal", json!({"action":"open","target":"fixture"}), "/options/request_id"),
        ("terminal", json!({"action":"exec","session":"unallocated","script":"true"}), "/options/request_id"),
        ("terminal", json!({"action":"write","session":"unallocated","options":{"eof":true}}), "/options/request_id"),
        ("terminal", json!({"action":"close","session":"unallocated"}), "/options/request_id"),
        ("job", json!({"action":"submit","targets":["fixture"],"command":"true"}), "/request_id"),
        ("job", json!({"action":"cancel","target":"fixture","job_id":"abcd1234"}), "/request_id"),
        ("call", json!({"operation":"jms_job_cancel","arguments":{"host":"fixture","job_id":"abcd1234"}}), "/request_id"),
        ("call", json!({"operation":"jms_fs","arguments":{"action":"upload","target":"fixture","path":"/remote","local_path":"/not-read"}}), "/arguments/request_id"),
        ("call", json!({"operation":"terminal_write","arguments":{"session":"unallocated","signal":"INT"}}), "/arguments/request_id"),
        ("call", json!({"operation":"jms_exec","arguments":{"targets":["fixture"],"command":"true"}}), "/request_id"),
        ("call", json!({"operation":"session_close","arguments":{"target":"fixture","session_id":"unallocated"}}), "/request_id"),
    ] {
        let error = server.dispatch(tool, args.as_object().unwrap().clone()).await.unwrap_err();
        assert!(error.message().contains("strict request ID"), "{tool} {args}: {error:?}");
        let jms_bridge::errors::BridgeError::InvalidArguments { validation, .. } = error else {
            panic!("expected structured validation");
        };
        assert_eq!(validation["path"], path);
    }
    assert_eq!(runtime.journal.active_tasks(), 0);
    for (tool, args) in [
        ("terminal", json!({"action":"read","session":"missing"})),
        ("fs", json!({"action":"stat","target":"*","path":"/file"})),
        ("job", json!({"action":"wait","targets":["all"],"job_id":"invalid"})),
    ] {
        let error = server.dispatch(tool, args.as_object().unwrap().clone()).await.unwrap_err();
        assert!(!error.message().contains("strict request ID"), "{error:?}");
    }
    let identity = json!({"session":"synthetic","expected_result_id":null});
    let id = "strict-seeded-close";
    runtime.journal.execute(id, "terminal_close", &identity, |_| async {
        Ok(json!({"ok":true,"test_fixture":true}))
    }).await.unwrap();
    for (tool, args) in [
        ("terminal", json!({"action":"close","session":"synthetic","options":{"request_id":id},"detail":"full"})),
        ("call", json!({"operation":"terminal_close","arguments":{"session":"synthetic","request_id":id},"detail":"full"})),
    ] {
        let reply = server.dispatch(tool, args.as_object().unwrap().clone()).await.unwrap();
        assert_eq!(reply["test_fixture"], true, "{reply}");
        assert_eq!(reply["duplicate"], true);
        assert_eq!(reply["execution_replayed"], false);
    }
}

#[tokio::test]
async fn legacy_exec_local_result_failure_is_not_started_and_reconciles_without_replay() {
    use axum::{extract::Path, routing::get, Json, Router};
    const FIRST: &str = "11111111-1111-1111-1111-111111111111";
    const SECOND: &str = "22222222-2222-2222-2222-222222222222";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/api/v1/perms/users/my/assets/", get(|| async {
            Json(json!({"count":2,"next":null,"results":[{"id":FIRST},{"id":SECOND}]}))
        }))
        .route("/api/v1/perms/users/my/assets/{id}/", get(|Path(id): Path<String>| async move {
            Json(json!({"id":id, "name":id, "address":id, "is_active":true,
                "permed_accounts":[{"username":"fixture","has_secret":true}],
                "permed_protocols":[{"name":"ssh"}]}))
        }));
    let mock = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let state = dir.path().join("state");
    std::fs::write(&config, format!(
        "[bastion]\nurl = 'http://{address}'\nssh_port = 1\nlogin_user = 'fixture'\nsession_token = 'offline'\n[bridge]\nstate_dir = '{}'\n",
        state.display()
    )).unwrap();
    let runtime = BridgeRuntime::start(Some(&config), false).await.unwrap();
    let server = BridgeServer::new(runtime.clone());
    let results = state.join("results");
    std::fs::remove_dir(&results).unwrap();
    std::fs::write(&results, "").unwrap();
    let request = json!({"operation":"jms_exec","request_id":"local-store-failure",
        "arguments":{"targets":[FIRST, SECOND],"command":"true"}, "detail":"full"});
    let first = server.dispatch("call", request.as_object().unwrap().clone()).await.unwrap();
    assert_eq!(first["request_state"], "complete", "{first}");
    assert_eq!(first["completion_unknown"], false, "{first}");
    assert_eq!(first["results"].as_array().unwrap().len(), 1);
    assert_eq!(first["results"][0]["failure_stage"], "results");
    assert_eq!(first["results"][0]["execution_state"], "not_started");
    assert_eq!(first["results"][0]["executed"], false);
    assert_eq!(first["results"][0]["completion_unknown"], false);
    let mut unkeyed = request.as_object().unwrap().clone();
    unkeyed.remove("request_id");
    assert!(server.dispatch("call", unkeyed).await.is_err());
    drop(server);
    drop(runtime);
    std::fs::remove_file(&results).unwrap();
    let reopened = BridgeRuntime::start(Some(&config), false).await.unwrap();
    // If the request were rerun, the new result store would allow a result to
    // be created. Reconciliation neither contacts the fixture nor starts work.
    mock.abort();
    let duplicate = BridgeServer::new(reopened.clone())
        .dispatch("call", request.as_object().unwrap().clone()).await.unwrap();
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(duplicate["execution_replayed"], false);
    assert_eq!(duplicate["results"], first["results"]);
    assert_eq!(std::fs::read_dir(&results).unwrap().count(), 0);
}
