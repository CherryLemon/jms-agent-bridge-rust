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
