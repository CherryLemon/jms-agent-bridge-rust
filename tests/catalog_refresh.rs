//! A snapshot refresh must never shrink because one detail request failed.
//!
//! The mock bastion serves the same list every time and lets the test decide how a
//! single asset detail answers: 200, 500 (transient) or 404 (permission revoked).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

const ASSET_A: &str = "11111111-1111-1111-1111-111111111111";
const ASSET_B: &str = "22222222-2222-2222-2222-222222222222";

fn detail(id: &str) -> Value {
    json!({
        "id": id,
        "name": if id == ASSET_A { "asset-a" } else { "asset-b" },
        "address": if id == ASSET_A { "10.0.0.1" } else { "10.0.0.2" },
        "is_active": true,
        "permed_accounts": [{"username": "root", "has_secret": true}],
        "permed_protocols": [{"name": "ssh"}],
    })
}

fn router(status: Arc<AtomicUsize>) -> Router {
    router_with_order(status, None)
}

#[derive(Default)]
struct DetailOrder {
    slow: AtomicUsize,
    completed: Mutex<Vec<String>>,
}

fn router_with_order(status: Arc<AtomicUsize>, order: Option<Arc<DetailOrder>>) -> Router {
    Router::new()
        .route(
            "/api/v1/perms/users/my/assets/",
            get(|| async move {
                Json(json!({
                    "count": 2,
                    "next": Value::Null,
                    "results": [
                        {"id": ASSET_A, "name": "asset-a"},
                        {"id": ASSET_B, "name": "asset-b"},
                    ],
                }))
            }),
        )
        .route(
            "/api/v1/perms/users/my/assets/{id}/",
            get(move |Path(id): Path<String>| {
                let status = status.clone();
                let order = order.clone();
                async move {
                    if let Some(order) = order {
                        let slow = if order.slow.load(Ordering::SeqCst) == 0 {
                            ASSET_A
                        } else {
                            ASSET_B
                        };
                        if id == slow {
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                        order.completed.lock().unwrap().push(id.clone());
                    }
                    if id == ASSET_B {
                        match status.load(Ordering::SeqCst) {
                            200 => (StatusCode::OK, Json(detail(&id))),
                            404 => (StatusCode::NOT_FOUND, Json(json!({"detail": "gone"}))),
                            _ => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({"detail": "boom"})),
                            ),
                        }
                    } else {
                        (StatusCode::OK, Json(detail(&id)))
                    }
                }
            }),
        )
}

async fn catalog(
    url: String,
    state_dir: std::path::PathBuf,
) -> Arc<jms_bridge::rest::catalog::AssetCatalog> {
    // The mock listens on loopback; make sure an inherited egress proxy is skipped.
    std::env::set_var("NO_PROXY", "127.0.0.1,localhost,::1");
    let mut cfg = jms_bridge::config::BastionConfig {
        url,
        api_timeout: 5.0,
        ..Default::default()
    };
    cfg.session_token = Some("test-token".into());
    let mut settings = jms_bridge::config::BridgeSettings::default();
    settings.state_dir = state_dir;
    jms_bridge::rest::catalog::AssetCatalog::new(Arc::new(cfg), Arc::new(settings)).unwrap()
}

#[tokio::test]
async fn transient_detail_errors_keep_the_previous_snapshot() {
    let status = Arc::new(AtomicUsize::new(200));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = router(status.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let directory = tempfile::tempdir().unwrap();
    let catalog = catalog(format!("http://{address}"), directory.path().to_path_buf()).await;

    catalog.refresh().await;
    assert_eq!(catalog.snapshot_assets().len(), 2, "initial snapshot");

    // A server error while reading one asset must fail the whole refresh.
    status.store(500, Ordering::SeqCst);
    let result = catalog.refresh().await;
    assert_eq!(
        catalog.snapshot_assets().len(),
        2,
        "a transient detail error must not shrink the snapshot"
    );
    assert!(
        result["last_error"]
            .as_str()
            .unwrap_or("")
            .contains("refresh failed"),
        "the failure must be reported, got {result}"
    );

    // An explicit 404 does mean the asset is gone for this account.
    status.store(404, Ordering::SeqCst);
    catalog.refresh().await;
    assert_eq!(
        catalog.snapshot_assets().len(),
        1,
        "an explicit permission answer removes the asset"
    );
}

#[tokio::test]
async fn multi_account_assets_stay_unresolved_without_a_preference() {
    // The list stays the same; only the account shape changes.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/api/v1/perms/users/my/assets/",
            get(|| async move {
                Json(json!({
                    "count": 1,
                    "next": Value::Null,
                    "results": [{"id": ASSET_A, "name": "asset-a"}],
                }))
            }),
        )
        .route(
            "/api/v1/perms/users/my/assets/{id}/",
            get(|Path(id): Path<String>| async move {
                (
                    StatusCode::OK,
                    Json(json!({
                        "id": id,
                        "name": "asset-a",
                        "address": "10.0.0.1",
                        "is_active": true,
                        "permed_accounts": [
                            {"username": "root", "has_secret": true},
                            {"username": "ops", "has_secret": true},
                        ],
                        "permed_protocols": [{"name": "ssh"}],
                    })),
                )
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let directory = tempfile::tempdir().unwrap();
    let catalog = catalog(format!("http://{address}"), directory.path().to_path_buf()).await;
    catalog.refresh().await;
    let inventory = catalog.ensure().await.unwrap();
    assert!(
        inventory.hosts.is_empty(),
        "two permitted accounts must stay unresolved, got {:?}",
        inventory.hosts
    );
    let reason = catalog.explain_no_targets().unwrap_or_default();
    assert!(
        reason.contains("preferred_account"),
        "the reason must say how to resolve it: {reason}"
    );
}

#[tokio::test]
async fn discover_etag_does_not_hide_failed_refresh_or_revocation() {
    use jms_bridge::mcp::BridgeServer;
    use jms_bridge::runtime::BridgeRuntime;
    use serde_json::Map;

    let state = Arc::new(AtomicUsize::new(200));
    let order = Arc::new(DetailOrder::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = router_with_order(state.clone(), Some(order.clone()));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[bastion]\nurl = \"http://{address}\"\nsession_token = \"offline-token\"\n\
             [bridge]\nstate_dir = {:?}\n",
            directory.path().join("state").display().to_string()
        ),
    )
    .unwrap();
    let runtime = BridgeRuntime::start(Some(&config), false).await.unwrap();
    let server = BridgeServer::new(runtime.clone());
    let initial = runtime.catalog.refresh().await;
    assert_eq!(initial["ok"], true, "{initial}");
    let args = |detail: &str, tag: Option<&str>| -> Map<String, Value> {
        let mut args = json!({"topic":"assets","query":"asset-a","limit":1,"detail":detail});
        if let Some(tag) = tag {
            args["if_none_match"] = json!(tag);
        }
        args.as_object().unwrap().clone()
    };

    // Wait for the initial background refresh, avoiding a race with an in-flight
    // snapshot which this same contract deliberately marks ineligible for a hit.
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let page = server
                .dispatch("discover", args("compact", None))
                .await
                .unwrap();
            if page.get("etag").is_some() {
                break page;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let tag = first["etag"].as_str().unwrap();
    let version = first["inventory_version"].as_str().unwrap();
    assert_eq!(first["matched"], 1);
    let hit = server
        .dispatch("discover", args("compact", Some(tag)))
        .await
        .unwrap();
    assert_eq!(hit["unchanged"], true);
    assert_eq!(hit["inventory_version"], version);
    assert!(hit["last_success"].is_number());

    let full = server
        .dispatch("discover", args("full", Some(tag)))
        .await
        .unwrap();
    assert_ne!(full["etag"], tag);
    assert_eq!(full["assets"][0]["name"], "asset-a");
    assert_eq!(full["inventory_version"], version);

    let args_page = |offset: usize, tag: Option<&str>| -> Map<String, Value> {
        let mut args = json!({"topic":"assets", "limit":1, "offset":offset});
        if let Some(tag) = tag {
            args["if_none_match"] = json!(tag);
        }
        args.as_object().unwrap().clone()
    };
    assert_eq!(
        order.completed.lock().unwrap().last_chunk::<2>().unwrap(),
        &[ASSET_B, ASSET_A],
    );
    let mut before = Vec::new();
    for (offset, id) in [ASSET_A, ASSET_B].iter().enumerate() {
        let page = server
            .dispatch("discover", args_page(offset, None))
            .await
            .unwrap();
        assert_eq!(page["assets"][0]["id"], *id);
        before.push(page);
    }
    assert_eq!(before[0]["next_offset"], 1);
    assert!(before[1]["next_offset"].is_null());

    order.completed.lock().unwrap().clear();
    order.slow.store(1, Ordering::SeqCst);
    assert_eq!(runtime.catalog.refresh().await["ok"], true);
    assert_eq!(
        order.completed.lock().unwrap().as_slice(),
        &[ASSET_A, ASSET_B]
    );
    for (offset, previous) in before.iter().enumerate() {
        let tag = previous["etag"].as_str().unwrap();
        let hit = server
            .dispatch("discover", args_page(offset, Some(tag)))
            .await
            .unwrap();
        assert_eq!(hit["unchanged"], true);
        assert_eq!(hit["inventory_version"], previous["inventory_version"]);
        let page = server
            .dispatch("discover", args_page(offset, None))
            .await
            .unwrap();
        assert_eq!(page["etag"], tag);
        assert_eq!(page["assets"], previous["assets"]);
        assert_eq!(page["next_offset"], previous["next_offset"]);
    }

    state.store(500, Ordering::SeqCst);
    assert_eq!(runtime.catalog.refresh().await["ok"], false);
    let failed = server
        .dispatch("discover", args("compact", Some(tag)))
        .await
        .unwrap();
    assert!(failed["inventory_error"]
        .as_str()
        .unwrap()
        .contains("refresh failed"));
    assert!(failed.get("etag").is_none());
    assert!(failed.get("unchanged").is_none());

    // The queried page contains only asset A and is unchanged, but revoking B
    // must invalidate the tag because authorization is scoped to the snapshot.
    state.store(404, Ordering::SeqCst);
    assert_eq!(runtime.catalog.refresh().await["ok"], true);
    let revoked = server
        .dispatch("discover", args("compact", Some(tag)))
        .await
        .unwrap();
    assert_eq!(revoked["assets"], first["assets"]);
    assert_ne!(revoked["inventory_version"], version);
    assert_ne!(revoked["etag"], tag);
    assert!(revoked.get("unchanged").is_none());
    runtime.shutdown().await;
}
