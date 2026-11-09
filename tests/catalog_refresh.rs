//! A snapshot refresh must never shrink because one detail request failed.
//!
//! The mock bastion serves the same list every time and lets the test decide how a
//! single asset detail answers: 200, 500 (transient) or 404 (permission revoked).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
                async move {
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
