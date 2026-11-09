//! Manual SSH pipe check: `cat` echoes what the exec channel writes.
//!
//! Ignored by default because it needs a live bastion; run with:
//! `cargo test --test ssh_pipe -- --ignored --nocapture` and the usual
//! `JMS_BRIDGE_*` environment (config path, credentials, proxy).

use std::sync::Arc;
use std::time::Duration;

use jms_bridge::config::{load_config, load_settings};
use jms_bridge::rest::AssetCatalog;
use jms_bridge::transport::ssh::{ShellEvent, SshPool};

#[tokio::test]
#[ignore]
async fn exec_channel_pipes_bytes_both_ways() {
    jms_bridge::tls::install_default_provider();
    let cfg = Arc::new(load_config(None).expect("config"));
    let settings = Arc::new(load_settings(None).expect("settings"));
    let catalog = AssetCatalog::new(cfg.clone(), settings.clone()).expect("catalog");
    let inventory = catalog.ensure().await.expect("inventory");
    let target = std::env::var("JMS_TEST_TARGET")
        .expect("set JMS_TEST_TARGET to one permitted asset name or address");
    let hosts = inventory.resolve(&[target]).expect("target");
    let host = hosts.into_iter().next().expect("one host");
    let pool = SshPool::new(cfg, settings);
    let connection = pool.connection(&host).await.expect("connection");

    let shell = connection.open_shell("cat").await.expect("exec cat");
    let (writer, mut reader) = shell.split();
    writer.write(b"hello-over-exec\n").await.expect("write");
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while seen.len() < 16 && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), reader.next()).await {
            Ok(Some(ShellEvent::Data(data))) => seen.extend_from_slice(&data),
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        }
    }
    println!("ECHO: {:?}", String::from_utf8_lossy(&seen));
    assert!(String::from_utf8_lossy(&seen).contains("hello-over-exec"));

    // A real rsync handshake is exercised end to end by `fs` upload/download.
    pool.close().await;
}
