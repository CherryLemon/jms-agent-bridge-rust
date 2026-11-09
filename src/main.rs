//! Command line entry point: serve the MCP surface, diagnose, or act as an rsync relay.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use jms_bridge::errors::BridgeError;
use jms_bridge::runtime::BridgeRuntime;

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    // rsync spawns this binary with `-e`; the relay must not start a runtime.
    if arguments.get(1).map(String::as_str) == Some("rsync-relay") {
        std::process::exit(jms_bridge::transport::rsync::relay_main(&arguments[1..]));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = runtime.block_on(run(arguments));
    std::process::exit(code);
}

async fn run(arguments: Vec<String>) -> i32 {
    init_tracing();
    let command = arguments.get(1).map(String::as_str).unwrap_or("serve");
    let flags = Flags::parse(&arguments[2..]);
    let result = match command {
        "serve" => serve(flags).await,
        "doctor" => doctor(flags).await,
        "probe" => probe(flags).await,
        "version" | "--version" | "-V" => {
            println!("{}", jms_bridge::version());
            return 0;
        }
        "help" | "--help" | "-h" => {
            print_help();
            return 0;
        }
        other => Err(BridgeError::invalid(format!(
            "unknown command {other:?}; run `jms-bridge help`"
        ))),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("jms-bridge: {}", error.message());
            1
        }
    }
}

fn init_tracing() {
    let filter = std::env::var("JMS_LOG").unwrap_or_else(|_| "info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .try_init();
}

struct Flags {
    config: Option<std::path::PathBuf>,
    stdio: bool,
    host: String,
    port: u16,
    target: String,
    take_lock: bool,
}

impl Flags {
    fn parse(arguments: &[String]) -> Self {
        let mut flags = Flags {
            config: None,
            stdio: false,
            host: "127.0.0.1".to_string(),
            port: 8766,
            target: "all".to_string(),
            take_lock: true,
        };
        let mut index = 0;
        while index < arguments.len() {
            let argument = arguments[index].clone();
            let mut take = |name: &str| -> Option<String> {
                if index + 1 < arguments.len() {
                    index += 1;
                    Some(arguments[index].clone())
                } else {
                    eprintln!("jms-bridge: {name} needs a value");
                    None
                }
            };
            match argument.as_str() {
                "--config" => flags.config = take("--config").map(std::path::PathBuf::from),
                "--stdio" => flags.stdio = true,
                "--host" => {
                    if let Some(value) = take("--host") {
                        flags.host = value;
                    }
                }
                "--port" => {
                    if let Some(value) = take("--port") {
                        if let Ok(port) = value.parse() {
                            flags.port = port;
                        }
                    }
                }
                "--target" => {
                    if let Some(value) = take("--target") {
                        flags.target = value;
                    }
                }
                "--no-lock" => flags.take_lock = false,
                _ => {}
            }
            index += 1;
        }
        flags
    }
}

fn print_help() {
    println!(
        "jms-bridge {}\n\
\n\
USAGE:\n\
  jms-bridge serve [--stdio] [--config PATH] [--host 127.0.0.1] [--port 8766]\n\
  jms-bridge doctor [--config PATH]\n\
  jms-bridge probe [--target SELECTOR] [--config PATH]\n\
  jms-bridge rsync-relay SOCKET (internal)\n\
\n\
The default transport is streamable HTTP on 127.0.0.1:8766 at /mcp.\n\
Credentials come from ~/.config/jms-bridge/config.toml and credentials.toml.",
        jms_bridge::version()
    );
}

async fn serve(flags: Flags) -> Result<(), BridgeError> {
    let runtime = BridgeRuntime::start(flags.config.as_deref(), flags.take_lock).await?;
    if flags.stdio {
        let server = jms_bridge::mcp::BridgeServer::new(runtime.clone());
        tracing::info!(version = jms_bridge::version(), "serving MCP over stdio");
        let service = rmcp::ServiceExt::serve(server, rmcp::transport::stdio())
            .await
            .map_err(|error| BridgeError::ssh(format!("stdio transport failed: {error}")))?;
        let _ = service.waiting().await;
        runtime.shutdown().await;
        return Ok(());
    }
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    let mut config = StreamableHttpServerConfig::default();
    // Stateless JSON responses: no session to lose when a client reconnects.
    config.legacy_session_mode = false;
    config.json_response = true;
    let service: StreamableHttpService<jms_bridge::mcp::BridgeServer, LocalSessionManager> =
        StreamableHttpService::new(
            {
                let runtime = runtime.clone();
                move || Ok(jms_bridge::mcp::BridgeServer::new(runtime.clone()))
            },
            Arc::new(LocalSessionManager::default()),
            config,
        );
    let status_runtime = runtime.clone();
    let router = axum::Router::new()
        .route(
            "/healthz",
            axum::routing::get(|| async {
                axum::Json(json!({"ok": true, "version": jms_bridge::version()}))
            }),
        )
        .route(
            "/service",
            axum::routing::get(move || {
                let runtime = status_runtime.clone();
                async move { axum::Json(runtime.status().await) }
            }),
        )
        .nest_service("/mcp", service);
    let address = format!("{}:{}", flags.host, flags.port);
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .map_err(|error| BridgeError::config(format!("cannot listen on {address}: {error}")))?;
    tracing::info!(
        version = jms_bridge::version(),
        address = address.as_str(),
        "serving MCP over streamable HTTP at /mcp"
    );
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown requested");
    };
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|error| BridgeError::config(format!("HTTP server failed: {error}")))?;
    runtime.shutdown().await;
    Ok(())
}

async fn doctor(flags: Flags) -> Result<(), BridgeError> {
    let runtime = BridgeRuntime::start(flags.config.as_deref(), false).await?;
    println!("jms-bridge {}", jms_bridge::version());
    println!("bastion: {}", runtime.cfg.url);
    println!("ssh port: {}", runtime.cfg.ssh_port);
    println!(
        "login user: {}",
        runtime
            .cfg
            .login_user
            .clone()
            .unwrap_or_else(|| "-".to_string())
    );
    println!("state dir: {}", runtime.settings.state_dir.display());
    match runtime.catalog.probe_health(Duration::from_secs(10)).await {
        Ok(value) => println!("/api/health/: OK {value}"),
        Err(error) => {
            println!("/api/health/: FAIL {}", error.message());
            match runtime.catalog.probe_version(Duration::from_secs(10)).await {
                Ok(Some(version)) => println!("settings/public/open/: OK version {version}"),
                Ok(None) => println!("settings/public/open/: no version field"),
                Err(error) => println!("settings/public/open/: FAIL {}", error.message()),
            }
        }
    }
    match runtime.catalog.ensure().await {
        Ok(inventory) => {
            println!("inventory: {} permitted assets", inventory.hosts.len());
            let status = runtime.catalog.status();
            println!("snapshot: {status}");
        }
        Err(error) => println!("inventory: FAIL {}", error.message()),
    }
    runtime.shutdown().await;
    Ok(())
}

async fn probe(flags: Flags) -> Result<(), BridgeError> {
    let runtime = BridgeRuntime::start(flags.config.as_deref(), false).await?;
    let arguments = json!({
        "targets": [flags.target],
        "script": "uname -s; uname -m",
        "timeout": 30,
        "max_output_bytes": 4096,
    });
    let value = runtime
        .tool_run(
            arguments
                .as_object()
                .cloned()
                .ok_or_else(|| BridgeError::invalid("probe arguments"))?,
        )
        .await?;
    println!("{}", summarize(&value));
    runtime.shutdown().await;
    Ok(())
}

/// One-line JSON diagnostic used by `probe` and operators.
pub fn summarize(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}
