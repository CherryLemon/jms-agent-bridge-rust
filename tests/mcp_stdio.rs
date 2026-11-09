//! The stdio transport must keep stdout free of anything but MCP messages.
//!
//! The unit tests call `dispatch()` directly, so they cannot see a log line that
//! `main` writes to stdout before the protocol starts.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

struct Session {
    child: std::process::Child,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Session {
    fn start() -> (Session, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[bastion]\nurl = \"https://bastion.invalid\"\nssh_port = 2224\n\n\
                 [bridge]\nstate_dir = {:?}\n",
                directory.path().join("state").to_string_lossy()
            ),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_jms-bridge"))
            .args([
                "serve",
                "--stdio",
                "--no-lock",
                "--config",
                config.to_str().unwrap(),
            ])
            .env("JMS_LOG", "info")
            .env("JMS_BRIDGE_CONFIG", &config)
            .env("JMS_BRIDGE_STATE_DIR", directory.path().join("state"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("binary starts");
        let stdout = BufReader::new(child.stdout.take().unwrap());
        (Session { child, stdout }, directory)
    }

    fn send(&mut self, message: serde_json::Value) {
        let stdin = self.child.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    /// Every stdout line must parse as a JSON-RPC message; anything else breaks clients.
    fn receive(&mut self) -> serde_json::Value {
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line).expect("stdout readable");
        assert!(read > 0, "server closed stdout instead of answering");
        serde_json::from_str::<serde_json::Value>(line.trim()).unwrap_or_else(|error| {
            panic!("stdout carried a non-protocol line ({error}): {line:?}")
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn stdio_stdout_carries_only_mcp_messages() {
    let (mut session, _directory) = Session::start();
    session.send(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "stdio-test", "version": "0"},
        },
    }));
    let init = session.receive();
    assert_eq!(init["result"]["serverInfo"]["name"], "jms-bridge");

    session.send(serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }));
    session.send(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    }));
    let tools = session.receive();
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(
        names,
        [
            "run",
            "fs",
            "terminal",
            "read_result",
            "discover",
            "call",
            "meta"
        ]
    );

    session.send(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "meta", "arguments": {}},
    }));
    let meta = session.receive();
    let text = meta["result"]["content"][0]["text"]
        .as_str()
        .expect("tool result text");
    let value: serde_json::Value = serde_json::from_str(text).expect("compact JSON");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}
