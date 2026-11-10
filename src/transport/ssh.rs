//! Process-owned SSH connections: pooled, generation-tracked and never shared blindly.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::known_hosts::check_known_hosts_path;
use russh::keys::{ssh_key, PrivateKey, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, Disconnect, Sig};
use tokio::sync::mpsc;

use crate::config::{BastionConfig, BridgeSettings};
use crate::errors::{BridgeError, BridgeResult};
use crate::inventory::Host;

/// A stream that can carry an SSH handshake (plain TCP, HTTP tunnel or proxy process).
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncStream for T {}

/// One item routed from a channel's read half to its consumer.
#[derive(Debug)]
pub enum ShellEvent {
    Data(Bytes),
    ExtData(Bytes),
    Exit(i32),
    /// The remote stopped writing but may still report an exit status.
    Eof,
    /// The remote refused the exec request itself.
    ExecRejected,
    Closed,
}

struct ClientHandler {
    host: String,
    port: u16,
    known_hosts: PathBuf,
}

#[derive(Debug)]
pub struct HandlerError(String);

impl From<russh::Error> for HandlerError {
    fn from(error: russh::Error) -> Self {
        Self(error.to_string())
    }
}

impl std::fmt::Display for HandlerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for HandlerError {}

impl client::Handler for ClientHandler {
    type Error = HandlerError;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Fail closed: an unknown or changed key is never accepted silently.
        match check_known_hosts_path(&self.host, self.port, server_public_key, &self.known_hosts) {
            Ok(true) => Ok(true),
            Ok(false) => Err(HandlerError(format!(
                "host key for {}:{} is not in {}; add it deliberately (ssh-keyscan -p {}) \
before connecting",
                self.host,
                self.port,
                self.known_hosts.display(),
                self.port
            ))),
            Err(error) => Err(HandlerError(format!(
                "host key verification against {} failed: {error}",
                self.known_hosts.display()
            ))),
        }
    }
}

pub struct SshConnection {
    pub key: String,
    pub generation: u64,
    handle: Arc<Handle<ClientHandler>>,
}

impl SshConnection {
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub async fn open_shell(&self, command: &str) -> BridgeResult<ChannelShell> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|error| BridgeError::ssh(format!("channel open failed: {error}")))?;
        channel
            .exec(true, command.as_bytes().to_vec())
            .await
            .map_err(|error| BridgeError::ssh(format!("exec request failed: {error}")))?;
        Ok(ChannelShell::new(channel))
    }

    pub async fn close(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "")
            .await;
    }
}

/// One session channel, split so reads and writes can run concurrently.
pub struct ChannelShell {
    pub writer: ChannelWriter,
    pub reader: ChannelReader,
}

pub struct ChannelWriter {
    inner: russh::ChannelWriteHalf<Msg>,
    closed: Arc<AtomicBool>,
}

pub struct ChannelReader {
    events: mpsc::Receiver<ShellEvent>,
    task: Option<tokio::task::JoinHandle<()>>,
    exit_code: Option<i32>,
    closed: bool,
    rejected: bool,
}

impl ChannelShell {
    fn new(channel: russh::Channel<Msg>) -> Self {
        let (mut read, write) = channel.split();
        let (sender, events) = mpsc::channel(64);
        let task = tokio::spawn(async move {
            loop {
                let message = read.wait().await;
                let event = match message {
                    Some(ChannelMsg::Data { data }) => {
                        ShellEvent::Data(Bytes::copy_from_slice(&data))
                    }
                    Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                        ShellEvent::ExtData(Bytes::copy_from_slice(&data))
                    }
                    // Unrecognized extended data is neither stdout nor stderr.
                    Some(ChannelMsg::ExtendedData { .. }) => continue,
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        ShellEvent::Exit(exit_status as i32)
                    }
                    // `Eof` only ends the byte stream: an exit status can still follow,
                    // so it must not terminate the reader.
                    Some(ChannelMsg::Eof) => ShellEvent::Eof,
                    Some(ChannelMsg::Close) => ShellEvent::Closed,
                    Some(ChannelMsg::OpenFailure(_)) | Some(ChannelMsg::Failure) => {
                        ShellEvent::ExecRejected
                    }
                    Some(_) => continue,
                    None => ShellEvent::Closed,
                };
                let terminal = matches!(event, ShellEvent::Closed | ShellEvent::ExecRejected);
                if sender.send(event).await.is_err() {
                    return;
                }
                if terminal {
                    return;
                }
            }
        });
        Self {
            writer: ChannelWriter {
                inner: write,
                closed: Arc::new(AtomicBool::new(false)),
            },
            reader: ChannelReader {
                events,
                task: Some(task),
                exit_code: None,
                closed: false,
                rejected: false,
            },
        }
    }

    pub fn split(self) -> (ChannelWriter, ChannelReader) {
        (self.writer, self.reader)
    }
}

impl ChannelWriter {
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub async fn write(&self, data: &[u8]) -> BridgeResult<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(BridgeError::ssh("channel is closed"));
        }
        let mut remaining = data;
        while !remaining.is_empty() {
            let before = remaining.len();
            self.inner.data(&mut remaining).await.map_err(|error| {
                self.closed.store(true, Ordering::SeqCst);
                BridgeError::ssh(format!("channel write failed: {error}"))
            })?;
            // A full channel window makes `data` return without progress; yield and
            // retry instead of silently dropping the rest of the buffer.
            if remaining.len() == before {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        Ok(())
    }

    pub async fn write_eof(&self) {
        let _ = self.inner.eof().await;
    }

    pub async fn signal(&self, signal: &str) -> BridgeResult<()> {
        let sig = match signal {
            "INT" => Sig::INT,
            "TERM" => Sig::TERM,
            "HUP" => Sig::HUP,
            "KILL" => Sig::KILL,
            other => {
                return Err(BridgeError::invalid(format!(
                    "unsupported signal {other:?}"
                )))
            }
        };
        self.inner
            .signal(sig)
            .await
            .map_err(|error| BridgeError::ssh(format!("signal failed: {error}")))
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let _ = self.inner.close().await;
    }
}

impl ChannelReader {
    /// Cancel-safe raw receive: the underlying channel receive is cancel safe, so a
    /// `select!` branch may drop this future without losing a packet.
    pub async fn recv(&mut self) -> Option<ShellEvent> {
        self.events.recv().await
    }

    /// Next event from the remote side; `None` once the channel is finished.
    pub async fn next(&mut self) -> Option<ShellEvent> {
        if self.closed {
            return None;
        }
        loop {
            match self.events.recv().await {
                Some(ShellEvent::Exit(code)) => {
                    self.exit_code = Some(code);
                    continue;
                }
                Some(ShellEvent::ExecRejected) => {
                    self.rejected = true;
                    self.closed = true;
                    return Some(ShellEvent::ExecRejected);
                }
                Some(ShellEvent::Closed) | None => {
                    self.closed = true;
                    return None;
                }
                Some(event) => return Some(event),
            }
        }
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn was_rejected(&self) -> bool {
        self.rejected
    }

    pub async fn close(&mut self) {
        self.closed = true;
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for ChannelReader {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub struct SshPool {
    cfg: Arc<BastionConfig>,
    settings: Arc<BridgeSettings>,
    connections: Mutex<HashMap<String, Arc<SshConnection>>>,
    login_gate: tokio::sync::Mutex<()>,
    last_login: Mutex<Option<Instant>>,
    failed_until: Mutex<HashMap<String, Instant>>,
    generations: Mutex<HashMap<String, u64>>,
    sequence: AtomicU64,
    closing: AtomicBool,
}

impl SshPool {
    pub fn new(cfg: Arc<BastionConfig>, settings: Arc<BridgeSettings>) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            settings,
            connections: Mutex::new(HashMap::new()),
            login_gate: tokio::sync::Mutex::new(()),
            last_login: Mutex::new(None),
            failed_until: Mutex::new(HashMap::new()),
            generations: Mutex::new(HashMap::new()),
            sequence: AtomicU64::new(0),
            closing: AtomicBool::new(false),
        })
    }

    pub fn key(&self, host: &Host) -> BridgeResult<String> {
        host.connection_key()
    }

    pub fn generation(&self, key: &str) -> u64 {
        self.generations
            .lock()
            .expect("generation lock")
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }

    /// Reuse a healthy connection, else authenticate a new one.
    pub async fn connection(&self, host: &Host) -> BridgeResult<Arc<SshConnection>> {
        let key = self.key(host)?;
        if let Some(connection) = self.existing(&key) {
            return Ok(connection);
        }
        // One process-wide login gate: JumpServer rate-limits attempts per account.
        let _gate = self.login_gate.lock().await;
        if let Some(connection) = self.existing(&key) {
            return Ok(connection);
        }
        if let Some(until) = self
            .failed_until
            .lock()
            .expect("failure lock")
            .get(&key)
            .copied()
        {
            if Instant::now() < until {
                return Err(BridgeError::config(
                    "previous SSH authentication failed; waiting before another attempt",
                ));
            }
        }
        let pace = {
            let last = *self.last_login.lock().expect("login lock");
            last.map(|last| 5.0 - last.elapsed().as_secs_f64())
                .unwrap_or(0.0)
        };
        if pace > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(pace)).await;
        }
        let connected = self.connect_once(host).await;
        *self.last_login.lock().expect("login lock") = Some(Instant::now());
        match connected {
            Ok(connection) => Ok(connection),
            Err(error) => {
                self.failed_until
                    .lock()
                    .expect("failure lock")
                    .insert(key, Instant::now() + Duration::from_secs(60));
                Err(error)
            }
        }
    }

    fn existing(&self, key: &str) -> Option<Arc<SshConnection>> {
        let connections = self.connections.lock().expect("connection lock");
        let connection = connections.get(key)?;
        if connection.is_closed() {
            return None;
        }
        Some(connection.clone())
    }

    /// TCP stream to the gateway, honouring the deployment's proxy settings.
    async fn open_transport(&self, gateway: &str, port: u16) -> BridgeResult<Box<dyn AsyncStream>> {
        if let Some(argv) = self.settings.ssh_proxy_command.first() {
            return proxy_command_stream(
                argv,
                &self.settings.ssh_proxy_command[1..],
                gateway,
                port,
            )
            .await;
        }
        let proxy = ssh_proxy(&self.settings);
        match proxy {
            Some(proxy) => http_connect_stream(&proxy, gateway, port).await,
            None => {
                let stream = tokio::net::TcpStream::connect((gateway, port))
                    .await
                    .map_err(|error| {
                        BridgeError::ssh(format!(
                            "SSH TCP connection to {gateway}:{port} failed ({error})"
                        ))
                    })?;
                let _ = stream.set_nodelay(true);
                Ok(Box::new(stream))
            }
        }
    }

    async fn connect_once(&self, host: &Host) -> BridgeResult<Arc<SshConnection>> {
        let gateway = self.settings.gateway_host(&self.cfg)?;
        let port = self.cfg.ssh_port;
        let config = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            inactivity_timeout: None,
            nodelay: true,
            ..Default::default()
        });
        // Resolve before the handshake so an unverifiable connection is refused
        // with a configuration error instead of being trusted.
        let known_hosts = self.settings.resolve_known_hosts()?;
        let handler = ClientHandler {
            host: self
                .settings
                .host_key_alias
                .clone()
                .unwrap_or_else(|| gateway.clone()),
            port,
            known_hosts,
        };
        let stream = self.open_transport(&gateway, port).await?;
        let connect = tokio::time::timeout(
            Duration::from_secs(30),
            client::connect_stream(config, stream, handler),
        )
        .await
        .map_err(|_| {
            BridgeError::ssh("SSH connection failed (ConnectTimeout); no automatic login retry")
        })?
        .map_err(|error| {
            BridgeError::ssh(format!(
                "SSH connection failed ({}); no automatic login retry",
                error
            ))
        })?;
        let mut handle = connect;
        let user = host.login_string(self.cfg.login_user.as_deref())?;
        // Authentication must not hang: a gateway waiting on a prompt nobody can
        // answer would otherwise hold the request until the deadline expires. One
        // absolute deadline covers the whole sequence (key lookup, public key,
        // password and every challenge round), not each step separately.
        let mut result: Option<AuthResult> = None;
        let auth_started = Instant::now();
        let auth_total = Duration::from_secs(90);
        let auth_deadline = Duration::from_secs(60);
        let remaining_auth = |stage: &str| -> BridgeResult<Duration> {
            let left = auth_total.saturating_sub(auth_started.elapsed());
            if left.is_zero() {
                return Err(BridgeError::ssh(format!(
                    "SSH authentication timed out during {stage}; the gateway did not finish"
                )));
            }
            Ok(left.min(auth_deadline))
        };
        if let Some(key_path) = &self.cfg.ssh_key {
            let private = load_private_key(key_path)?;
            let window = remaining_auth("the public key exchange")?;
            let hash = tokio::time::timeout(window, handle.best_supported_rsa_hash())
                .await
                .map_err(|_| {
                    BridgeError::ssh(
                        "SSH authentication timed out while negotiating a key algorithm",
                    )
                })?
                .ok()
                .flatten()
                .flatten();
            let window = remaining_auth("public key authentication")?;
            result = Some(
                tokio::time::timeout(
                    window,
                    handle.authenticate_publickey(
                        user.clone(),
                        PrivateKeyWithHashAlg::new(Arc::new(private), hash),
                    ),
                )
                .await
                .map_err(|_| {
                    BridgeError::ssh(
                        "SSH authentication timed out during public key authentication",
                    )
                })?
                .map_err(|error| {
                    BridgeError::ssh(format!("SSH authentication failed ({error})"))
                })?,
            );
        }
        let password = self
            .cfg
            .ssh_password
            .clone()
            .or_else(crate::config::stored_password);
        if !matches!(result, Some(AuthResult::Success)) {
            if let Some(password) = &password {
                let window = remaining_auth("password authentication")?;
                result = Some(
                    tokio::time::timeout(
                        window,
                        handle.authenticate_password(user.clone(), password.clone()),
                    )
                    .await
                    .map_err(|_| {
                        BridgeError::ssh(
                            "SSH authentication timed out during password authentication",
                        )
                    })?
                    .map_err(|error| {
                        BridgeError::ssh(format!("SSH authentication failed ({error})"))
                    })?,
                );
            }
        }
        if !matches!(result, Some(AuthResult::Success)) {
            if let Some(password) = &password {
                // JumpServer may answer with a keyboard-interactive challenge instead of
                // plain password auth; only the password and username prompts are filled in.
                let window = remaining_auth("the interactive challenge")?;
                let mut response = tokio::time::timeout(
                    window,
                    handle.authenticate_keyboard_interactive_start(user.clone(), None::<String>),
                )
                .await
                .map_err(|_| {
                    BridgeError::ssh(
                        "SSH authentication timed out; the gateway did not finish the challenge",
                    )
                })?
                .map_err(|error| {
                    BridgeError::ssh(format!("SSH authentication failed ({error})"))
                })?;
                loop {
                    match response {
                        KeyboardInteractiveAuthResponse::Success => {
                            result = Some(AuthResult::Success);
                            break;
                        }
                        KeyboardInteractiveAuthResponse::Failure { .. } => break,
                        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                            let mut replies: Vec<String> = Vec::new();
                            for prompt in &prompts {
                                let text = prompt.prompt.to_lowercase();
                                if text.contains("password") || text.contains("密码") {
                                    replies.push(password.clone());
                                } else if text.contains("username") || text.contains("login") {
                                    replies.push(user.clone());
                                } else {
                                    replies.push(String::new());
                                }
                            }
                            let window = remaining_auth("an interactive challenge round")?;
                            response = tokio::time::timeout(
                                window,
                                handle.authenticate_keyboard_interactive_respond(replies),
                            )
                            .await
                            .map_err(|_| {
                                BridgeError::ssh(
                                    "SSH authentication timed out; the gateway did not accept the \
credentials",
                                )
                            })?
                            .map_err(|error| {
                                BridgeError::ssh(format!("SSH authentication failed ({error})"))
                            })?;
                        }
                    }
                }
            }
        }
        if !matches!(result, Some(AuthResult::Success)) {
            let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
            return Err(BridgeError::config(
                "SSH authentication failed; configure bastion.ssh_key or JMS_BRIDGE_SSH_PASSWORD",
            ));
        }
        let key = self.key(host)?;
        let generation = {
            let mut generations = self.generations.lock().expect("generation lock");
            let entry = generations.entry(key.clone()).or_insert(0);
            *entry += 1;
            *entry
        };
        let connection = Arc::new(SshConnection {
            key: key.clone(),
            generation,
            handle: Arc::new(handle),
        });
        self.connections
            .lock()
            .expect("connection lock")
            .insert(key, connection.clone());
        self.sequence.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            asset = host.name.as_str(),
            generation,
            "SSH connection established"
        );
        Ok(connection)
    }

    /// Open a shell for `command`, retrying once only before any user script is sent.
    pub async fn open_process(
        &self,
        host: &Host,
        command: &str,
    ) -> BridgeResult<(ChannelShell, bool)> {
        let key = self.key(host)?;
        let previous = self.existing(&key);
        let connection = self.connection(host).await?;
        let reconnected = match &previous {
            Some(previous) => !Arc::ptr_eq(previous, &connection),
            None => false,
        };
        match connection.open_shell(command).await {
            Ok(shell) => Ok((shell, reconnected)),
            Err(error) => {
                // A lost connection is the only failure worth one retry here: the user
                // script has not been transmitted yet, so nothing can be duplicated.
                if !connection.is_closed() {
                    return Err(error);
                }
                connection.close().await;
                self.connections
                    .lock()
                    .expect("connection lock")
                    .remove(&key);
                let replacement = self.connection(host).await?;
                let shell = replacement.open_shell(command).await?;
                Ok((shell, true))
            }
        }
    }

    /// Drop one connection so the next operation authenticates again.
    pub async fn replace(&self, host: &Host) -> BridgeResult<Arc<SshConnection>> {
        let key = self.key(host)?;
        let existing = self
            .connections
            .lock()
            .expect("connection lock")
            .remove(&key);
        if let Some(connection) = existing {
            connection.close().await;
        }
        self.connection(host).await
    }

    pub fn status(&self) -> serde_json::Value {
        let connections = self.connections.lock().expect("connection lock");
        let connected = connections
            .values()
            .filter(|connection| !connection.is_closed())
            .count();
        serde_json::json!({
            "connected": connected,
            "disconnected": connections.len().saturating_sub(connected),
        })
    }

    pub async fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        let connections: Vec<Arc<SshConnection>> = {
            let mut map = self.connections.lock().expect("connection lock");
            map.drain().map(|(_, connection)| connection).collect()
        };
        for connection in connections {
            connection.close().await;
        }
    }
}

fn load_private_key(path: &PathBuf) -> BridgeResult<PrivateKey> {
    PrivateKey::read_openssh_file(path).map_err(|error| {
        BridgeError::config(format!("cannot read SSH key {}: {error}", path.display()))
    })
}

/// Proxy used for the SSH data plane: the bridge setting first, then the environment.
fn ssh_proxy(settings: &BridgeSettings) -> Option<String> {
    if let Some(proxy) = settings.rest_proxy.clone() {
        return Some(proxy);
    }
    for name in [
        "JMS_BRIDGE_SSH_PROXY",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        if let Ok(value) = std::env::var(name) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Blocking-free `CONNECT host:port` tunnel through an HTTP proxy.
async fn http_connect_stream(
    proxy: &str,
    gateway: &str,
    port: u16,
) -> BridgeResult<Box<dyn AsyncStream>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut url = url::Url::parse(proxy)
        .map_err(|error| BridgeError::config(format!("invalid proxy URL: {error}")))?;
    let proxy_host = url
        .host_str()
        .ok_or_else(|| BridgeError::config("proxy URL has no host"))?
        .to_string();
    let proxy_port = url.port_or_known_default().unwrap_or(8080);
    let mut stream = tokio::net::TcpStream::connect((proxy_host.as_str(), proxy_port))
        .await
        .map_err(|error| BridgeError::ssh(format!("proxy connection failed ({error})")))?;
    let credentials = if url.username().is_empty() {
        None
    } else {
        Some(format!(
            "{}:{}",
            url.username(),
            url.password().unwrap_or("")
        ))
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    let mut request = format!(
        "CONNECT {gateway}:{port} HTTP/1.1\r\nHost: {gateway}:{port}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let Some(credentials) = credentials {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| BridgeError::ssh(format!("proxy handshake failed ({error})")))?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|error| BridgeError::ssh(format!("proxy handshake failed ({error})")))?;
        if read == 0 {
            return Err(BridgeError::ssh("proxy closed the tunnel during CONNECT"));
        }
        head.push(byte[0]);
        if head.len() > 8192 {
            return Err(BridgeError::ssh("proxy sent an oversized CONNECT response"));
        }
    }
    let status_line = String::from_utf8_lossy(&head);
    let code = status_line.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(BridgeError::ssh(format!(
            "proxy refused the SSH tunnel (HTTP {code})"
        )));
    }
    Ok(Box::new(stream))
}

/// Stream fed by a child process's stdio, matching the reference `ProxyCommand`.
async fn proxy_command_stream(
    program: &str,
    arguments: &[String],
    gateway: &str,
    port: u16,
) -> BridgeResult<Box<dyn AsyncStream>> {
    let mut child = tokio::process::Command::new(program)
        .args(expand_proxy_arguments(arguments, gateway, port))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| {
            BridgeError::config(format!("cannot run ssh_proxy_command {program:?}: {error}"))
        })?;
    let stdin = child.stdin.take().expect("proxy stdin");
    let stdout = child.stdout.take().expect("proxy stdout");
    Ok(Box::new(ProcessStream {
        reader: stdout,
        writer: stdin,
    }))
}

/// `%h` and `%p` are the OpenSSH placeholders used by ProxyCommand.
fn expand_proxy_arguments(arguments: &[String], gateway: &str, port: u16) -> Vec<String> {
    arguments
        .iter()
        .map(|argument| {
            argument
                .replace("%h", gateway)
                .replace("%p", &port.to_string())
        })
        .collect()
}

struct ProcessStream {
    reader: tokio::process::ChildStdout,
    writer: tokio::process::ChildStdin,
}

impl tokio::io::AsyncRead for ProcessStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(context, buffer)
    }
}

impl tokio::io::AsyncWrite for ProcessStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(context, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(context)
    }
}
