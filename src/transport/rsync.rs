//! System `rsync` driven through the bridge's own SSH connection.
//!
//! `rsync -e "<this binary> rsync-relay <socket>"` asks the relay (a child of the local
//! rsync) to hand its byte stream to the service over a private Unix socket. The service
//! validates the asset, opens the remote `rsync --server` channel on the pooled
//! connection, and pumps bytes between socket and channel. No ControlMaster, no second
//! authentication, and no shell is created for the transfer.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex as AsyncMutex;

use crate::errors::{BridgeError, BridgeResult};
use crate::inventory::Host;
use crate::transport::ssh::{ShellEvent, SshPool};

const INSTALL_HINT: &str =
    "Install rsync 3.x (on macOS: brew install rsync) and put it first on PATH.";

/// Emitted by the remote shell wrapper before it `exec`s the rsync server.
const READY_MARKER: &str = "\u{1e}JMSRSYNCREADY\u{1f}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Push,
    Pull,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Push => "push",
            Direction::Pull => "pull",
        }
    }
}

/// One private socket per transfer; removed even when the transfer fails.
pub struct RsyncRelay {
    pub socket: PathBuf,
    directory: PathBuf,
}

impl RsyncRelay {
    pub fn create() -> BridgeResult<Self> {
        let directory =
            std::env::temp_dir().join(format!("jms-rsync-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
        }
        let socket = directory.join("stream.sock");
        Ok(Self { socket, directory })
    }
}

impl Drop for RsyncRelay {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Resolve and validate the local rsync once per resident process.
pub struct RsyncBinary {
    validated: AsyncMutex<Option<(PathBuf, u64, u64, u64)>>,
}

impl Default for RsyncBinary {
    fn default() -> Self {
        Self {
            validated: AsyncMutex::new(None),
        }
    }
}

impl RsyncBinary {
    pub async fn resolve(&self) -> BridgeResult<PathBuf> {
        let mut guard = self.validated.lock().await;
        let binary = find_on_path("rsync").ok_or_else(|| {
            BridgeError::config(format!(
                "Local rsync is not installed or not executable on PATH. {INSTALL_HINT}"
            ))
        })?;
        let binary = std::fs::canonicalize(&binary).unwrap_or(binary);
        let identity = identity_of(&binary)?;
        if let Some((cached, device, inode, size)) = guard.as_ref() {
            if *cached == binary && (*device, *inode, *size) == identity {
                return Ok(binary);
            }
        }
        let output = std::process::Command::new(&binary)
            .arg("-s")
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .map_err(|error| {
                BridgeError::config(format!(
                    "Cannot run local rsync capability check at {} ({error}); check the installation and permissions. Transfer not started.",
                    binary.display()
                ))
            })?;
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let lowered = combined.to_lowercase();
        if lowered.contains("openrsync") || unsupported_protect_args(&lowered) {
            return Err(BridgeError::config(format!(
                "Local rsync at {} does not support --protect-args (-s), required by compact transfers. {INSTALL_HINT} Transfer not started.",
                binary.display()
            )));
        }
        if !output.status.success() {
            return Err(BridgeError::config(format!(
                "Local rsync capability check (-s --version) failed at {} with exit code {:?}; support could not be verified. Check the installation. Transfer not started.",
                binary.display(),
                output.status.code()
            )));
        }
        let major = parse_major_version(&combined).ok_or_else(|| {
            BridgeError::config(format!(
                "Local rsync capability check at {} returned unrecognized version output; support could not be verified. Transfer not started.",
                binary.display()
            ))
        })?;
        if major < 3 {
            return Err(BridgeError::config(format!(
                "Local rsync at {} is older than 3.0 and lacks --protect-args (-s). {INSTALL_HINT} Transfer not started.",
                binary.display()
            )));
        }
        if identity_of(&binary)? != identity {
            return Err(BridgeError::config(
                "Local rsync changed during its capability check; retry before transferring. Transfer not started.",
            ));
        }
        *guard = Some((binary.clone(), identity.0, identity.1, identity.2));
        Ok(binary)
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(&candidate) {
                    if metadata.permissions().mode() & 0o111 != 0 {
                        return Some(candidate);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                return Some(candidate);
            }
        }
    }
    None
}

fn identity_of(path: &Path) -> BridgeResult<(u64, u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).map_err(|error| {
        BridgeError::config(format!(
            "Cannot inspect local rsync at {} ({error}); check the installation and permissions. Transfer not started.",
            path.display()
        ))
    })?;
    Ok((metadata.dev(), metadata.ino(), metadata.size()))
}

fn unsupported_protect_args(text: &str) -> bool {
    for line in text.lines() {
        let lowered = line.to_lowercase();
        if (lowered.contains("invalid option")
            || lowered.contains("illegal option")
            || lowered.contains("unknown option")
            || lowered.contains("unrecognized option")
            || lowered.contains("unsupported option"))
            && (lowered.contains("--protect-args")
                || lowered.contains("--secluded-args")
                || lowered.contains("-s"))
        {
            return true;
        }
    }
    false
}

fn parse_major_version(text: &str) -> Option<u64> {
    for line in text.lines() {
        let trimmed = line.trim();
        let lowered = trimmed.to_lowercase();
        if let Some(rest) = lowered.strip_prefix("rsync  version ") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            return digits.parse().ok();
        }
        if let Some(rest) = lowered.strip_prefix("rsync version ") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            return digits.parse().ok();
        }
    }
    None
}

/// Outcome of the rsync child plus the evidence needed for the result's state.
pub struct TransferOutcome {
    pub exit_code: i32,
    pub sent: bool,
    pub completed: bool,
    pub timed_out: bool,
}

/// Run one rsync transfer through the pooled connection.
#[allow(clippy::too_many_arguments)]
pub async fn transfer(
    pool: &Arc<SshPool>,
    binary: &Path,
    host: &Host,
    local: &str,
    remote: &str,
    direction: Direction,
    excludes: &[String],
    delete: bool,
    timeout: f64,
    container: Option<&str>,
    overwrite: bool,
    out_path: &Path,
    err_path: &Path,
) -> BridgeResult<TransferOutcome> {
    if let Some(container) = container {
        if container.is_empty()
            || container.len() > 128
            || !container
                .chars()
                .next()
                .map(|c| c.is_ascii_alphanumeric())
                .unwrap_or(false)
            || !container
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            return Err(BridgeError::invalid("invalid existing container name/ID"));
        }
    }
    let relay = RsyncRelay::create()?;
    let listener = UnixListener::bind(&relay.socket).map_err(|error| {
        BridgeError::storage(format!("cannot bind rsync relay socket: {error}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&relay.socket, std::fs::Permissions::from_mode(0o600));
    }
    let asset_id = host
        .asset_id
        .clone()
        .ok_or_else(|| BridgeError::config("target needs a permitted REST asset ID"))?;
    let sent = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let accept = {
        let pool = pool.clone();
        let host = host.clone();
        let asset_id = asset_id.clone();
        let container = container.map(str::to_string);
        let sent = sent.clone();
        let stop = stop.clone();
        let err_path = err_path.to_path_buf();
        tokio::spawn(async move {
            while !stop.load(Ordering::SeqCst) {
                let accept =
                    tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
                let Ok(Ok((stream, _))) = accept else {
                    continue;
                };
                if let Err(error) = serve_stream(
                    &pool,
                    &host,
                    &asset_id,
                    container.as_deref(),
                    stream,
                    &err_path,
                    &sent,
                )
                .await
                {
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(&err_path)
                    {
                        let _ = writeln!(file, "Transport stream failed ({})", error.message());
                    }
                }
            }
        })
    };
    let mut command = std::process::Command::new(binary);
    command.arg("-azs");
    let relay_cmd = format!(
        "{} rsync-relay {}",
        crate::fsprobe::shlex_quote(
            &std::env::current_exe()
                .unwrap_or_else(|_| PathBuf::from("jms-bridge"))
                .to_string_lossy()
        ),
        crate::fsprobe::shlex_quote(&relay.socket.to_string_lossy())
    );
    command.arg("-e").arg(relay_cmd);
    if !overwrite {
        command.arg("--ignore-existing");
    }
    command.arg("--itemize-changes");
    if delete {
        command.arg("--delete");
    }
    for pattern in excludes {
        command.arg("--exclude").arg(pattern);
    }
    command.arg("--");
    let spec = format!("{asset_id}:{remote}");
    match direction {
        Direction::Push => {
            command.arg(local).arg(&spec);
        }
        Direction::Pull => {
            command.arg(&spec).arg(local);
        }
    }
    let out = std::fs::File::create(out_path)?;
    let err = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(err_path)?;
    command.stdout(Stdio::from(out)).stderr(Stdio::from(err));
    command.stdin(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|error| BridgeError::config(format!("cannot start local rsync: {error}")))?;
    let waited = tokio::time::timeout(Duration::from_secs_f64(timeout.max(0.5)), async {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok::<_, std::io::Error>(status.code().unwrap_or(255)),
                Ok(None) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(error) => return Err(error),
            }
        }
    })
    .await;
    stop.store(true, Ordering::SeqCst);
    let outcome = match waited {
        Ok(Ok(code)) => TransferOutcome {
            exit_code: code,
            sent: sent.load(Ordering::SeqCst),
            completed: true,
            timed_out: false,
        },
        Ok(Err(error)) => {
            let _ = child.kill();
            return Err(BridgeError::storage(format!("rsync failed: {error}")));
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            TransferOutcome {
                exit_code: 124,
                sent: sent.load(Ordering::SeqCst),
                completed: false,
                timed_out: true,
            }
        }
    };
    // Give the relay task a moment to observe the stop flag and close its channels.
    let _ = tokio::time::timeout(Duration::from_secs(2), accept).await;
    Ok(outcome)
}

async fn serve_stream(
    pool: &Arc<SshPool>,
    host: &Host,
    asset_id: &str,
    container: Option<&str>,
    mut stream: UnixStream,
    err_path: &Path,
    sent: &Arc<AtomicBool>,
) -> BridgeResult<()> {
    let mut line = Vec::new();
    let mut buffer = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let count = stream.read(&mut buffer).await?;
            if count == 0 || buffer[0] == b'\n' {
                return Ok::<_, std::io::Error>(());
            }
            line.push(buffer[0]);
            if line.len() > 8192 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "rsync transport request too large",
                ));
            }
        }
    })
    .await;
    match read {
        Ok(Ok(())) => {}
        _ => {
            return Err(BridgeError::storage(
                "rsync transport request was not received",
            ))
        }
    }
    let request: Value = serde_json::from_slice(&line)
        .map_err(|_| BridgeError::invalid("invalid rsync transport request"))?;
    let Some(items) = request.as_array() else {
        return Err(BridgeError::invalid("invalid rsync transport request"));
    };
    if items.len() < 2 || items[0].as_str() != Some(asset_id) || items[1].as_str() != Some("rsync")
    {
        return Err(BridgeError::invalid("invalid rsync transport request"));
    }
    let mut remote_args: Vec<String> = Vec::new();
    if let Some(container) = container {
        remote_args.extend([
            "docker".into(),
            "exec".into(),
            "-i".into(),
            container.to_string(),
        ]);
    }
    remote_args.extend(
        items[1..]
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string),
    );
    // JumpServer's gateway can drop channel data written before it has wired the
    // target session. A shell wrapper emits a readiness marker first, so the relay
    // only forwards rsync protocol bytes once the remote side is really attached.
    let mut quued: Vec<String> = vec![
        "sh".into(),
        "-c".into(),
        format!("printf '{READY_MARKER}'; exec \"$@\""),
        "jms-rsync".into(),
    ];
    quued.extend(remote_args.iter().cloned());
    let remote_command = crate::fsprobe::shlex_join(&quued);
    tracing::debug!(command = remote_command.as_str(), "rsync_relay_exec");
    let connection = pool.connection(host).await?;
    let channel = connection.open_shell(&remote_command).await?;
    let (writer, mut reader) = channel.split();
    let ready_started = Instant::now();
    let mut ready: Vec<u8> = Vec::new();
    while take_ready(&ready).is_none() {
        if ready_started.elapsed() > Duration::from_secs(15) {
            return Err(BridgeError::ssh(
                "remote side did not confirm the rsync channel; transfer state is unknown",
            ));
        }
        match tokio::time::timeout(Duration::from_secs(15), reader.next()).await {
            Ok(Some(ShellEvent::Data(data))) => ready.extend_from_slice(&data),
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => {
                return Err(BridgeError::ssh(
                    "remote rsync channel closed before it was ready; transfer did not start",
                ))
            }
        }
    }
    // The marker and the first rsync protocol bytes can share one SSH packet; only
    // the marker is stripped and everything after it must reach the local rsync.
    let leftover = take_ready(&ready).expect("marker verified above");
    if !leftover.is_empty() && stream.write_all(&leftover).await.is_err() {
        return Err(BridgeError::ssh(
            "rsync socket closed before the protocol started",
        ));
    }
    sent.store(true, Ordering::SeqCst);
    let err_handle = err_path.to_path_buf();
    tokio::spawn(async move {
        let mut socket_open = true;
        let mut channel_open = true;
        let mut chunk = vec![0u8; 65536];
        // Both directions are serviced concurrently: rsync is full duplex, so a
        // blocking read on one side deadlocks the handshake.
        while socket_open || channel_open {
            tokio::select! {
                read = stream.read(&mut chunk), if socket_open => {
                    match read {
                        Ok(0) => {
                            socket_open = false;
                            writer.write_eof().await;
                        }
                        Ok(count) => {
                            if let Err(error) = writer.write(&chunk[..count]).await {
                                tracing::debug!(error = error.message(), "rsync socket->channel failed");
                                return;
                            }
                        }
                        Err(_) => socket_open = false,
                    }
                }
                event = reader.recv(), if channel_open => {
                    match event {
                        Some(ShellEvent::Data(data)) => {
                            if stream.write_all(&data).await.is_err() {
                                return;
                            }
                        }
                        Some(ShellEvent::ExtData(data)) => {
                            if let Ok(mut file) = std::fs::OpenOptions::new()
                                .append(true)
                                .create(true)
                                .open(&err_handle)
                            {
                                let _ = file.write_all(&data);
                            }
                        }
                        Some(ShellEvent::ExecRejected) | None => {
                            channel_open = false;
                            // The remote side is gone: close the local socket so the relay
                            // (and therefore rsync) can exit instead of waiting forever.
                            let _ = stream.shutdown().await;
                            socket_open = false;
                        }
                        Some(_) => {}
                    }
                }
            }
        }
    });
    Ok(())
}

/// Bytes that follow the readiness marker, or `None` while it has not fully arrived.
///
/// The marker is only a prefix of the stream: a single SSH packet may carry it and
/// the first rsync protocol bytes together, and dropping those bytes breaks the
/// handshake even though the relay looks healthy.
fn take_ready(buffer: &[u8]) -> Option<Vec<u8>> {
    let marker = READY_MARKER.as_bytes();
    let position = buffer
        .windows(marker.len())
        .position(|window| window == marker)?;
    Some(buffer[position + marker.len()..].to_vec())
}

/// The relay child: connect to the service socket, then copy bytes both ways.
pub fn relay_main(argv: &[String]) -> i32 {
    if argv.len() < 2 {
        eprintln!("rsync-relay requires a socket path");
        return 2;
    }
    let socket_path = &argv[1];
    let mut socket = match StdUnixStream::connect(socket_path) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("rsync-relay cannot connect: {error}");
            return 2;
        }
    };
    let request = serde_json::to_vec(&argv[2..].iter().cloned().collect::<Vec<String>>())
        .unwrap_or_else(|_| b"[]".to_vec());
    let mut line = request;
    line.push(b'\n');
    if socket.write_all(&line).is_err() {
        return 2;
    }
    let reader_socket = match socket.try_clone() {
        Ok(clone) => clone,
        Err(_) => return 2,
    };
    let sender = std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buffer = [0u8; 65536];
        loop {
            match stdin.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if socket.write_all(&buffer[..count]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = socket.shutdown(std::net::Shutdown::Write);
    });
    let mut stdout = std::io::stdout();
    let mut incoming = reader_socket;
    let mut buffer = [0u8; 65536];
    loop {
        match incoming.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if stdout.write_all(&buffer[..count]).is_err() {
                    break;
                }
                let _ = stdout.flush();
            }
            Err(_) => break,
        }
    }
    // Do not join the stdin pump: rsync keeps its child's stdin open until it exits,
    // and it only exits after this process does. The reference implementation lets the
    // daemon thread die with the process for the same reason.
    drop(sender);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_accepts_rsync_banner() {
        assert_eq!(
            parse_major_version("rsync  version 3.2.7  protocol version 31"),
            Some(3)
        );
        assert_eq!(parse_major_version("openrsync: protocol version 29"), None);
        assert_eq!(parse_major_version("rsync version 2.6.9"), Some(2));
    }

    #[test]
    fn unsupported_protect_args_is_detected() {
        assert!(unsupported_protect_args(
            "rsync: --protect-args: unknown option"
        ));
        assert!(unsupported_protect_args("-s: Invalid option"));
        assert!(!unsupported_protect_args(
            "rsync  version 3.2.7  protocol version 31"
        ));
    }

    #[test]
    fn direction_strings_match_the_public_argument() {
        assert_eq!(Direction::Push.as_str(), "push");
        assert_eq!(Direction::Pull.as_str(), "pull");
    }

    #[test]
    fn relay_socket_lives_in_a_private_directory() {
        let relay = RsyncRelay::create().unwrap();
        assert!(relay.socket.starts_with(&relay.directory));
        assert!(relay.directory.starts_with(std::env::temp_dir()));
        let directory = relay.directory.clone();
        drop(relay);
        assert!(!directory.exists());
    }

    #[test]
    fn readiness_keeps_protocol_bytes_from_the_same_packet() {
        let mut packet = READY_MARKER.as_bytes().to_vec();
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x1f]);
        assert_eq!(
            take_ready(&packet),
            Some(vec![0x00, 0x00, 0x00, 0x1f]),
            "protocol bytes sent with the marker must reach the local rsync"
        );
    }

    #[test]
    fn readiness_alone_yields_no_leftover() {
        assert_eq!(take_ready(READY_MARKER.as_bytes()), Some(Vec::new()));
    }

    #[test]
    fn readiness_waits_until_the_marker_is_complete() {
        let marker = READY_MARKER.as_bytes();
        assert_eq!(take_ready(&marker[..marker.len() - 1]), None);
        assert_eq!(take_ready(b"banner\n"), None);
        // A split marker becomes visible once the second half arrives.
        let mut buffer = marker[..3].to_vec();
        buffer.extend_from_slice(&marker[3..]);
        buffer.extend_from_slice(b"payload");
        assert_eq!(take_ready(&buffer), Some(b"payload".to_vec()));
    }
}
