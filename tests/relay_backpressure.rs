//! The relay must survive backpressure.
//!
//! rsync hands a custom remote-shell a *non-blocking* stdout unless `--blocking-io` is
//! used, and the relay writes to stdout synchronously. A write that hits a full pipe
//! therefore returns `WouldBlock`, which an earlier version treated as end of stream:
//! it exited 0 and truncated the transfer. This test drives the real relay binary with
//! a consumer that reads slowly and a payload far larger than the pipe buffer.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PAYLOAD: usize = 8 * 1024 * 1024;

fn relay_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_jms-bridge"))
}

/// Read the child's stdout slowly, so its pipe stays full for most of the transfer.
fn slow_consumer(
    mut stdout: std::process::ChildStdout,
    expected: usize,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut received = Vec::with_capacity(expected);
        let mut chunk = [0u8; 32 * 1024];
        let deadline = Instant::now() + Duration::from_secs(60);
        while received.len() < expected && Instant::now() < deadline {
            match stdout.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    received.extend_from_slice(&chunk[..count]);
                    // Deliberately slower than the producer.
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        received
    })
}

/// Mark the child's stdout non-blocking, which is what rsync does for a custom
/// remote-shell unless `--blocking-io` is given. Without this the test cannot reproduce
/// the EAGAIN that truncates a long transfer.
fn nonblocking_stdout(command: &mut Command) -> &mut Command {
    unsafe {
        command.pre_exec(|| {
            let flags = libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

#[test]
fn a_full_stdout_pipe_does_not_truncate_the_relay() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("relay.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();

    let mut command = Command::new(relay_binary());
    nonblocking_stdout(&mut command);
    let mut child = command
        .arg("rsync-relay")
        .arg(socket_path.to_string_lossy().to_string())
        .arg("asset.example")
        .arg("--server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the relay");

    // The relay announces its arguments on one JSON line, then relays bytes.
    let (mut service, _) = listener.accept().expect("the relay connects");
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\n") {
        let read = service.read(&mut byte).expect("read the relay request");
        assert!(read == 1, "the relay closed before sending its request");
        request.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&request);
    assert!(text.contains("asset.example"), "request was {text}");

    let stdout = child.stdout.take().expect("relay stdout");
    let consumer = slow_consumer(stdout, PAYLOAD);

    // Push the payload the way the SSH side would, in SSH-sized packets.
    let payload: Vec<u8> = (0..PAYLOAD).map(|index| (index % 251) as u8).collect();
    let writer = std::thread::spawn(move || {
        for chunk in payload.chunks(32 * 1024) {
            if service.write_all(chunk).is_err() {
                return false;
            }
        }
        let _ = service.shutdown(std::net::Shutdown::Write);
        true
    });

    let received = consumer.join().expect("consumer thread");
    let sent_ok = writer.join().expect("writer thread");
    let status = child.wait().expect("relay exits");
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }

    assert!(sent_ok, "the service side failed to write the payload");
    assert_eq!(
        received.len(),
        PAYLOAD,
        "the relay dropped {} bytes: {stderr}",
        PAYLOAD - received.len()
    );
    assert_eq!(
        received,
        (0..PAYLOAD)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<u8>>(),
        "the relay corrupted the stream"
    );
    assert!(
        status.success(),
        "the relay exited with {status:?}: {stderr}"
    );
}

/// A blocking reader that also needs to see the relay stop when the far side closes.
#[test]
fn the_relay_exits_zero_when_the_service_closes_cleanly() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("relay2.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let mut child = Command::new(relay_binary())
        .arg("rsync-relay")
        .arg(socket_path.to_string_lossy().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the relay");
    let (mut service, _) = listener.accept().expect("the relay connects");
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\n") {
        let read = service.read(&mut byte).expect("read the request");
        assert_eq!(read, 1);
        request.push(byte[0]);
    }
    service.write_all(b"payload").unwrap();
    UnixStream::shutdown(&service, std::net::Shutdown::Both).unwrap();

    let output = wait_with_output(&mut child);
    assert!(
        output.0.success(),
        "relay exited with {:?}: {}",
        output.0,
        output.1
    );
    assert_eq!(output.2, b"payload");
}

fn wait_with_output(
    child: &mut std::process::Child,
) -> (std::process::ExitStatus, String, Vec<u8>) {
    let mut stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let (sent_stdout, sent_stderr) = std::thread::scope(|scope| {
        let out = scope.spawn(|| {
            let mut buffer = Vec::new();
            let _ = stdout.read_to_end(&mut buffer);
            buffer
        });
        let err = scope.spawn(|| {
            let mut buffer = String::new();
            let _ = stderr.read_to_string(&mut buffer);
            buffer
        });
        (
            out.join().unwrap_or_default(),
            err.join().unwrap_or_default(),
        )
    });
    let status = child.wait().expect("wait");
    (status, sent_stderr, sent_stdout)
}
