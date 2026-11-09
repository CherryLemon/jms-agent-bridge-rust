//! Shell sessions with explicit readiness and transmission markers.
//!
//! A script is transmitted only after both streams acknowledged a readiness marker,
//! and completion is proven by a matching end marker carrying the exit status. An SSH
//! channel that ends without that evidence is `unknown`, never success.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::errors::{BridgeError, BridgeResult};
use crate::inventory::shell_quote;
use crate::transport::ssh::{ChannelReader, ChannelShell, ChannelWriter, ShellEvent};

pub const START_PREFIX: &[u8] = b"\x1eSTART";
pub const READY_PREFIX: &[u8] = b"\x1eREADY";
pub const MARKER_SUFFIX: u8 = 0x1f;

pub fn new_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Both streams must echo this before the user script is sent.
pub fn ready_packet(nonce: &str) -> Vec<u8> {
    format!("printf '\\036READY{nonce}\\037'; printf '\\036READY{nonce}\\037' >&2\n").into_bytes()
}

pub fn ready_marker(nonce: &str) -> Vec<u8> {
    let mut marker = READY_PREFIX.to_vec();
    marker.extend_from_slice(nonce.as_bytes());
    marker.push(MARKER_SUFFIX);
    marker
}

pub fn exec_start_marker(nonce: &str) -> Vec<u8> {
    let mut marker = START_PREFIX.to_vec();
    marker.extend_from_slice(nonce.as_bytes());
    marker.push(MARKER_SUFFIX);
    marker
}

pub fn exec_end_marker(nonce: &str) -> Vec<u8> {
    format!("\x1eEND{nonce}:").into_bytes()
}

/// One-branch packet for a persistent shell: quote once, then eval the literal script.
pub fn exec_packet(nonce: &str, body: &str) -> Vec<u8> {
    format!(
        "printf '\\036START{nonce}\\037'; printf '\\036START{nonce}\\037' >&2\n\
builtin eval -- {quoted}\n\
__jms_rc=$?; printf '\\036END{nonce}:%s\\037' \"$__jms_rc\"; \
printf '\\036END{nonce}:%s\\037' \"$__jms_rc\" >&2\n",
        quoted = shell_quote(body)
    )
    .into_bytes()
}

/// Interactive variant: one physical line is parsed before eval starts, so a
/// foreground `read`/REPL consumes later user input rather than the end marker.
pub fn terminal_packet(nonce: &str, script: &str) -> Vec<u8> {
    let quoted = format!(
        "$'{}'",
        script
            .replace('\\', "\\\\")
            .replace('\'', "\\'")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    );
    format!(
        "printf '\\036START{nonce}\\037'; printf '\\036START{nonce}\\037' >&2; \
builtin eval -- {quoted}; __jms_terminal_rc=$?; \
printf '\\036END{nonce}:%s\\037' \"$__jms_terminal_rc\"; \
printf '\\036END{nonce}:%s\\037' \"$__jms_terminal_rc\" >&2\n"
    )
    .into_bytes()
}

/// Cumulative shell, used for both isolated executions and named sessions.
pub struct ShellSession {
    pub writer: ChannelWriter,
    pub reader: ChannelReader,
    pub out: Vec<u8>,
    pub err: Vec<u8>,
    pub startup_out: Vec<u8>,
    pub startup_err: Vec<u8>,
    pub ready: bool,
    pub started: bool,
    pub lost: bool,
    pub ready_marker: Option<Vec<u8>>,
    pub last_used: Instant,
}

#[derive(Debug, Clone, Copy)]
pub struct CaptureResult {
    pub out_code: i32,
    pub err_code: i32,
    pub started: bool,
}

impl ShellSession {
    pub fn new(shell: ChannelShell) -> Self {
        let (writer, reader) = shell.split();
        Self {
            writer,
            reader,
            out: Vec::new(),
            err: Vec::new(),
            startup_out: Vec::new(),
            startup_err: Vec::new(),
            ready: false,
            started: false,
            lost: false,
            ready_marker: None,
            last_used: Instant::now(),
        }
    }

    pub fn is_closing(&self) -> bool {
        self.lost || self.reader.is_closed()
    }

    /// Confirm both streams before transmitting any script.
    pub async fn prime(&mut self, timeout: Duration) -> BridgeResult<()> {
        let nonce = new_nonce();
        let marker = ready_marker(&nonce);
        self.ready_marker = Some(marker.clone());
        self.writer.write(&ready_packet(&nonce)).await?;
        let deadline = Instant::now() + timeout;
        let mut out_ready = false;
        let mut err_ready = false;
        while !(out_ready && err_ready) {
            if Instant::now() >= deadline {
                return Err(BridgeError::ssh(
                    "remote shell did not acknowledge readiness in time; script was not sent",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event =
                match tokio::time::timeout(remaining, self.reader.next()).await {
                    Ok(event) => event,
                    Err(_) => return Err(BridgeError::ssh(
                        "remote shell did not acknowledge readiness in time; script was not sent",
                    )),
                };
            match event {
                Some(ShellEvent::Data(data)) => {
                    Self::push_limited(&mut self.startup_out, &data);
                    self.out.extend_from_slice(&data);
                    if let Some(position) = find(&self.out, &marker) {
                        self.out.drain(..position + marker.len());
                        out_ready = true;
                    } else {
                        trim_head(&mut self.out, marker.len());
                    }
                }
                Some(ShellEvent::ExtData(data)) => {
                    Self::push_limited(&mut self.startup_err, &data);
                    self.err.extend_from_slice(&data);
                    if let Some(position) = find(&self.err, &marker) {
                        self.err.drain(..position + marker.len());
                        err_ready = true;
                    } else {
                        trim_head(&mut self.err, marker.len());
                    }
                }
                _ => return Err(BridgeError::ssh(
                    "remote shell closed during startup; script was not sent. SSH authentication \
alone does not confirm remote execution is available; check the gateway execution policy and \
target connection",
                )),
            }
        }
        self.ready = true;
        Ok(())
    }

    fn push_limited(buffer: &mut Vec<u8>, data: &[u8]) {
        buffer.extend_from_slice(data);
        if buffer.len() > 2048 {
            let cut = buffer.len() - 2048;
            buffer.drain(..cut);
        }
    }

    /// Persist the bounded startup diagnostics (never the readiness marker).
    pub fn save_startup_output(&self, out_path: &Path, err_path: &Path) -> std::io::Result<()> {
        let marker = self.ready_marker.clone().unwrap_or_default();
        for (path, data) in [(out_path, &self.startup_out), (err_path, &self.startup_err)] {
            if data.is_empty() {
                continue;
            }
            let mut cleaned = data.clone();
            if !marker.is_empty() {
                while let Some(position) = find(&cleaned, &marker) {
                    cleaned.drain(position..position + marker.len());
                }
            }
            let mut file = File::create(path)?;
            file.write_all(&cleaned)?;
        }
        Ok(())
    }

    /// Stream both outputs to disk until the channel closes.
    ///
    /// `marker` is the transmission acknowledgement on stdout: bytes before it are the
    /// shell banner, not command output, and the return value says whether it arrived.
    pub async fn pump(
        &mut self,
        out_path: &Path,
        err_path: &Path,
        marker: Option<Vec<u8>>,
        deadline: Option<Duration>,
    ) -> BridgeResult<bool> {
        let mut out = PumpStream::new(std::mem::take(&mut self.out), out_path, marker)?;
        let mut err = PumpStream::new(std::mem::take(&mut self.err), err_path, None)?;
        let limit = deadline.map(|value| Instant::now() + value);
        let result = loop {
            out.flush_buffer()?;
            err.flush_buffer()?;
            let remaining = match limit {
                Some(limit) => {
                    let remaining = limit.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break Err(BridgeError::ssh("execution timed out"));
                    }
                    Some(remaining)
                }
                None => None,
            };
            let event = match remaining {
                Some(remaining) => {
                    match tokio::time::timeout(remaining, self.reader.next()).await {
                        Ok(event) => event,
                        Err(_) => break Err(BridgeError::ssh("execution timed out")),
                    }
                }
                None => self.reader.next().await,
            };
            match event {
                Some(ShellEvent::Data(data)) => out.push(&data),
                Some(ShellEvent::ExtData(data)) => err.push(&data),
                _ => break Ok(out.started),
            }
        };
        self.out = out.into_buffer();
        self.err = err.into_buffer();
        // A closed channel is a normal end here: whether the command ran is decided by
        // the start marker and the exit status, not by the channel's lifetime.
        result
    }

    /// Capture one acknowledged command on a persistent shell.
    pub async fn capture(
        &mut self,
        out_path: &Path,
        err_path: &Path,
        start: &[u8],
        end: &[u8],
        timeout: Duration,
    ) -> BridgeResult<CaptureResult> {
        let mut out = MarkerCapture::new(std::mem::take(&mut self.out), out_path, start, end)?;
        let mut err = MarkerCapture::new(std::mem::take(&mut self.err), err_path, start, end)?;
        let deadline = Instant::now() + timeout;
        let result = loop {
            out.scan()?;
            err.scan()?;
            self.started |= out.started || err.started;
            if out.done && err.done {
                break Ok(CaptureResult {
                    out_code: out.code.unwrap_or(255),
                    err_code: err.code.unwrap_or(255),
                    started: out.started || err.started,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break Err(BridgeError::ssh("execution timed out"));
            }
            let event = match tokio::time::timeout(remaining, self.reader.next()).await {
                Ok(event) => event,
                Err(_) => break Err(BridgeError::ssh("execution timed out")),
            };
            match event {
                Some(ShellEvent::Data(data)) => out.push(&data),
                Some(ShellEvent::ExtData(data)) => err.push(&data),
                _ => {
                    self.lost = true;
                    break Err(BridgeError::ssh(
                        "persistent shell exited before completion; session state was lost",
                    ));
                }
            }
        };
        self.out = out.into_buffer();
        self.err = err.into_buffer();
        self.last_used = Instant::now();
        result
    }

    pub async fn close(&mut self) {
        self.writer.close().await;
        self.reader.close().await;
    }

    /// Exit status reported by the remote side, if any.
    pub fn exit_code(&self) -> Option<i32> {
        self.reader.exit_code()
    }

    pub fn is_rejected(&self) -> bool {
        self.reader.was_rejected()
    }
}

struct PumpStream {
    buffer: Vec<u8>,
    file: File,
    marker: Option<Vec<u8>>,
    started: bool,
}

impl PumpStream {
    fn new(buffer: Vec<u8>, path: &Path, marker: Option<Vec<u8>>) -> BridgeResult<Self> {
        let started = marker.is_none();
        Ok(Self {
            buffer,
            file: File::create(path)?,
            marker,
            started,
        })
    }

    fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn flush_buffer(&mut self) -> BridgeResult<()> {
        let Some(marker) = self.marker.clone() else {
            let _ = self.file.write_all(&self.buffer);
            self.buffer.clear();
            return Ok(());
        };
        if let Some(position) = find(&self.buffer, &marker) {
            let _ = self.file.write_all(&self.buffer[..position]);
            let rest = self.buffer[position + marker.len()..].to_vec();
            let _ = self.file.write_all(&rest);
            self.buffer.clear();
            self.started = true;
            self.marker = None;
            return Ok(());
        }
        if self.buffer.len() >= marker.len() {
            let keep = marker.len() - 1;
            let cut = self.buffer.len() - keep;
            let _ = self.file.write_all(&self.buffer[..cut]);
            self.buffer.drain(..cut);
        }
        Ok(())
    }

    fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }
}

struct MarkerCapture {
    buffer: Vec<u8>,
    file: File,
    start: Vec<u8>,
    end: Vec<u8>,
    active: bool,
    started: bool,
    done: bool,
    code: Option<i32>,
}

impl MarkerCapture {
    fn new(buffer: Vec<u8>, path: &Path, start: &[u8], end: &[u8]) -> BridgeResult<Self> {
        Ok(Self {
            buffer,
            file: File::create(path)?,
            start: start.to_vec(),
            end: end.to_vec(),
            active: false,
            started: false,
            done: false,
            code: None,
        })
    }

    fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn scan(&mut self) -> BridgeResult<()> {
        if self.done {
            return Ok(());
        }
        if !self.active {
            match find(&self.buffer, &self.start) {
                Some(position) => {
                    self.buffer.drain(..position + self.start.len());
                    self.active = true;
                    self.started = true;
                }
                None => {
                    if self.buffer.len() >= self.start.len() {
                        let cut = self.buffer.len() - (self.start.len() - 1);
                        self.buffer.drain(..cut);
                    }
                    return Ok(());
                }
            }
        }
        loop {
            let Some(position) = find(&self.buffer, &self.end) else {
                // Publish everything except a possible partial end marker.
                let keep = self.end.len() + 16;
                if self.buffer.len() > keep {
                    let cut = self.buffer.len() - keep;
                    let _ = self.file.write_all(&self.buffer[..cut]);
                    self.buffer.drain(..cut);
                }
                return Ok(());
            };
            let suffix_start = position + self.end.len();
            match self.buffer[suffix_start..]
                .iter()
                .position(|byte| *byte == MARKER_SUFFIX)
            {
                Some(offset) => {
                    let code_text =
                        String::from_utf8_lossy(&self.buffer[suffix_start..suffix_start + offset])
                            .trim()
                            .to_string();
                    let _ = self.file.write_all(&self.buffer[..position]);
                    self.buffer.drain(..suffix_start + offset + 1);
                    self.code = Some(code_text.parse().unwrap_or(255));
                    self.done = true;
                    return Ok(());
                }
                None => {
                    // The status digits have not fully arrived yet.
                    let _ = self.file.write_all(&self.buffer[..position]);
                    self.buffer.drain(..position);
                    return Ok(());
                }
            }
        }
    }

    fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }
}

/// Keep only the last `keep` bytes: a marker may straddle two channel reads.
fn trim_head(buffer: &mut Vec<u8>, marker_len: usize) {
    if buffer.len() >= marker_len {
        let cut = buffer.len() - (marker_len - 1);
        buffer.drain(..cut);
    }
}

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_are_control_character_bounded() {
        let nonce = "abc123";
        assert_eq!(ready_marker(nonce), b"\x1eREADYabc123\x1f".to_vec());
        assert_eq!(exec_start_marker(nonce), b"\x1eSTARTabc123\x1f".to_vec());
        assert_eq!(exec_end_marker(nonce), b"\x1eENDabc123:".to_vec());
    }

    #[test]
    fn ready_packet_echoes_on_both_streams() {
        let packet = String::from_utf8(ready_packet("n1")).unwrap();
        assert!(packet.contains("printf '\\036READYn1\\037'"));
        assert!(packet.contains(">&2"));
        assert_eq!(packet.matches("READYn1").count(), 2);
    }

    #[test]
    fn exec_packet_quotes_the_body_once() {
        let packet = String::from_utf8(exec_packet("n1", "echo 'hi'; exit 3")).unwrap();
        // The literal body is single-quoted inside `builtin eval --`, and the exit
        // status is printed on both streams as an end marker.
        assert_eq!(packet.matches("builtin eval --").count(), 1);
        assert!(packet.contains("builtin eval -- 'echo '\"'\"'hi'\"'\"'; exit 3'\n"));
        assert!(packet.contains("__jms_rc=$?"));
        assert!(packet.contains(">&2"));
    }

    #[test]
    fn terminal_packet_escapes_newlines_for_one_physical_line() {
        let packet = String::from_utf8(terminal_packet("n1", "a\nb'c\\d")).unwrap();
        assert!(packet.contains("$'a\\nb\\'c\\\\d'"));
        // Exactly one physical line: a foreground read must not consume the marker.
        assert_eq!(packet.lines().count(), 1);
    }

    #[test]
    fn marker_capture_extracts_status_and_leaves_the_remainder() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("out.log");
        let start = exec_start_marker("n1");
        let end = exec_end_marker("n1");
        let mut capture = MarkerCapture::new(b"banner\r\n".to_vec(), &path, &start, &end).unwrap();
        capture.push(b"banner\r\n");
        capture.push(b"\x1eSTARTn1\x1fhello\n");
        capture.scan().unwrap();
        assert!(capture.started);
        assert!(!capture.done);
        capture.push(b"\x1eENDn1:7\x1fnext-prompt");
        capture.scan().unwrap();
        assert!(capture.done);
        assert_eq!(capture.code, Some(7));
        assert_eq!(capture.buffer, b"next-prompt".to_vec());
        assert!(capture.started);
    }

    #[test]
    fn marker_capture_handles_a_marker_split_across_reads() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("out.log");
        let start = exec_start_marker("n1");
        let end = exec_end_marker("n1");
        let mut capture = MarkerCapture::new(Vec::new(), &path, &start, &end).unwrap();
        capture.push(b"\x1eSTA");
        capture.scan().unwrap();
        assert!(!capture.started);
        capture.push(b"RTn1\x1fpartial");
        capture.scan().unwrap();
        assert!(capture.started);
        capture.push(b" output\x1eENDn1:");
        capture.scan().unwrap();
        assert!(!capture.done);
        capture.push(b"0\x1f");
        capture.scan().unwrap();
        assert!(capture.done);
        assert_eq!(capture.code, Some(0));
    }
}
