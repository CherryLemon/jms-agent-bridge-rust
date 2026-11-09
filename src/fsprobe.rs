//! Generate literal Bash filesystem requests and decode bounded records locally.
//!
//! The remote collector is `resources/fs_probe.sh`, embedded verbatim from the
//! Python implementation so the wire protocol stays identical: the probe prints
//! `JMSFS-BASH1`, then base64 of NUL-separated tagged records, then `JMSFS-END <rc>`.
//! User values are passed as argv to a fixed here-document, never evaluated as code.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Map, Value};

pub const SCAN_LIMIT: u64 = 100_000;
pub const SCAN_BYTES: u64 = 64 * 1024 * 1024;
pub const WIRE_LIMIT: usize = 1024 * 1024;
pub const DEFAULT_BYTES: usize = 4096;
pub const PROBE_SOURCE: &str = include_str!("../resources/fs_probe.sh");

#[derive(Debug, Clone, Default)]
pub struct FsOptions {
    pub action: String,
    pub path: String,
    pub paths: Vec<String>,
    pub pattern: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub container: Option<String>,
    pub local_path: Option<String>,
    pub overwrite: bool,
    pub literal: Option<bool>,
    pub case_sensitive: Option<bool>,
    pub hidden: Option<bool>,
    pub respect_ignore: Option<bool>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub depth: Option<u64>,
    pub start_line: Option<u64>,
    pub line_count: Option<u64>,
    pub byte_offset: Option<u64>,
    pub tail: Option<bool>,
    pub max_bytes: Option<usize>,
    pub context_lines: Option<u64>,
    pub max_file_bytes: Option<u64>,
    pub timeout: Option<u64>,
}

impl FsOptions {
    fn tail(&self) -> bool {
        self.tail.unwrap_or(false)
    }

    fn line_count(&self) -> usize {
        self.line_count.unwrap_or(200) as usize
    }

    fn max_bytes(&self) -> usize {
        self.max_bytes.unwrap_or(DEFAULT_BYTES)
    }

    fn start_line(&self) -> u64 {
        self.start_line.unwrap_or(1)
    }

    fn limit(&self) -> usize {
        self.limit.unwrap_or(100) as usize
    }

    fn offset(&self) -> u64 {
        self.offset.unwrap_or(0)
    }

    /// Whether a caller supplied an explicit continuation cursor.
    fn has_byte_offset(&self) -> bool {
        self.byte_offset.is_some()
    }
}

/// Keep fnmatch's literal backslashes and parentheses out of Bash extglobs.
pub fn bash_glob(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut inside = false;
    for (index, character) in chars.iter().enumerate() {
        if *character == '[' {
            inside = true;
        } else if *character == ']' {
            inside = false;
        }
        if *character == '\\' || (!inside && matches!(character, '(' | ')' | '|' | '+' | '@' | '!'))
        {
            out.push('\\');
        }
        if inside && *character == '^' && index > 0 && chars[index - 1] == '[' {
            out.push('\\');
        }
        out.push(*character);
    }
    out
}

/// `shlex.quote`: leave safe strings alone, otherwise single-quote and escape.
pub fn shlex_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-')
        });
    if safe {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub fn shlex_join(values: &[String]) -> String {
    values
        .iter()
        .map(|value| shlex_quote(value))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The complete remote script for one filesystem action.
pub fn remote_script(options: &FsOptions, rg_command: &str) -> Result<String, String> {
    for value in [
        options.path.as_str(),
        options.pattern.as_str(),
        rg_command,
        options.local_path.as_deref().unwrap_or(""),
    ]
    .into_iter()
    .chain(options.paths.iter().map(String::as_str))
    .chain(options.include.iter().map(String::as_str))
    .chain(options.exclude.iter().map(String::as_str))
    {
        if value.contains('\0') {
            return Err("NUL is not a valid shell argument".into());
        }
    }
    if options.action == "search" && options.pattern.contains('\n') {
        return Err("line-based search patterns must be single-line strings".into());
    }
    let depth: u64 = match options.action.as_str() {
        "list" => 1,
        "tree" => options.depth.unwrap_or(3),
        _ => 128,
    };
    let numbers: [u64; 16] = [
        options.max_bytes() as u64,
        options.line_count() as u64,
        options.start_line(),
        options.byte_offset.map(|value| value as i64).unwrap_or(-1) as u64,
        u64::from(options.tail()),
        depth,
        options.limit() as u64,
        options.offset(),
        options.max_file_bytes.unwrap_or(8 * 1024 * 1024),
        u64::from(options.literal.unwrap_or(true)),
        u64::from(options.case_sensitive.unwrap_or(true)),
        u64::from(options.hidden.unwrap_or(false)),
        u64::from(options.respect_ignore.unwrap_or(true)),
        SCAN_LIMIT,
        SCAN_BYTES,
        WIRE_LIMIT as u64,
    ];
    let mut args: Vec<String> = vec![
        options.action.clone(),
        options.path.clone(),
        options.pattern.clone(),
    ];
    for number in numbers {
        // `byte_offset` is sent as a signed value so -1 still means "absent".
        args.push(
            if number == u64::from(-1i64 as i64 as u64) && options.byte_offset.is_none() {
                "-1".to_string()
            } else {
                number.to_string()
            },
        );
    }
    args.push(bash_glob(&options.pattern));
    args.push(options.context_lines.unwrap_or(0).to_string());
    args.push(rg_command.to_string());
    for values in [
        options.paths.clone(),
        options
            .include
            .iter()
            .map(|value| bash_glob(value))
            .collect(),
        options
            .exclude
            .iter()
            .map(|value| bash_glob(value))
            .collect(),
    ] {
        args.push(values.len().to_string());
        args.extend(values);
    }
    let timeout = options.timeout.unwrap_or(30);
    let mut command = vec![
        "timeout".to_string(),
        "--signal=TERM".to_string(),
        "--kill-after=1".to_string(),
        timeout.to_string(),
        "bash".to_string(),
        "--noprofile".to_string(),
        "--norc".to_string(),
        "-s".to_string(),
        "--".to_string(),
    ];
    command.extend(args);
    Ok(format!(
        "(\n\
set +e\n\
if ! command -v timeout >/dev/null 2>&1; then printf 'JMSFS-MISSING timeout\\n';\n\
elif ! command -v base64 >/dev/null 2>&1; then printf 'JMSFS-MISSING base64\\n';\n\
else\n\
printf 'JMSFS-BASH1\\n'\n\
{command} <<'__JMS_FS_BASH__' | base64 -w0\n\
{source}\n\
__JMS_FS_BASH__\n\
__jms_fs_codes=(\"${{PIPESTATUS[@]}}\")\n\
__jms_fs_rc=${{__jms_fs_codes[0]}}\n\
if (( __jms_fs_codes[1] != 0 )); then __jms_fs_rc=${{__jms_fs_codes[1]}}; fi\n\
printf '\\nJMSFS-END %s\\n' \"$__jms_fs_rc\"\n\
fi\n\
)\n",
        command = shlex_join(&command),
        source = PROBE_SOURCE
    ))
}

fn text(value: &[u8]) -> String {
    String::from_utf8_lossy(value).to_string()
}

fn error_value(kind: &str, message: &str, path: Option<&str>) -> Value {
    let mut map = Map::new();
    map.insert("ok".into(), Value::Bool(false));
    map.insert("error".into(), Value::from(kind));
    map.insert("message".into(), Value::from(message));
    if let Some(path) = path {
        map.insert("path".into(), Value::from(path));
    }
    Value::Object(map)
}

fn decode_b64(value: &[u8]) -> Result<Vec<u8>, ()> {
    BASE64.decode(value).map_err(|_| ())
}

fn filemode(mode: u32) -> String {
    let kind = match mode & 0o170000 {
        0o100000 => '-',
        0o040000 => 'd',
        0o120000 => 'l',
        0o060000 => 'b',
        0o020000 => 'c',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '?',
    };
    let mut out = String::with_capacity(10);
    out.push(kind);
    let bits = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (mask, character) in bits {
        out.push(if mode & mask != 0 { character } else { '-' });
    }
    let mut chars: Vec<char> = out.chars().collect();
    if mode & 0o4000 != 0 {
        chars[3] = if mode & 0o100 != 0 { 's' } else { 'S' };
    }
    if mode & 0o2000 != 0 {
        chars[6] = if mode & 0o010 != 0 { 's' } else { 'S' };
    }
    if mode & 0o1000 != 0 {
        chars[9] = if mode & 0o001 != 0 { 't' } else { 'T' };
    }
    chars.into_iter().collect()
}

fn base_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(index) => &trimmed[index + 1..],
        None => trimmed,
    }
}

fn python_json_len(value: &Value) -> usize {
    fn write(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                out.push('{');
                for (index, (key, item)) in map.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    out.push('"');
                    out.push_str(key);
                    out.push_str("\": ");
                    write(item, out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    write(item, out);
                }
                out.push(']');
            }
            Value::String(text) => {
                out.push('"');
                for character in text.chars() {
                    match character {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => {
                            out.push_str(&format!("\\u{:04x}", c as u32));
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    out.len()
}

fn read_page(fields: &[Vec<u8>], options: &FsOptions) -> Result<Value, String> {
    let (path, size, stamp, start, previous, payload, after_size, after_stamp) = (
        &fields[0], &fields[1], &fields[2], &fields[3], &fields[4], &fields[5], &fields[6],
        &fields[7],
    );
    let parse = |value: &Vec<u8>| -> Result<i64, String> {
        text(value)
            .trim()
            .parse::<i64>()
            .map_err(|_| "invalid read page fields".to_string())
    };
    let size = parse(size)?;
    let stamp = parse(stamp)?;
    let mut start = parse(start)?;
    let after_size = parse(after_size)?;
    let after_stamp = parse(after_stamp)?;
    let mut data = decode_b64(payload).map_err(|_| "invalid base64 read payload".to_string())?;
    let tail = options.tail();
    let count = options.line_count();
    let mut budget = options.max_bytes();
    if options.action == "read_many" {
        budget /= options.paths.len().max(1);
    }
    let previous = decode_b64(previous).map_err(|_| "invalid base64 cursor".to_string())?;
    let mut partial_first = start > 0 && previous != b"\n";
    let line = if tail || options.has_byte_offset() {
        None
    } else {
        Some(options.start_line())
    };
    if tail {
        if partial_first {
            if let Some(position) = data.iter().position(|byte| *byte == b'\n') {
                start += position as i64 + 1;
                data = data[position + 1..].to_vec();
                partial_first = false;
            }
        }
        let lines: Vec<&[u8]> = split_keep_ends(&data);
        let keep = lines.len().saturating_sub(count);
        let selected: Vec<u8> = lines[keep..].concat();
        start += (data.len() - selected.len()) as i64;
        data = selected;
    } else {
        let mut n = budget.min(data.len());
        while n < data.len() && (0x80..0xC0).contains(&data[n]) {
            n += 1;
        }
        let head = &data[..n];
        let lines: Vec<&[u8]> = split_keep_ends(head);
        data = lines
            .iter()
            .take(count)
            .copied()
            .collect::<Vec<&[u8]>>()
            .concat();
    }
    if tail || partial_first {
        while !data.is_empty() && (0x80..0xC0).contains(&data[0]) {
            start += 1;
            data.remove(0);
        }
    }
    let end = start + data.len() as i64;
    let eof = end >= size;
    let mut out = Map::new();
    out.insert("ok".into(), Value::Bool(true));
    out.insert("path".into(), Value::from(text(path)));
    out.insert("text".into(), Value::from(text(&data)));
    out.insert("encoding".into(), Value::from("utf-8"));
    out.insert("decoding_errors".into(), Value::from("replace"));
    out.insert(
        "start_line".into(),
        line.map_or(Value::Null, |value| json!(value)),
    );
    out.insert(
        "next_line".into(),
        line.map_or(Value::Null, |value| {
            json!(value + data.iter().filter(|byte| **byte == b'\n').count() as u64)
        }),
    );
    out.insert("byte_offset".into(), json!(start));
    out.insert("next_byte_offset".into(), json!(end));
    out.insert("total_bytes".into(), json!(size));
    out.insert("eof".into(), Value::Bool(eof));
    out.insert("truncated".into(), Value::Bool(!eof || (tail && start > 0)));
    out.insert("partial_first_line".into(), Value::Bool(partial_first));
    out.insert(
        "partial_last_line".into(),
        Value::Bool(!data.is_empty() && !data.ends_with(b"\n") && !eof),
    );
    out.insert(
        "changed_during_read".into(),
        Value::Bool((size, stamp) != (after_size, after_stamp)),
    );
    out.insert(
        "fingerprint".into(),
        json!({"size": after_size, "mtime_ns": after_stamp}),
    );
    let _ = budget;
    Ok(Value::Object(out))
}

fn split_keep_ends(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    for (index, byte) in data.iter().enumerate() {
        if *byte == b'\n' {
            out.push(&data[start..=index]);
            start = index + 1;
        }
    }
    if start < data.len() {
        out.push(&data[start..]);
    }
    out
}

fn info(fields: &[Vec<u8>], action: &str) -> Result<Value, String> {
    let (path, relative, depth, mode, size, stamp, uid, gid, link, resolved) = (
        &fields[0], &fields[1], &fields[2], &fields[3], &fields[4], &fields[5], &fields[6],
        &fields[7], &fields[8], &fields[9],
    );
    let mode_value =
        u32::from_str_radix(text(mode).trim(), 16).map_err(|_| "invalid stat mode".to_string())?;
    let kind = match mode_value & 0o170000 {
        0o100000 => "file",
        0o040000 => "directory",
        0o120000 => "symlink",
        _ => "special",
    };
    let path_text = text(path);
    let mut out = Map::new();
    out.insert("path".into(), Value::from(path_text.clone()));
    out.insert("name".into(), Value::from(base_name(&path_text)));
    out.insert("type".into(), Value::from(kind));
    out.insert(
        "size".into(),
        json!(text(size).trim().parse::<i64>().unwrap_or(0)),
    );
    out.insert(
        "mtime_ns".into(),
        json!(text(stamp).trim().parse::<i64>().unwrap_or(0)),
    );
    out.insert("mode".into(), Value::from(filemode(mode_value)));
    out.insert(
        "uid".into(),
        json!(text(uid).trim().parse::<i64>().unwrap_or(0)),
    );
    out.insert(
        "gid".into(),
        json!(text(gid).trim().parse::<i64>().unwrap_or(0)),
    );
    if kind == "symlink" {
        out.insert("link_target".into(), Value::from(text(link)));
        out.insert("resolved_path".into(), Value::from(text(resolved)));
    }
    if action != "stat" {
        out.insert("relative_path".into(), Value::from(text(relative)));
        out.insert(
            "depth".into(),
            json!(text(depth).trim().parse::<i64>().unwrap_or(0)),
        );
    }
    if out["path"].as_str().map(str::as_bytes) != Some(path.as_slice()) {
        out.insert("path_bytes_b64".into(), Value::from(BASE64.encode(path)));
        out.insert("path_encoding".into(), Value::from("utf-8-replace"));
    }
    Ok(Value::Object(out))
}

fn rg_row(raw: &[u8], root: &str) -> Result<Value, String> {
    let event: Value = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
    let data = event
        .get("data")
        .ok_or_else(|| "rg row without data".to_string())?;
    let decode_field = |value: &Value| -> Result<String, String> {
        if let Some(text_value) = value.get("text") {
            return Ok(text_value.as_str().unwrap_or_default().to_string());
        }
        let bytes = value
            .get("bytes")
            .and_then(Value::as_str)
            .ok_or_else(|| "rg row field without text".to_string())?;
        let decoded = decode_b64(bytes.as_bytes()).map_err(|_| "invalid rg bytes".to_string())?;
        Ok(text(&decoded))
    };
    let path = decode_field(
        data.get("path")
            .ok_or_else(|| "rg row without path".to_string())?,
    )?;
    let path = if path.starts_with('/') {
        path
    } else {
        let suffix = path.strip_prefix("./").unwrap_or(&path);
        format!("{}/{}", root.trim_end_matches('/'), suffix)
    };
    let relative =
        if let Some(rest) = path.strip_prefix(&format!("{}/", root.trim_end_matches('/'))) {
            rest.to_string()
        } else {
            base_name(&path).to_string()
        };
    let content = decode_field(
        data.get("lines")
            .ok_or_else(|| "rg row without lines".to_string())?,
    )?;
    let content = content.trim_end_matches(['\r', '\n']).to_string();
    let truncated = content.chars().count() > 2000;
    let mut out = Map::new();
    out.insert("path".into(), Value::from(path));
    out.insert("relative_path".into(), Value::from(relative));
    out.insert(
        "line".into(),
        data.get("line_number").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "kind".into(),
        event.get("type").cloned().unwrap_or(Value::Null),
    );
    out.insert("text".into(), Value::from(take_chars(&content, 2000)));
    out.insert("line_truncated".into(), Value::Bool(truncated));
    Ok(Value::Object(out))
}

fn take_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

const ARITY: &[(u8, usize)] = &[
    (b'H', 3),
    (b'E', 3),
    (b'I', 10),
    (b'G', 2),
    (b'R', 8),
    (b'C', 7),
    (b'L', 6),
    (b'J', 1),
    (b'P', 7),
];

fn arity(tag: &str) -> Option<usize> {
    let bytes = tag.as_bytes();
    if bytes.len() != 1 {
        return None;
    }
    ARITY
        .iter()
        .find(|(name, _)| *name == bytes[0])
        .map(|(_, count)| *count)
}

/// Decode one probe payload into the same JSON shape the Python bridge returned.
pub fn decode(raw: &[u8], options: &FsOptions, stderr: &[u8]) -> Value {
    if let Some(rest) = raw.strip_prefix(b"JMSFS-MISSING ") {
        let missing = String::from_utf8_lossy(rest)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        return error_value(
            "UnsupportedOperation",
            &format!("missing target command: {missing}"),
            None,
        );
    }
    if raw.len() > WIRE_LIMIT * 2 + 65536 {
        return error_value(
            "InvalidProbeResponse",
            "filesystem probe exceeded wire limit",
            None,
        );
    }
    let split = raw.iter().position(|byte| *byte == b'\n');
    let (header, encoded) = match split {
        Some(index) => (&raw[..index], &raw[index + 1..]),
        None => (raw, &raw[raw.len()..]),
    };
    let end_marker = b"\nJMSFS-END ";
    let Some(end_position) = rfind(encoded, end_marker) else {
        return error_value(
            "InvalidProbeResponse",
            "missing Bash probe completion marker",
            None,
        );
    };
    let status_text = String::from_utf8_lossy(&encoded[end_position + end_marker.len()..]);
    let tail = status_text.trim().to_string();
    let rest = &encoded[end_position + end_marker.len()..];
    // The rc line is the remainder of the trailer line.
    let rc_text = tail
        .split(|c: char| !c.is_ascii_digit() && c != '-')
        .next()
        .unwrap_or("0")
        .to_string();
    let _ = rest;
    let rc: i32 = rc_text.parse().unwrap_or(0);
    if header != b"JMSFS-BASH1" {
        return error_value(
            "InvalidProbeResponse",
            "missing Bash probe completion marker",
            None,
        );
    }
    let body = &encoded[..end_position];
    let payload = match decode_b64(body) {
        Ok(payload) => payload,
        Err(()) => {
            return error_value(
                "InvalidProbeResponse",
                "filesystem probe payload is not valid base64",
                None,
            )
        }
    };
    let tokens: Vec<&[u8]> = payload.split(|byte| *byte == 0).collect();
    let mut records: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
    let mut index = 0usize;
    let mut partial = false;
    while index + 1 < tokens.len() {
        let tag = text(tokens[index]);
        let Some(count) = arity(&tag) else {
            partial = true;
            break;
        };
        if index + count >= tokens.len() {
            partial = true;
            break;
        }
        records.push((
            tag,
            tokens[index + 1..index + 1 + count]
                .iter()
                .map(|value| value.to_vec())
                .collect(),
        ));
        index += count + 1;
    }
    let last_token_empty = tokens.last().map(|value| value.is_empty()).unwrap_or(true);
    if !last_token_empty || !records.iter().any(|(tag, _)| tag == "P") {
        partial = true;
    }

    let mut errors: Vec<Value> = Vec::new();
    let mut scan_limited = partial || rc != 0;
    let mut engine = "bash".to_string();
    let mut ignore_rules_applied = false;
    let mut skipped_large: Option<i64> = Some(0);
    let mut skipped_binary: Option<i64> = Some(0);
    let mut warnings: Vec<Value> = Vec::new();
    let mut depth_limited = false;
    let mut timed_out = false;
    let mut rows: Vec<Value> = Vec::new();
    let mut files: Vec<Value> = Vec::new();
    let mut single: Option<Value> = None;
    let mut elapsed = 0.0f64;

    for (tag, fields) in &records {
        match tag.as_str() {
            "H" => {
                engine = text(&fields[0]);
                ignore_rules_applied = text(&fields[1]) == "1";
                let warning = text(&fields[2]);
                if !warning.is_empty() {
                    warnings.push(Value::from(warning));
                }
            }
            "E" => {
                let path = text(&fields[0]);
                let kind = text(&fields[1]);
                let message = text(&fields[2]);
                let item = error_value(&kind, &message, Some(&path));
                if options.action == "read_many" {
                    files.push(item.clone());
                } else {
                    single = Some(item.clone());
                }
                if errors.len() < 20 {
                    errors.push(item);
                }
            }
            "I" => match info(fields, &options.action) {
                Ok(row) => {
                    if options.action == "stat" {
                        let mut map = Map::new();
                        map.insert("ok".into(), Value::Bool(true));
                        if let Value::Object(row) = row {
                            map.extend(row);
                        }
                        single = Some(Value::Object(map));
                    } else {
                        rows.push(row);
                    }
                }
                Err(message) => errors.push(error_value("ParseError", &message, None)),
            },
            "G" => {
                let mut row = Map::new();
                row.insert("path".into(), Value::from(text(&fields[0])));
                row.insert("relative_path".into(), Value::from(text(&fields[1])));
                rows.push(Value::Object(row));
            }
            "R" => match read_page(fields, options) {
                Ok(row) => {
                    if options.action == "read_many" {
                        files.push(row);
                    } else {
                        single = Some(row);
                    }
                }
                Err(message) => errors.push(error_value("ParseError", &message, None)),
            },
            "C" => {
                let path = text(&fields[0]);
                let digest = text(&fields[1]);
                let changed =
                    (text(&fields[3]), text(&fields[4])) != (text(&fields[5]), text(&fields[6]));
                let mut row = Map::new();
                row.insert("ok".into(), Value::Bool(!changed));
                row.insert("path".into(), Value::from(path));
                row.insert("algorithm".into(), Value::from("sha256"));
                row.insert("digest".into(), Value::from(digest));
                row.insert(
                    "bytes".into(),
                    json!(text(&fields[2]).trim().parse::<i64>().unwrap_or(0)),
                );
                row.insert("changed_during_read".into(), Value::Bool(changed));
                single = Some(Value::Object(row));
            }
            "L" => {
                let content = String::from_utf8_lossy(&fields[4])
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
                let clipped = fields[5] == b"1";
                let truncated = clipped || content.chars().count() > 2000;
                let mut row = Map::new();
                row.insert("path".into(), Value::from(text(&fields[0])));
                row.insert("relative_path".into(), Value::from(text(&fields[1])));
                row.insert(
                    "line".into(),
                    json!(text(&fields[2]).trim().parse::<i64>().unwrap_or(0)),
                );
                row.insert("kind".into(), Value::from(text(&fields[3])));
                row.insert("text".into(), Value::from(take_chars(&content, 2000)));
                row.insert("line_truncated".into(), Value::Bool(truncated));
                rows.push(Value::Object(row));
            }
            "J" => match rg_row(&fields[0], &options.path) {
                Ok(row) => rows.push(row),
                Err(message) => errors.push(error_value("ParseError", &message, None)),
            },
            "P" => {
                let large = text(&fields[1]).trim().parse::<i64>().unwrap_or(0);
                let binary = text(&fields[2]).trim().parse::<i64>().unwrap_or(0);
                let limited = text(&fields[3]).trim().parse::<i64>().unwrap_or(0);
                let depth = text(&fields[4]).trim().parse::<i64>().unwrap_or(0);
                skipped_large = if large < 0 { None } else { Some(large) };
                skipped_binary = if binary < 0 { None } else { Some(binary) };
                scan_limited |= limited != 0;
                depth_limited = depth != 0;
                elapsed = (text(&fields[6]).trim().parse::<f64>().unwrap_or(0.0)
                    - text(&fields[5]).trim().parse::<f64>().unwrap_or(0.0))
                .max(0.0);
                elapsed = (elapsed * 1000.0).round() / 1000.0;
            }
            _ => {}
        }
    }
    if rc == 124 || rc == 137 {
        timed_out = true;
        scan_limited = true;
    } else if rc != 0 {
        errors.push(error_value(
            "CollectorFailure",
            &format!(
                "Bash collector failed: {}",
                String::from_utf8_lossy(&stderr[..stderr.len().min(1024)])
            ),
            None,
        ));
    }

    if options.action == "read_many" {
        if rc != 0 || partial {
            return error_value(
                if rc == 124 || rc == 137 {
                    "TimeoutError"
                } else {
                    "InvalidProbeResponse"
                },
                "incomplete read_many response",
                None,
            );
        }
        let ok = files
            .iter()
            .all(|row| row.get("ok").and_then(Value::as_bool).unwrap_or(false));
        return json!({
            "ok": ok,
            "files": files,
            "backend": "bash",
            "elapsed_seconds": elapsed,
        });
    }
    if matches!(options.action.as_str(), "read" | "stat" | "checksum") {
        let Some(single) = single else {
            return error_value(
                if rc == 124 || rc == 137 {
                    "TimeoutError"
                } else {
                    "InvalidProbeResponse"
                },
                "incomplete filesystem response",
                None,
            );
        };
        if rc != 0 || partial {
            return error_value(
                if rc == 124 || rc == 137 {
                    "TimeoutError"
                } else {
                    "InvalidProbeResponse"
                },
                "incomplete filesystem response",
                None,
            );
        }
        let mut map = match single {
            Value::Object(map) => map,
            other => {
                let mut map = Map::new();
                map.insert("value".into(), other);
                map
            }
        };
        map.insert("backend".into(), Value::from("bash"));
        map.insert("elapsed_seconds".into(), json!(elapsed));
        return Value::Object(map);
    }

    let budget = options.max_bytes();
    let limit = options.limit();
    let total_rows = rows.len();
    let mut output: Vec<Value> = Vec::new();
    let mut spent = 0usize;
    for row in rows {
        let size = python_json_len(&row);
        if output.len() >= limit || (!output.is_empty() && spent + size > budget) {
            break;
        }
        output.push(row);
        spent += size;
    }
    let more = total_rows > output.len();
    let offset = options.offset();
    let incomplete = more || scan_limited;
    let mut state = Map::new();
    state.insert("errors".into(), Value::Array(errors.clone()));
    state.insert("scan_limited".into(), Value::Bool(scan_limited));
    state.insert("engine".into(), Value::from(engine));
    state.insert(
        "ignore_rules_applied".into(),
        Value::Bool(ignore_rules_applied),
    );
    state.insert(
        "skipped_large_files".into(),
        skipped_large.map_or(Value::Null, |value| json!(value)),
    );
    state.insert(
        "skipped_binary_files".into(),
        skipped_binary.map_or(Value::Null, |value| json!(value)),
    );
    if !warnings.is_empty() {
        state.insert("warnings".into(), Value::Array(warnings));
    }
    if depth_limited {
        state.insert("depth_limited".into(), Value::Bool(true));
    }
    if timed_out {
        state.insert("timed_out".into(), Value::Bool(true));
    }
    let mut out = Map::new();
    out.insert(
        "ok".into(),
        Value::Bool(
            state
                .get("errors")
                .and_then(Value::as_array)
                .map(|errors| errors.is_empty())
                .unwrap_or(true),
        ),
    );
    out.insert("entries".into(), Value::Array(output.clone()));
    out.insert("returned".into(), json!(output.len()));
    out.insert("offset".into(), json!(offset));
    out.insert(
        "next_offset".into(),
        if more {
            json!(offset + output.len() as u64)
        } else {
            Value::Null
        },
    );
    out.insert("truncated".into(), Value::Bool(incomplete));
    out.insert(
        "complete".into(),
        Value::Bool(!incomplete && !has_errors(&state)),
    );
    out.insert("path".into(), Value::from(options.path.clone()));
    out.insert("action".into(), Value::from(options.action.clone()));
    out.insert("backend".into(), Value::from("bash"));
    out.insert("elapsed_seconds".into(), json!(elapsed));
    for (key, value) in state {
        out.insert(key, value);
    }
    Value::Object(out)
}

fn has_errors(state: &Map<String, Value>) -> bool {
    state
        .get("errors")
        .and_then(Value::as_array)
        .map(|errors| !errors.is_empty())
        .unwrap_or(false)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

/// Summary of one decoded directory-style page.
pub fn page_summary(value: &Value) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    if let Some(map) = value.as_object() {
        for key in ["path", "action", "returned", "next_offset", "truncated"] {
            if let Some(item) = map.get(key) {
                out.insert(key.to_string(), item.clone());
            }
        }
    }
    out
}
