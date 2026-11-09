//! Published tool and operation schemas.
//!
//! Seven resident tools carry the whole interface. Everything else is an explicit
//! operation whitelisted here and disclosed one schema at a time by `discover`; the
//! same schema validates `call` arguments *before* any side effect.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::{json, Map, Value};

use crate::schema::strip_titles;

pub const DANGEROUS_FLAG_DESCRIPTION: &str = "Acknowledges the local guard for this authorized \
command; it grants no authorization.";

pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub read_only: bool,
    pub destructive: bool,
    pub open_world: bool,
}

fn string(description: &str) -> Value {
    json!({"type": "string", "description": description})
}

fn integer(minimum: u64, maximum: u64, default: u64, description: &str) -> Value {
    json!({"type": "integer", "minimum": minimum, "maximum": maximum, "default": default,
           "description": description})
}

/// Range without a description, for hidden operation fields.
fn int(minimum: u64, maximum: u64, default: u64) -> Value {
    integer(minimum, maximum, default, "")
}

fn boolean(default: bool, description: &str) -> Value {
    json!({"type": "boolean", "default": default, "description": description})
}

fn array_of_strings(description: &str, maximum: Option<u64>) -> Value {
    let mut value = json!({"type": "array", "minItems": 1,
        "items": {"type": "string", "minLength": 1}, "description": description});
    if let Some(maximum) = maximum {
        value["maxItems"] = json!(maximum);
    }
    value
}

/// Complete tool definitions: every accepted field, used for validation.
pub fn full_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "run",
            description: "Run literal Bash on REST targets; session_id retains shell state. Use \
request_id for writes, then reconcile lost replies. queue_full is an unsent per-target refusal. \
Full output is saved; read_result fetches it. Advanced fields may also be passed in options.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["targets"],
                "properties": {
                    "targets": array_of_strings("Asset names, IDs, IPs, aliases, or all.", None),
                    "script": {"type": "string", "maxLength": 1048576,
                               "description": "Literal Bash; values are data."},
                    "script_path": string("Absolute local file read instead of script."),
                    "cwd": string("Remote working directory; cd failure skips the script."),
                    "env": {"type": "object", "additionalProperties": {"type": "string"},
                            "description": "Exported before the script."},
                    "container": string("Existing container; never created."),
                    "image": string("Image for a new disposable container; never both with container."),
                    "docker_args": {"type": "array", "items": {"type": "string"},
                                    "description": "Extra docker arguments; needs container or image."},
                    "session_id": {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,64}$",
                                   "description": "Named shell that keeps cwd, exports and functions."},
                    "timeout": {"type": "number", "minimum": 1, "maximum": 600, "default": 60},
                    "max_output_bytes": integer(256, 16384, 4096,
                        "Preview budget shared by all targets."),
                    "request_id": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$",
                                   "description": "Caller id; recover with request_status."},
                    "allow_dangerous": {"type": "boolean", "default": false,
                                        "description": DANGEROUS_FLAG_DESCRIPTION},
                    "options": {"type": "object", "additionalProperties": false,
                        "description": "Same advanced fields, for callers that prefer one bag.",
                        "properties": {
                            "script_path": string("Absolute local file read instead of script."),
                            "container": string("Existing container; never created."),
                            "image": string("Image for a new disposable container; never both with container."),
                            "docker_args": {"type": "array", "items": {"type": "string"}},
                            "session_id": {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,64}$"},
                            "timeout": {"type": "number", "minimum": 1, "maximum": 600, "default": 60},
                            "max_output_bytes": integer(256, 16384, 4096, "Preview budget."),
                            "cwd": string("Remote working directory."),
                            "env": {"type": "object", "additionalProperties": {"type": "string"}},
                        }},
                },
            }),
            read_only: false,
            destructive: true,
            open_world: true,
        },
        ToolSpec {
            name: "fs",
            description:
                "Explore files or transfer them on one exact REST asset; optional existing \
container. Absolute paths/patterns are data, not shell. read/list/stat/read_many/glob/search/tree/\
checksum are read-only; upload/download write destinations. local_path is on this MCP machine. \
Put advanced fields in options; discover(operation='jms_fs', query=action) lists them.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["target", "action"],
                "properties": {
                    "target": string("One exact asset name, ID, IP or alias."),
                    "action": {"type": "string", "enum": ["list", "stat", "read", "read_many", "glob",
                        "search", "tree", "checksum", "upload", "download"]},
                    "path": string("Absolute remote path; required except read_many."),
                    "pattern": string("Glob (glob) or search pattern (search)."),
                    "container": string("Existing container; never created."),
                    "request_id": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$",
                                   "description": "Transfers only: recover with request_status."},
                    "options": {"type": "object", "additionalProperties": false,
                        "description": "Action fields: paths, local_path, overwrite, paging, filters, timeout.",
                        "properties": {
                            "paths": array_of_strings("read_many: absolute paths.", Some(16)),
                            "local_path": string("upload/download: absolute path on the MCP machine."),
                            "overwrite": boolean(false, "Replace existing destination files when true."),
                            "offset": integer(0, 100000, 0, "Rows to skip; repeat to continue."),
                            "limit": integer(1, 1000, 100, "Maximum rows per page."),
                            "depth": integer(1, 20, 3, "tree: maximum relative depth."),
                            "start_line": integer(1, 10000000, 1, "read/read_many: 1-based first line."),
                            "line_count": integer(1, 2000, 200, "read/read_many: maximum lines per file."),
                            "byte_offset": integer(0, 1099511627776, 0, "read: byte cursor from the previous page."),
                            "tail": boolean(false, "read/read_many: last line_count lines within max_bytes."),
                            "max_bytes": integer(256, 65536, 4096, "Content budget per response."),
                            "literal": boolean(true, "search: false enables regex."),
                            "case_sensitive": boolean(true, "search: case sensitivity."),
                            "include": array_of_strings("glob/search: include file globs.", Some(20)),
                            "exclude": array_of_strings("Traversal exclusions.", Some(20)),
                            "hidden": boolean(false, "Include dotfiles in traversal."),
                            "respect_ignore": boolean(true, "glob/search: honour ignore files."),
                            "context_lines": integer(0, 5, 0, "search: context lines per match."),
                            "max_file_bytes": integer(1024, 67108864, 8388608, "search/checksum: per-file cap."),
                            "timeout": integer(1, 900, 30, "Exploration 1..120s; transfers 1..900s."),
                        }},
                },
            }),
            read_only: false,
            destructive: true,
            open_world: true,
        },
        ToolSpec {
            name: "terminal",
            description:
                "Open a bound shell on one target; use its handle for exec/read/write/close. \
Running is not completion; reads honour cursors. Discover terminal_<action> for advanced options.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "action": {"type": "string", "enum": ["open", "exec", "read", "write", "close"],
                               "default": "exec"},
                    "target": string("open: one exact REST asset name, ID, IP or alias."),
                    "session": string("Handle returned by terminal(action='open')."),
                    "script": {"type": "string", "maxLength": 1048576, "description": "exec: literal Bash."},
                    "input": {"type": "string", "maxLength": 1048576, "description": "write: bytes for a foreground command."},
                    "options": {"type": "object", "additionalProperties": false,
                        "description": "open: target/container/image/cwd/env. exec/read/write: wait_ms, max_bytes, cursor, signal, eof, allow_dangerous, request_id.",
                        "properties": {
                            "target": string("open: one exact REST asset."),
                            "container": string("open: existing container."),
                            "image": string("open: image for a new container."),
                            "docker_args": {"type": "array", "items": {"type": "string"}},
                            "cwd": string("open: directory for the bound shell."),
                            "env": {"type": "object", "additionalProperties": {"type": "string"}},
                            "wait_ms": integer(0, 30000, 1000, "How long to watch before returning."),
                            "max_bytes": integer(1, 16384, 4096, "Output budget per stream."),
                            "cursor": {"type": "object", "additionalProperties": false,
                                       "properties": {"stdout": {"type": "integer", "minimum": 0},
                                                      "stderr": {"type": "integer", "minimum": 0}},
                                       "description": "Re-read from absolute byte offsets."},
                            "signal": {"type": "string", "enum": ["INT", "TERM"]},
                            "eof": boolean(false, "write: close stdin."),
                            "allow_dangerous": boolean(false, DANGEROUS_FLAG_DESCRIPTION),
                            "request_id": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$"},
                        }},
                },
            }),
            read_only: false,
            destructive: true,
            open_world: true,
        },
        ToolSpec {
            name: "read_result",
            description:
                "Read saved output by byte offset (limit <=16384), tail, or literal pattern; \
continue with next_offset.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["result_id"],
                "properties": {
                    "result_id": string("Result id from run/fs/call."),
                    "stream": {"type": "string", "enum": ["stdout", "stderr", "result"], "default": "stdout"},
                    "offset": integer(0, 1099511627776, 0, "First byte of this page."),
                    "limit": integer(1, 16384, 4096, "Page size in bytes."),
                    "tail": boolean(false, "Read the last `limit` bytes instead of from offset."),
                    "pattern": {"type": "string", "maxLength": 1024,
                                "description": "Literal search; needs tail=false."},
                },
            }),
            read_only: true,
            destructive: false,
            open_world: false,
        },
        ToolSpec {
            name: "discover",
            description:
                "Search assets or operation names; operation returns one schema. Inventory \
does not show accelerator occupancy; use jms_accelerator_status for live checks.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "query": string("Category, operation substring, or asset name/IP/UUID."),
                    "operation": string("Return this operation's full schema."),
                    "topic": {"type": "string", "enum": ["operations", "assets", "status"], "default": "operations"},
                    "limit": integer(1, 30, 10, "Rows per page."),
                    "offset": integer(0, 100000, 0, "Rows to skip."),
                },
            }),
            read_only: true,
            destructive: false,
            open_world: true,
        },
        ToolSpec {
            name: "call",
            description: "Call a discovered operation. request_id applies to jms_submit_job. Full \
responses: read_result(stream='result').",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["operation"],
                "properties": {
                    "operation": string("Whitelisted operation name from discover."),
                    "arguments": {"type": "object", "description": "Validated against the operation schema.",
                                  "default": {}},
                    "request_id": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$",
                                   "description": "jms_submit_job only: recover with request_status."},
                },
            }),
            read_only: false,
            destructive: true,
            open_world: true,
        },
        ToolSpec {
            name: "meta",
            description:
                "Read service, result:<id> or request:<id> metadata; use read_result for output.",
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "ref": {"type": "string", "default": "service",
                            "description": "service, result:<result_id>, or request:<request_id>."},
                    "section": {"type": "string",
                                "enum": ["summary", "all", "timing", "transport", "request", "policy"],
                                "default": "summary"},
                },
            }),
            read_only: true,
            destructive: false,
            open_world: false,
        },
    ]
}

fn request_id_property() -> Value {
    json!({"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$"})
}

/// Hidden operations, one schema each; `call` validates with the same JSON.
pub fn operations() -> &'static BTreeMap<String, Value> {
    static OPERATIONS: OnceLock<BTreeMap<String, Value>> = OnceLock::new();
    OPERATIONS.get_or_init(build_operations)
}

fn build_operations() -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    map.insert("jms_fs".to_string(), fs_schema());
    map.insert("jms_accelerator_status".to_string(), accelerator_schema());
    map.insert(
        "jms_exec".to_string(),
        json!({
            "name": "jms_exec",
            "description": "Run a short command with the legacy environment: sources the asset's \
        env_setup and enters its workdir. Prefer run for scripts, Docker, or a clean environment.",
            "inputSchema": {
                "type": "object", "additionalProperties": false,
                "required": ["targets", "command"],
                "properties": {
                    "targets": array_of_strings("Targets to execute on.", None),
                    "command": {"type": "string", "maxLength": 1048576},
                    "timeout": {"type": "number", "minimum": 1, "maximum": 600, "default": 60},
                    "allow_dangerous": boolean(false, DANGEROUS_FLAG_DESCRIPTION),
                },
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
        }),
    );
    map.insert(
        "jms_list_assets".to_string(),
        json!({
            "name": "jms_list_assets",
            "description": "Search the hourly REST asset snapshot; no YAML inventory is used.",
            "inputSchema": {
                "type": "object", "additionalProperties": false,
                "properties": {"search": {"type": "string"}},
            },
            "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": true},
        }),
    );
    map.insert("jms_asset_detail".to_string(), json!({
        "name": "jms_asset_detail",
        "description": "Read a permitted asset and its available accounts from the REST snapshot.",
        "inputSchema": {
            "type": "object", "additionalProperties": false,
            "required": ["asset_id"],
            "properties": {"asset_id": {"type": "string", "minLength": 1}},
        },
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": true},
    }));
    map.insert("jms_inventory_reload".to_string(), json!({
        "name": "jms_inventory_reload",
        "description": "Refresh the REST asset snapshot now; this does not close connections or shells.",
        "inputSchema": {"type": "object", "additionalProperties": false, "properties": {}},
        "annotations": {"readOnlyHint": false, "destructiveHint": false, "openWorldHint": true},
    }));
    map.insert("request_status".to_string(), json!({
        "name": "request_status",
        "description": "Read saved request/job/result receipts; never executes work. Reconcile the \
original ID after reply loss; reusing it never replays.",
        "inputSchema": {
            "type": "object", "additionalProperties": false,
            "required": ["request_id"],
            "properties": {"request_id": request_id_property()},
        },
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
    }));
    map.insert("result_metadata".to_string(), json!({
        "name": "result_metadata",
        "description": "Read saved metadata without running a command.",
        "inputSchema": {
            "type": "object", "additionalProperties": false,
            "required": ["ref"],
            "properties": {
                "ref": {"type": "string"},
                "section": {"type": "string",
                            "enum": ["summary", "all", "timing", "transport", "request", "policy"]},
            },
        },
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
    }));
    map.insert("script_guard_check".to_string(), json!({
        "name": "script_guard_check",
        "description": "Read-only diagnosis of the exact script guard; never executes supplied text.",
        "inputSchema": {
            "type": "object", "additionalProperties": false,
            "required": ["script"],
            "properties": {"script": {"type": "string", "maxLength": 1048576}},
        },
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
    }));
    map.insert(
        "session_list".to_string(),
        json!({
            "name": "session_list",
            "description": "List live sessions of both kinds (kind=terminal handles from terminal(action='open'), kind=shell from run(session_id=...)).",
            "inputSchema": {"type": "object", "additionalProperties": false, "properties": {}},
            "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
        }),
    );
    map.insert("session_close".to_string(), json!({
        "name": "session_close",
        "description": "Close one session on one permitted asset: kind=terminal for terminal(action='open') handles, kind=shell for run(session_id=...) shells. Without a kind the handle is looked up in both registries.",
        "inputSchema": {
            "type": "object", "additionalProperties": false,
            "required": ["target", "session_id"],
            "properties": {
                "target": {"type": "string"},
                "session_id": {"type": "string"},
                "kind": {"type": "string", "enum": ["terminal", "shell"]},
            },
        },
        "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
    }));
    for (name, description, props, required) in terminal_operations() {
        map.insert(
            name.to_string(),
            json!({
                "name": name,
                "description": description,
                "inputSchema": {
                    "type": "object", "additionalProperties": false,
                    "properties": props,
                    "required": required,
                },
                "annotations": {
                    "readOnlyHint": name == "terminal_read",
                    "destructiveHint": name != "terminal_read",
                    "openWorldHint": true,
                },
            }),
        );
    }
    for (name, description, props, required, read_only, idempotent) in job_operations() {
        let mut annotations = json!({"readOnlyHint": read_only, "destructiveHint": !read_only,
                                     "openWorldHint": true});
        if idempotent {
            annotations["idempotentHint"] = Value::Bool(true);
        }
        map.insert(
            name.to_string(),
            json!({
                "name": name,
                "description": description,
                "inputSchema": {
                    "type": "object", "additionalProperties": false,
                    "properties": props,
                    "required": required,
                },
                "annotations": annotations,
            }),
        );
    }
    map
}

fn terminal_operations() -> Vec<(&'static str, &'static str, Value, Value)> {
    let pages = || {
        json!({
            "wait_ms": int(0, 30000, 1000),
            "max_bytes": int(1, 16384, 4096),
            "cursor": {"type": "object", "additionalProperties": false,
                       "properties": {"stdout": {"type": "integer", "minimum": 0},
                                      "stderr": {"type": "integer", "minimum": 0}}},
        })
    };
    let mut exec = pages();
    exec["session"] = json!({"type": "string"});
    exec["script"] = json!({"type": "string", "maxLength": 1048576});
    exec["allow_dangerous"] = json!({"type": "boolean", "default": false,
                                     "description": DANGEROUS_FLAG_DESCRIPTION});
    exec["request_id"] = request_id_property();
    let mut read = pages();
    read["session"] = json!({"type": "string"});
    let mut write = pages();
    write["session"] = json!({"type": "string"});
    write["input"] = json!({"type": "string", "maxLength": 1048576});
    write["signal"] = json!({"type": "string", "enum": ["INT", "TERM"]});
    write["eof"] = json!({"type": "boolean", "default": false});
    write["allow_dangerous"] = json!({"type": "boolean", "default": false});
    write["request_id"] = request_id_property();
    vec![
        (
            "terminal_open",
            "Bind one exact target/container/cwd/env; returns a session handle.",
            json!({
                "target": {"type": "string", "minLength": 1},
                "container": {"type": "string"},
                "image": {"type": "string"},
                "docker_args": {"type": "array", "items": {"type": "string"}},
                "cwd": {"type": "string"},
                "env": {"type": "object", "additionalProperties": {"type": "string"}},
                "request_id": request_id_property(),
            }),
            json!(["target"]),
        ),
        (
            "terminal_exec",
            "Start a command. Running is not completion; logs survive MCP disconnection.",
            exec,
            json!(["session", "script"]),
        ),
        (
            "terminal_read",
            "Read incremental output; a cursor re-reads saved bytes. Never runs work.",
            read,
            json!(["session"]),
        ),
        (
            "terminal_write",
            "Send input, EOF or a signal; input acknowledgement is not completion.",
            write,
            json!(["session"]),
        ),
        (
            "terminal_close",
            "Close this shell, possibly interrupting its command. Saved outputs remain.",
            json!({"session": {"type": "string"}}),
            json!(["session"]),
        ),
    ]
}

fn job_operations() -> Vec<(&'static str, &'static str, Value, Value, bool, bool)> {
    vec![
        (
            "jms_submit_job",
            "Launch a long-running command detached on each host; returns a job id immediately.",
            json!({
                "targets": array_of_strings("Targets to launch on.", None),
                "command": {"type": "string", "maxLength": 1048576},
                "allow_dangerous": boolean(false, DANGEROUS_FLAG_DESCRIPTION),
            }),
            json!(["targets", "command"]),
            false,
            false,
        ),
        (
            "jms_job_status",
            "Check a job's status on each targeted host (status, exit code, log size, alive).",
            json!({
                "targets": array_of_strings("Targets to ask.", None),
                "job_id": {"type": "string", "pattern": "^[0-9a-f]{8}$"},
            }),
            json!(["targets", "job_id"]),
            true,
            false,
        ),
        (
            "jms_job_logs",
            "Read a job's log from offset onward; poll with the returned next_offset.",
            json!({
                "host": {"type": "string"},
                "job_id": {"type": "string", "pattern": "^[0-9a-f]{8}$"},
                "offset": int(0, 1099511627776, 0),
                "max_bytes": int(1024, 16384, 4096),
            }),
            json!(["host", "job_id"]),
            true,
            false,
        ),
        (
            "jms_job_cancel",
            "Kill a running job on one host.",
            json!({
                "host": {"type": "string"},
                "job_id": {"type": "string", "pattern": "^[0-9a-f]{8}$"},
            }),
            json!(["host", "job_id"]),
            false,
            true,
        ),
        (
            "jms_job_wait",
            "Block until every targeted host reports a terminal status, or timeout elapses. A \
timeout cancels nothing.",
            json!({
                "targets": array_of_strings("Targets to watch.", None),
                "job_id": {"type": "string", "pattern": "^[0-9a-f]{8}$"},
                "timeout": {"type": "number", "minimum": 1, "maximum": 180, "default": 50},
                "interval": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 2},
            }),
            json!(["targets", "job_id"]),
            true,
            false,
        ),
        (
            "jms_job_list",
            "List the job ids currently running on each targeted host (tmux-launched jobs only).",
            json!({"targets": array_of_strings("Targets to ask.", None)}),
            json!(["targets"]),
            true,
            false,
        ),
    ]
}

fn fs_schema() -> Value {
    json!({
        "name": "jms_fs",
        "description": "Remote filesystem operations without shell commands. One exact REST asset; \
    optional existing Docker container. Bounded pages and cursors with explicit partial/error reporting. \
    Prefer the top-level fs tool.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["target", "action"],
            "properties": {
                "target": {"type": "string", "minLength": 1},
                "action": {"type": "string", "enum": ["list", "stat", "read", "read_many", "glob",
                    "search", "tree", "checksum", "upload", "download"]},
                "path": {"type": "string", "minLength": 1, "maxLength": 4096},
                "paths": array_of_strings("read_many: absolute paths.", Some(16)),
                "container": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"},
                "local_path": {"type": "string", "minLength": 1, "maxLength": 4096},
                "overwrite": {"type": "boolean", "default": false},
                "request_id": request_id_property(),
                "pattern": {"type": "string", "minLength": 1, "maxLength": 1024},
                "literal": {"type": "boolean", "default": true},
                "case_sensitive": {"type": "boolean", "default": true},
                "include": array_of_strings("glob/search: include globs.", Some(20)),
                "exclude": array_of_strings("Traversal exclusions.", Some(20)),
                "hidden": {"type": "boolean", "default": false},
                "respect_ignore": {"type": "boolean", "default": true},
                "offset": integer(0, 100000, 0, "Rows to skip."),
                "limit": integer(1, 1000, 100, "Maximum result rows per page."),
                "depth": integer(1, 20, 3, "tree: maximum relative depth."),
                "start_line": integer(1, 10000000, 1, "read/read_many: 1-based first line."),
                "line_count": integer(1, 2000, 200, "read/read_many: maximum lines per file."),
                "byte_offset": integer(0, 1099511627776, 0, "read: byte cursor."),
                "tail": {"type": "boolean", "default": false},
                "max_bytes": integer(256, 65536, 4096, "Content budget per response."),
                "context_lines": integer(0, 5, 0, "search: context lines per match."),
                "max_file_bytes": integer(1024, 67108864, 8388608, "search/checksum: per-file cap."),
                "timeout": integer(1, 900, 30, "Exploration 1..120s; transfers 1..900s."),
            },
        },
        "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
    })
}

fn accelerator_schema() -> Value {
    json!({
        "name": "jms_accelerator_status",
        "description": "Read live GPU/NPU availability, utilization, memory and occupying PID/user/\
    container/task on 1-8 explicit REST assets. Read-only; summary includes all targets; full details are \
    saved for read_result(stream=\"result\"). Unknown or incomplete data is never free.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["targets"],
            "properties": {
                "targets": {"type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": true,
                            "items": {"type": "string", "minLength": 1}},
                "timeout": {"type": "integer", "minimum": 15, "maximum": 180, "default": 90},
            },
        },
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": true},
    })
}

pub fn categories() -> BTreeMap<&'static str, Vec<&'static str>> {
    let mut map = BTreeMap::new();
    map.insert(
        "assets",
        vec![
            "jms_list_assets",
            "jms_asset_detail",
            "jms_inventory_reload",
        ],
    );
    map.insert("inspect", vec!["jms_accelerator_status", "jms_exec"]);
    map.insert(
        "jobs",
        vec![
            "jms_submit_job",
            "jms_job_status",
            "jms_job_logs",
            "jms_job_cancel",
            "jms_job_wait",
            "jms_job_list",
        ],
    );
    map.insert("sessions", vec!["session_list", "session_close"]);
    map.insert("requests", vec!["request_status"]);
    map.insert("fs", vec!["jms_fs"]);
    map.insert("guard", vec!["script_guard_check"]);
    map.insert("metadata", vec!["result_metadata"]);
    map.insert(
        "terminal",
        vec![
            "terminal_open",
            "terminal_exec",
            "terminal_read",
            "terminal_write",
            "terminal_close",
        ],
    );
    map
}

/// Fields that are common to every fs action.
pub const FS_COMMON: [&str; 6] = [
    "target",
    "action",
    "path",
    "container",
    "timeout",
    "max_bytes",
];

pub fn fs_action_options(action: &str) -> Option<Vec<&'static str>> {
    let fields: Vec<&'static str> = match action {
        "list" => vec!["offset", "limit", "hidden", "exclude"],
        "tree" => vec!["offset", "limit", "hidden", "exclude", "depth"],
        "stat" => vec![],
        "checksum" => vec!["max_file_bytes"],
        "upload" => vec!["local_path", "overwrite", "exclude", "request_id"],
        "download" => vec!["local_path", "overwrite", "exclude", "request_id"],
        "read" => vec!["start_line", "line_count", "byte_offset", "tail"],
        "read_many" => vec!["paths", "start_line", "line_count", "tail"],
        "glob" => vec![
            "pattern",
            "include",
            "exclude",
            "hidden",
            "respect_ignore",
            "offset",
            "limit",
        ],
        "search" => vec![
            "pattern",
            "literal",
            "case_sensitive",
            "include",
            "exclude",
            "hidden",
            "respect_ignore",
            "offset",
            "limit",
            "context_lines",
            "max_file_bytes",
        ],
        _ => return None,
    };
    Some(fields)
}

/// One fs action's schema, describing only the fields that action reads.
pub fn fs_action_schema(action: &str) -> Result<Value, String> {
    let options = fs_action_options(action).ok_or_else(|| "unknown fs action".to_string())?;
    let full = fs_schema();
    let properties = full["inputSchema"]["properties"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let mut kept = Map::new();
    for key in FS_COMMON.iter().copied().chain(options) {
        if action == "read_many" && key == "path" {
            continue;
        }
        if let Some(value) = properties.get(key) {
            kept.insert(key.to_string(), value.clone());
        }
    }
    kept.insert("action".into(), json!({"type": "string", "const": action}));
    let mut required = vec!["target".to_string(), "action".to_string()];
    required.push(
        if action == "read_many" {
            "paths"
        } else {
            "path"
        }
        .to_string(),
    );
    if matches!(action, "search" | "glob") {
        required.push("pattern".into());
    }
    if matches!(action, "upload" | "download") {
        required.push("local_path".into());
    }
    Ok(strip_titles(&json!({
        "name": "jms_fs",
        "description": format!(
            "fs action={action}. Put advanced fields in fs.options; call(jms_fs) uses these fields flat. Existing validation applies."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": Value::Object(kept),
            "required": required,
        },
        "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
    })))
}

/// Tools advertised to clients: the fields that are worth a permanent schema.
///
/// Validation always uses [`full_specs`], so unadvertised fields stay accepted for
/// compatibility while the model only pays for the common ones.
pub fn advertised() -> Vec<ToolSpec> {
    full_specs()
        .into_iter()
        .map(|spec| {
            let schema = public_view(&spec.name, spec.input_schema.clone());
            ToolSpec {
                input_schema: schema,
                ..spec
            }
        })
        .collect()
}

/// Per-tool keep list for the advertised schema (mirrors the Python bridge).
fn public_view(name: &str, schema: Value) -> Value {
    let keep: &[&str] = match name {
        "run" => &[
            "targets",
            "script",
            "request_id",
            "allow_dangerous",
            "options",
        ],
        "fs" => &[
            "target",
            "action",
            "path",
            "pattern",
            "container",
            "request_id",
            "options",
        ],
        "terminal" => &["action", "target", "session", "script", "input", "options"],
        _ => return schema,
    };
    let mut value = schema;
    let Some(map) = value.as_object_mut() else {
        return value;
    };
    if let Some(properties) = map.get_mut("properties").and_then(Value::as_object_mut) {
        properties.retain(|key, _| keep.contains(&key.as_str()));
    }
    if let Some(required) = map.get_mut("required").and_then(Value::as_array_mut) {
        required.retain(|item| {
            item.as_str()
                .map(|key| keep.contains(&key))
                .unwrap_or(false)
        });
    }
    // The options bag is advertised as an entry point only: its fields live in
    // `discover(operation='run')` so they do not cost tokens in every session.
    if let Some(options) = map
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("options"))
        .and_then(Value::as_object_mut)
    {
        let hint = match name {
            "run" => "script_path, cwd, env, container, image, docker_args, session_id, timeout, max_output_bytes",
            "fs" => "action-specific fields (offset, limit, start_line, local_path, overwrite, ...)",
            _ => "target, container, image, docker_args, cwd, env, wait_ms, max_bytes, cursor, signal, eof",
        };
        options.clear();
        options.insert("type".into(), Value::from("object"));
        options.insert(
            "description".into(),
            Value::from(format!(
                "Advanced fields: {hint}. discover(operation='{name}') lists them."
            )),
        );
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::validate;

    /// One valid and one invalid sample per advertised tool. A sample that fails
    /// validation must fail loudly: swallowing the error proves nothing.
    fn samples() -> Vec<(&'static str, Value, Value)> {
        vec![
            (
                "run",
                json!({"targets": ["a"], "script": "ls", "request_id": "r-1",
                       "options": {"timeout": 5, "env": {"A": "1"}}}),
                json!({"targets": ["a"], "script": 5}),
            ),
            (
                "fs",
                json!({"target": "a", "action": "read", "path": "/etc/hostname",
                       "options": {"start_line": 1}}),
                json!({"target": "a", "action": "nope"}),
            ),
            (
                "terminal",
                json!({"action": "open", "target": "a", "options": {"cwd": "/tmp"}}),
                json!({"action": "nope"}),
            ),
            (
                "read_result",
                json!({"result_id": "abc", "limit": 1024, "tail": true}),
                json!({"result_id": "abc", "limit": 999999}),
            ),
            (
                "discover",
                json!({"query": "job", "topic": "operations", "limit": 5}),
                json!({"topic": "nope", "limit": 0}),
            ),
            (
                "call",
                json!({"operation": "jms_job_status", "arguments": {}}),
                json!({}),
            ),
            (
                "meta",
                json!({"ref": "service", "section": "summary"}),
                json!({"ref": "service", "section": "nope"}),
            ),
        ]
    }

    #[test]
    fn every_advertised_schema_accepts_and_rejects_samples() {
        let samples = samples();
        for spec in advertised() {
            assert_eq!(spec.input_schema["type"], "object", "{}", spec.name);
            let (_, good, bad) = samples
                .iter()
                .find(|(name, _, _)| *name == spec.name)
                .unwrap_or_else(|| panic!("{} has no schema sample", spec.name));
            validate(&spec.input_schema, good)
                .unwrap_or_else(|error| panic!("{} rejected its valid sample: {error}", spec.name));
            assert!(
                validate(&spec.input_schema, bad).is_err(),
                "{} accepted an invalid sample",
                spec.name
            );
        }
    }

    #[test]
    fn env_accepts_only_string_values() {
        let run = advertised()
            .into_iter()
            .find(|spec| spec.name == "run")
            .unwrap();
        let full = full_specs()
            .into_iter()
            .find(|spec| spec.name == "run")
            .unwrap();
        let error = validate(
            &full.input_schema,
            &json!({"targets": ["a"], "script": "ls", "env": {"CUDA_VISIBLE_DEVICES": 0}}),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("CUDA_VISIBLE_DEVICES"),
            "{error}"
        );
    }

    #[test]
    fn run_schema_requires_targets_but_not_script() {
        let run = advertised()
            .into_iter()
            .find(|spec| spec.name == "run")
            .unwrap();
        assert!(validate(&run.input_schema, &json!({})).is_err());
        // `script` and `options.script_path` are interchangeable, so the handler
        // enforces "exactly one" and the schema only requires targets.
        assert!(validate(&run.input_schema, &json!({"targets": ["a"]})).is_ok());
        assert!(validate(
            &run.input_schema,
            &json!({"targets": ["a"], "script": "ls"})
        )
        .is_ok());
        // The advertised options bag is an entry point; the validation schema is what
        // rejects an unknown advanced field.
        let full = full_specs()
            .into_iter()
            .find(|spec| spec.name == "run")
            .unwrap();
        assert!(validate(
            &full.input_schema,
            &json!({"targets": ["a"], "script": "ls", "options": {"sandbox": true}})
        )
        .is_err());
    }

    /// `tools/list` is paid on every session, so its size is a contract.
    #[test]
    fn advertised_tools_stay_within_their_token_budget() {
        let payload = serde_json::to_string(
            &advertised()
                .iter()
                .map(|spec| {
                    json!({
                        "name": spec.name,
                        "description": spec.description,
                        "inputSchema": spec.input_schema,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(
            payload.len() <= 6144,
            // 10 KiB before the options/discover split; keep it from creeping back.
            "tools/list grew to {} bytes; move details into options or discover",
            payload.len()
        );
        // Every advertised field must also be a real field: the lists may shrink, never drift.
        for spec in advertised() {
            let full = full_specs()
                .into_iter()
                .find(|full| full.name == spec.name)
                .unwrap();
            for key in spec.input_schema["properties"]
                .as_object()
                .map(|map| map.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
            {
                assert!(
                    full.input_schema["properties"].get(&key).is_some(),
                    "{} advertises unknown field {key}",
                    spec.name
                );
            }
        }
    }

    #[test]
    fn measure_sizes() {
        for spec in crate::schemas::advertised() {
            let payload = serde_json::json!({"name": spec.name, "description": spec.description,
                                         "inputSchema": spec.input_schema})
            .to_string();
            println!(
                "{:10} {:5} desc={:4} schema={:5}",
                spec.name,
                payload.len(),
                spec.description.len(),
                spec.input_schema.to_string().len()
            );
        }
    }

    #[test]
    fn hidden_operations_cover_the_whitelist() {
        let operations = operations();
        for name in [
            "jms_fs",
            "jms_accelerator_status",
            "terminal_open",
            "terminal_exec",
            "terminal_read",
            "terminal_write",
            "terminal_close",
            "request_status",
            "result_metadata",
            "script_guard_check",
            "session_list",
            "session_close",
            "jms_submit_job",
            "jms_job_status",
            "jms_job_logs",
            "jms_job_cancel",
            "jms_job_wait",
            "jms_job_list",
            "jms_list_assets",
            "jms_asset_detail",
            "jms_inventory_reload",
            "jms_exec",
        ] {
            assert!(operations.contains_key(name), "missing {name}");
        }
        assert!(!operations.contains_key("jms_cluster_submit"));
    }

    #[test]
    fn fs_action_schema_narrows_to_the_action() {
        let read = fs_action_schema("read").unwrap();
        assert_eq!(read["inputSchema"]["properties"]["action"]["const"], "read");
        assert!(read["inputSchema"]["properties"].get("paths").is_none());
        assert_eq!(
            read["inputSchema"]["required"],
            json!(["target", "action", "path"])
        );

        let many = fs_action_schema("read_many").unwrap();
        assert!(many["inputSchema"]["properties"].get("path").is_none());
        assert_eq!(
            many["inputSchema"]["required"],
            json!(["target", "action", "paths"])
        );

        let search = fs_action_schema("search").unwrap();
        assert!(search["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("pattern")));
        assert!(fs_action_schema("nope").is_err());
    }

    #[test]
    fn job_ids_must_be_eight_hex_characters() {
        let operations = operations();
        let status = &operations["jms_job_status"]["inputSchema"];
        assert!(validate(status, &json!({"targets": ["a"], "job_id": "abcd1234"})).is_ok());
        assert!(validate(status, &json!({"targets": ["a"], "job_id": "not-a-job"})).is_err());
    }
}
