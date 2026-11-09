# jms-agent-bridge (Rust)

A resident bridge between MCP clients and JumpServer: one process owns the REST
inventory, the pooled SSH connections, the saved results and the background work,
and exposes a deliberately small MCP surface — seven tools — so that an agent can
do everything without paying for a dozen tool descriptions on every turn.

This is a Rust reimplementation of [`jms-agent-bridge`](https://github.com/lvyufeng/jms-agent-bridge)
(reference commit `fd2085f`) following its migration plan: the same external behavior for
the compact surface, with the legacy Python extras (`jms_cluster_*`, `jms_dev_*`,
audit/ticket/workspace/attestation, YAML as a second source of truth) removed.

## Why this shape

* **One resident process.** Logins, SSH connections, session shells and results
  outlive a single MCP request. Disconnecting a client never cancels accepted
  work; the request can be reconciled by id afterwards.
* **Compact by default.** Every response is the short form. Full output is saved
  to disk and fetched on demand with byte offsets, so a 300 MB log costs a few
  hundred bytes on the wire.
* **Explicit uncertainty.** Each execution reports `not_started`, `completed` or
  `unknown`, backed by markers sent on the remote side. A lost reply is never
  retried blindly: `request_id` receipts make a replay visible instead.
* **No hidden shell.** Scripts are transported as literal data and executed with
  `bash -s`/`eval --`, never spliced into a generated command line.

## Build

```bash
cargo build --release
install -m755 target/release/jms-bridge ~/.local/bin/jms-bridge
```

Rust 1.88 or newer. No system libraries beyond libc and zlib/bluetooth-free
`reqwest` stuff: TLS is `rustls` with the `ring` provider, SSH is `russh`.

## Configuration

`~/.config/jms-bridge/config.toml`:

```toml
[bastion]
url = "https://bastion.example.com"
ssh_port = 2224
login_user = "your-login"
proxy = "http://proxy.internal:8080"   # optional, for REST + SSH
```

`~/.config/jms-bridge/credentials.toml` (mode `0600`):

```toml
[credentials]
session_token = "..."     # or private_token, or access_key_id/access_key_secret
```

Every value can also come from the environment: `JMS_BRIDGE_URL`,
`JMS_BRIDGE_SSH_PORT`, `JMS_BRIDGE_LOGIN_USER`, `JMS_BRIDGE_SESSION_TOKEN`,
`JMS_BRIDGE_PRIVATE_TOKEN`, `JMS_BRIDGE_ACCESS_KEY_ID`,
`JMS_BRIDGE_ACCESS_KEY_SECRET`, `JMS_BRIDGE_VERIFY_TLS`, `JMS_BRIDGE_CONFIG`,
`JMS_BRIDGE_CREDENTIALS`, `JMS_BRIDGE_STATE_DIR`.

See `examples/` for annotated files.

## Run

```bash
jms-bridge serve                 # streamable HTTP on 127.0.0.1:8766/mcp
jms-bridge serve --stdio         # stdio transport for local MCP clients
jms-bridge doctor                # config, REST health, permitted inventory
jms-bridge probe --target all    # one trivial command through the real path
jms-bridge version
```

The HTTP transport is stateless with JSON responses: `POST /mcp` speaks MCP,
`GET /healthz` answers liveness, `GET /service` returns the runtime status the
`meta`/`discover` tools report. Only one process may own the state directory;
the second one exits instead of racing on results.

## The seven tools

| Tool | Purpose |
| --- | --- |
| `run` | Run literal Bash on REST-authorized targets, with `cwd`, `env`, container/image, named shells and per-target results. |
| `fs` | Explore or transfer files on one exact asset: `list`, `stat`, `read`, `read_many`, `glob`, `search`, `tree`, `checksum`, `upload`, `download`. |
| `terminal` | Bound interactive shells: `open`, `exec`, `read`, `write`, `close` — for REPLs and prompts that need stdin. |
| `read_result` | Page one saved stream by byte offset, `tail`, or literal `pattern` search. |
| `discover` | List operation categories, search hidden operations, and read one operation's full schema. Also lists assets (`topic="assets"`) and live status (`topic="status"`). |
| `call` | Execute one whitelisted operation by name (jobs, inspection, inventory, sessions, receipts). |
| `meta` | Service/result/request metadata: summary, timing, transport, policy. |

Advanced fields live in an `options` object so the advertised schema stays small;
`discover` returns the exact hidden schema for each operation and each `fs` action.

### Execution contract

* `execution_state`: `completed` (start and finish markers seen), `not_started`
  (proven unsent: login, queue or validation refused it), or `unknown` (the bytes
  may have reached the remote side, but no completion evidence exists). An
  `unknown` result is never replayed automatically.
* `request_id` (`^[A-Za-z0-9_.:-]{1,128}$`) records a receipt before the first
  side effect. A duplicate call returns the same receipt with
  `execution_replayed: false` plus the stored result; it does not run again.
  Recover a lost reply with `call(operation="request_status")` or
  `meta(ref="request:<id>")`.
* `queue_full` is an unsent per-target refusal: nothing ran, so retrying is safe.

## State

Everything lives under `~/.local/state/jms-bridge` (`JMS_BRIDGE_STATE_DIR`):

```
results/<result_id>/{meta.json,stdout.log,stderr.log,result.json}
requests/<sha256>/{state.json}          # request receipts
assets.json                             # last permitted REST snapshot
terminal_sessions.json                  # shells that a restart cannot restore
```

Results expire after 7 days (`result_ttl_seconds`), with hourly cleanup; running
results are protected. A restart marks in-flight requests `unknown` and refuses
to revive lost interactive shells instead of replaying their last command.

The layout and the receipt fingerprint are identical to the Python bridge, so
the same state directory can be reused when switching binaries — see
`docs/migration.md`.

## Intentional differences from the Python bridge

* The script guard has no comment exemption (the Python guard ignored matches
  inside comments); the Rust guard is fail-closed and reports the matched
  patterns so an operator can decide.
* `jms_cluster_*`, `jms_dev_*`, audit, ticket, workspace and attestation tools
  are gone, as is YAML inventory as a source of truth; the REST snapshot is the
  only inventory, with an optional hosts overlay for display metadata.
* One SSH driver (`russh`) replaces asyncssh + paramiko.
* Interactive packets are a single physical line (`builtin eval --` with
  `$'…'` quoting) instead of a named argv helper, so a foreground REPL read
  cannot swallow the completion marker while `import x` still works.
* The `fs` tool advertises the union of its action fields instead of swapping
  schemas per call; `discover(operation="jms_fs", query=<action>)` narrows it.
* `detail=compact|full` is still accepted but no longer advertised: it costs a
  line in every schema and the default is already the compact form.
* `terminal` accepts `target` at the top level as well as inside `options`.
* The accelerator collector is the validated Python probe, base64-embedded in the
  binary, so a target needs `python3` for `jms_accelerator_status` only.

## Verification

```bash
cargo test                     # unit + offline contract tests
jms-bridge doctor              # REST + inventory
jms-bridge probe --target all  # SSH path, markers, saved results
```

A live run against a production JumpServer deployment covered multi-target `run`, 1.3 MB saved
output with paging, `request_id` dedupe, persistent shells, every `fs` action,
upload/download round trips, job lifecycle, timeouts, an interactive Python REPL
through `terminal`, accelerator inspection, and restart-interruption
receipts. The full matrix, plus what was deliberately not exercised, is in
`docs/verification.md`, and the switch/rollback story is in `docs/migration.md`.

## License

Apache-2.0; see `LICENSE`.
