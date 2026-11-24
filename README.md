# jms-agent-bridge (Rust)

A resident bridge between MCP clients and JumpServer: one process owns the REST
inventory, the pooled SSH connections, the saved results and the background work,
and exposes a deliberately small MCP surface — eight tools — so that an agent can
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
* **Fail closed.** The gateway's host key is verified against `known_hosts` (an
  unknown or changed key is refused), an asset with several permitted accounts
  stays unresolved until one is configured, and a script whose completion cannot
  be proven is reported as `unknown` rather than as a finished run.

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

[bridge]
preferred_account = "root"   # required when assets permit several accounts
# known_hosts = "~/.ssh/known_hosts"
```

`~/.config/jms-bridge/credentials.toml` (mode `0600`):

```toml
[credentials]
access_key_id = "..."
access_key_secret = "..."
# Alternatively use session_token or private_token.
```

Access keys use JumpServer's HTTP Signature (HMAC-SHA256), signing the exact
request path and query plus `Date` and `Accept` (`X-JMS-Org` when configured).
A complete access-key pair takes precedence over session/private tokens. Keep
credentials outside the repository; never include them in logs or command-line
arguments. The resident process reads credentials at startup: updating the file
or calling `jms_inventory_reload` does not reload credentials. Coordinate a
service restart after active work and persistent terminals have been reconciled.

Every value can also come from the environment: `JMS_BRIDGE_URL`,
`JMS_BRIDGE_SSH_PORT`, `JMS_BRIDGE_LOGIN_USER`, `JMS_BRIDGE_SESSION_TOKEN`,
`JMS_BRIDGE_PRIVATE_TOKEN`, `JMS_BRIDGE_ACCESS_KEY_ID`,
`JMS_BRIDGE_ACCESS_KEY_SECRET`, `JMS_BRIDGE_VERIFY_TLS`, `JMS_BRIDGE_CONFIG`,
`JMS_BRIDGE_CREDENTIALS`, `JMS_BRIDGE_STATE_DIR`, `JMS_BRIDGE_KNOWN_HOSTS`.
Tokens may live in `[bastion]`, in `[credentials]`, or in the environment; the
environment wins.

The gateway's host key is **always** verified: the bridge reads
`~/.ssh/known_hosts` (or `bridge.known_hosts`), refuses hosts that are not
pinned, and refuses keys that changed. Nothing is accepted implicitly.

SSH authentication must complete without further interaction: a private key, a
password, or the password prompt of keyboard-interactive authentication. The whole
sequence shares one 90-second budget, so a gateway that keeps prompting fails with
an authentication error instead of holding the login gate.

When JumpServer permits several accounts on one asset the bridge does not pick
one: set `bridge.preferred_account` to the account you want, or the asset stays
explicitly unusable and `discover(topic='assets')` says so.

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
`meta`/`discover` tools report. With `--stdio`, stdout carries protocol frames
only and all logging goes to stderr. Only one process may own the state
directory; `serve` and `probe` take an exclusive lock, and `doctor` never touches
a live state directory (it uses a throwaway one, so it cannot disturb a running
service).

## The eight tools

| Tool | Purpose |
| --- | --- |
| `run` | Run literal Bash on REST-authorized targets, with `cwd`, `env`, container/image, named shells and per-target results. |
| `fs` | Explore or transfer files on one exact asset: `list`, `stat`, `read`, `read_many`, `glob`, `search`, `tree`, `checksum`, `upload`, `download`. |
| `terminal` | Bound interactive shells: `open`, `exec`, `read`, `write`, `close` — for REPLs and prompts that need stdin. |
| `job` | Submit, wait, inspect, cancel or list detached jobs; pass submit handles to a batch wait. |
| `read_result` | Page one saved stream by byte offset with optional `head_lines`, by `tail`, or by literal `pattern` search. |
| `discover` | List operation categories, search hidden operations, and read one operation's full schema. Also lists assets (`topic="assets"`) and live status (`topic="status"`). |
| `call` | Execute one whitelisted operation by name (jobs, inspection, inventory, sessions, receipts). |
| `meta` | Service/result/request metadata: summary, timing, transport, policy. |

`call(operation="session_list")` reports both kinds of handle (`kind: "shell"`
for `run(session_id=...)`, `kind: "terminal"` for `terminal(action="open")`), and
`session_close` accepts the `kind` or works it out from the handle. A handle with
a command in flight is reported as `running`; the query never waits for that
command, so status latency does not grow with command duration. A terminal accepts
one command at a time: a second `exec` is refused with "terminal is busy".

For a command's saved output, call
`terminal(action="read", session=..., options={"result_id":"..."})`
(or legacy `terminal_read` with the same ID). It reads that command even if a
new command owns the terminal or the server has restarted. Use the returned
cursor for subsequent pages; explicit cursors do not move the implicit session
cursor. Omit the result ID to read the session's current command as before.

For a short command that may print before exiting, set
`options={"wait_for":"completed","wait_ms":15000}` on terminal `exec`, `read` or
`write`. The legacy equivalents accept the same fields directly. The default
`wait_for="output"` returns on available output or a terminal state, which is
useful for interactive prompts. Completion mode waits for a terminal state
within the observation budget; `wait_ms=0` reads immediately and the maximum is
30,000 ms. An expired wait neither cancels nor replays the command. The reply
still includes the observed state, result ID and cursor; if it has `more`,
continue reading that same command with its `result_id` and cursor. Changing
wait or paging options does not change a journaled request's execution identity.

For a delayed close, use
`terminal(action="close", session=..., options={"expected_result_id":"..."})`
(or legacy `terminal_close` with `expected_result_id` directly). If that result
is still the current command, the close response includes its ID. If the
session has a different command, no live command, or was already closed, the
guarded request does not close or remove it. Omitting `expected_result_id`
retains whole-session close. The guard is available only for close; stdin,
signals and EOF are unchanged.

If sending a command fails or times out, that shell is marked lost and cannot
accept another command. Keep the result ID to reconcile the uncertain outcome;
open a new terminal explicitly rather than replaying the command automatically.

Advanced fields live in an `options` object so the advertised schema stays small;
`discover(operation="run"|"fs"|"terminal"|"job")` returns the complete schema, and
`discover(operation="jms_fs", query=<action>)` narrows it per action. Everything
that is accepted but not advertised is still validated before any side effect.

Add `view="signature"` to an operation search or exact lookup for a one-line
signature derived from the schema. Required arguments are listed first,
optional arguments are marked with `?`, selected common bounds are included,
and an action-specific lookup fixes the action
(e.g. `discover(operation="jms_fs", query="read", view="signature")`).
Omit `view` for the normal search summary (including signatures) or the full
schema of an exact operation or filesystem action.

`topic="operations"` responses include a static `catalog_version` and an
`etag` scoped to that bridge instance, query, operation, view, limit and offset.
Conditional discovery is optional. Send that `etag` as `if_none_match` on the
same request; a hit returns only `{"unchanged":true}`. A miss returns the full
requested representation with a fresh tag. If the cached body is unavailable,
omit `if_none_match` to retrieve it. The tag and version add about 180 bytes to
an uncached response, which can outweigh the payload of a one-line lookup;
caching is most useful for repeated lists and full schemas.

`topic="assets"` uses a separate `inventory_version` for the authorized
snapshot and a page-specific `etag`. Asset rows are ordered by normalized
asset ID before they are persisted, paged, or hashed. Duplicate IDs are
retained, with ties ordered by the serialized row.
A matching `if_none_match` returns
`unchanged: true`, the version and `last_success`. Tags are scoped to the
issuing bridge and exact query, representation, limit and offset. The bridge
does not return a hit for snapshots only loaded from disk, stale snapshots,
or while a refresh is in progress or has failed; it returns the normal full
page and freshness/error diagnostics instead. This does not force an extra
REST refresh or change the inventory refresh cadence. Live status remains
uncached.

Listings are paged (`offset`/`limit`, `next_offset` in the answer) and a `call` or `job`
response above 8 KiB is saved whole: the reply then carries `staged: true`, a
business summary and a `result_id` that `read_result(stream="result")` reads back.

For truncated `run` output, each affected stream in `preview_ranges` lists
`shown` and `omitted` source byte offsets as half-open ranges, independent of
JSON escaping or lossy text encoding. Stdout previews a prefix and stderr a
suffix. Follow the read-only `next_action` where present; for more than one
page, continue with `next_offset` until the omitted range ends. The output
byte budget still applies across all targets; a row with no preview bytes
can still give ranges for its retained output. Older receipts may lack ranges.


For a saved stream, `read_result(head_lines=N)` stops at the Nth newline or the
byte limit, whichever comes first (an ordinary UTF-8 page may extend by up to
three bytes). Use the returned `next_offset` to continue even if the limit was
reached in the middle of a line. Do not combine `head_lines` with `tail` or
`pattern`.

### Execution contract

* `execution_state`: `completed` (start and finish markers seen), `not_started`
  (proven unsent: login, queue or validation refused it), or `unknown` (the bytes
  may have reached the remote side, but no completion evidence exists). An
  `unknown` result is never replayed automatically. Closing a terminal or hitting
  a timeout with a command in flight moves it to `unknown`; it never stays
  `running` after the handle is gone.
* `launch_state` (jobs): `acknowledged`, `rejected` or `unknown`. Only an
  acknowledgement sets `launched: true`; the `job_id` is reported in every case so
  a lost reply can be reconciled.
* `request_id` (`^[A-Za-z0-9_.:-]{1,128}$`) records a receipt before the first
  side effect. A duplicate call returns the same receipt with
  `execution_replayed: false` plus the stored result; it does not run again.
  Recover a lost reply with `call(operation="request_status")` or
  `meta(ref="request:<id>")`.
* `queue_full` is an unsent per-target refusal: nothing ran, so retrying is safe.
* `jms_job_wait` stops at `done`, `failed`, `cancelled` or `missing`. A scan that
  cannot finish inside the remaining budget reports `status:"unknown"` with
  `watch_timeout:true`; the remote job is never cancelled by a timeout.
* A durable write is a precondition: if the result id or the prepared job receipt
  cannot be persisted, the operation stops before anything reaches the remote side.
  A write that fails *after* the work ran is reported next to the real verdict
  (`local_error: true`), never as `not_started`.

### Detached jobs

```text
job(action="submit", targets=["worker-a", "worker-b"], command="…", request_id="build-42")
job(action="wait", jobs=[{"target":"worker-a","job_id":"1a2b3c4d"},{"target":"worker-b","job_id":"5e6f7890"}])
```

Read the current bounded suffix with
`job(action="logs", target="worker-a", job_id="1a2b3c4d", tail=true)`.
The legacy `jms_job_logs` operation accepts the same flag under `arguments`,
using `host` instead of `target`. The returned `offset` is the first source
byte of the suffix. To follow later appends, omit `tail` and pass
`next_offset` as `offset`. Do not supply `tail=true` and an explicit
`offset` together. Cursors advance by the raw source bytes actually read,
including when text decoding replaces a partial UTF-8 sequence.


Search the same log with a literal `pattern` (up to 1024 UTF-8 bytes),
instead of `tail`. Start with `offset` (default 0); repeat the same pattern
and pass `next_cursor` as `cursor` on later calls. Each call scans at most
1 MiB of source and returns at most 20 excerpted matches; `max_bytes`
bounds the match-array JSON separately. Each match has a source `offset`
and its excerpt starts at `text_offset`. A no-match page can still have
a continuation. `eof` refers to the sampled file size, so the cursor can
also be used after later appends to catch a literal crossing the append
boundary. A changed file identity or observed truncation returns
`reset: true`; restart without the cursor if you want to scan the
replacement log. A cursor is scoped to the resolved job and pattern,
and never grants access.

Pass the returned `jobs` array directly to `wait`. `submissions` carries per-target
launch evidence, including rejected launches that do not get a wait handle. A
concurrent duplicate can report `request_state: "running"`; retry or reconcile
the same ID to recover its final handles. An equivalent legacy
`call(operation="jms_submit_job", request_id=...)` uses the same durable receipt.
`wait` returns ordered `status` rows and a reusable `pending` array if the shared
watch deadline expires. The timeout never cancels a job. Large diagnostics are saved
under `result_id`; `jobs` or `pending` remains inline when it fits. If the
handles themselves are too large, the same field contains `{"ref":"<id>"}`.
Pass that object unchanged as `jobs` to continue; the bridge checks each target
against the current permitted inventory before probing it. Legacy
`call(operation="jms_job_wait")` with a single ID is unchanged.

An inline `jobs` or `pending` array marked `remote_job` can be copied to another
bridge. The receiving bridge must resolve the same asset, use an account that
can read the same remote job state, and resolve the same job directory. The
directory is derived from the target working directory, falling back to
the remote account's `$HOME`. If bridge A uses a different working directory
or bridge B resolves a different home, B may report `missing` even with the
same asset and job ID. Verify the directory and account on both bridges
before interpreting that status; it is not a reason to resubmit.
For one usable handle the response can include a read-only
`next_action` invoking `jms_job_status`; it does not re-submit the command.
Save the inline handles with your task before switching execution machines.
A staged `ref`, `request_id`, or `result_id` marked `bridge_local` depends on
the original bridge's state store. If you only have a local reference, obtain
the inline handles from that bridge before switching. If the original bridge
is unavailable and no remote handle is known, keep the outcome uncertain;
do not submit again based on the missing local receipt.

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
* The advertised schema carries only the common fields plus an `options` entry
  point (under 7 KiB for all eight tools, down from 10.2 KB with every field
  spelled out); validation always uses the complete definition, and
  `discover(operation=<tool>)` returns it. The `fs` action fields are documented
  per action through `discover(operation="jms_fs", query=<action>)`.
* `detail=compact|full` is still accepted but no longer advertised: it costs a
  line in every schema and the default is already the compact form.
* `terminal` accepts `target` at the top level as well as inside `options`.
* A `run` fingerprint is computed over the normalized call (defaults filled,
  unset optionals as `null`), matching the Python bridge, so an equivalent retry
  is recognized as a duplicate across the two implementations.
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
