# Changelog

## 0.3.5

Evidence can only become more certain, never less; every result that is created has an
owner that closes it.

### Execution evidence
* An error that carries no transmission evidence is now `unknown`, not `not_started`:
  the blanket `BridgeError -> ExecFailure` conversion no longer claims "nothing was
  sent". Call sites that proved it use `before_send` explicitly.
* A retry that succeeds and then fails to attach its annotation (`store.annotate`)
  keeps the completed verdict, the result id and the exit code, and reports the write
  failure as `local_error: true`.
* Terminal commands: the worker marks the command `may have been sent` *before* writing
  the packet, and a failed or timed-out write leaves the state `unknown` instead of
  reverting it to `not_started` - the packet starts with `builtin eval`, so a partial
  write can still run the script.

### Result lifecycle
* `ResultLease` now also covers the staging payload write (`save_serialized`) and the
  terminal's stream-file creation: a failure after `create()` closes the result and
  releases the active slot instead of leaving an entry cleanup would skip.
* The rsync transfer writes to the caller's evidence flag, so an aborted transfer is
  reported as `unknown` rather than `not_started`.

### Terminal concurrency
* The takeover decision stays under the command lock, but the packet write happens
  outside it, with a 120 s bound. A channel that stops consuming can no longer hold the
  lock, so `close` can still take it and abort the worker.
* The worker's task handle is published before the worker may run (start gate), so
  `close` always sees a handle to abort.

### Jobs
* `jms_job_wait` records each host's answer as it arrives (`status_incremental`) and
  drops targets that reached a terminal state from later probes: a host that finished in
  the current round keeps its verdict even when another host never answers.

### Sessions and latency
* Session state is set by the path that touched the shell (success -> active, restart
  refusal / dead channel -> lost, queue timeout -> snapshot). The generic
  "named session means active" fallback is gone.
* Reporting a finished command no longer calls `pool.connection()`: the connection label
  comes from a read-only snapshot, so an expired connection cannot trigger a new login
  on the response path.
* `run` shares one `Arc<str>` script across targets.

### Known issue (tracked, not fixed here)
* Large downloads through the relay fail: rsync exits 12 with "connection unexpectedly
  closed" after roughly 0.7-1.6 MB, while uploads of the same file succeed (25-41 MB/s
  measured on the test asset, 64 MiB). Verified against the unmodified 0.3.4 code as
  well, so it predates this change. A two-task relay (independent uplink/downlink) was
  implemented and produced the same symptom, so the cause is not the pump structure; the
  remote sender appears to receive an early EOF/close. Downloads of small files (the
  live suite uses ~1.9 KB) are unaffected.

## 0.3.4

Fault-path pass: what the caller is told when something fails locally, and what the
terminal does when a command is accepted but the worker has not started.

### Execution evidence
* `execute_to_store` returns a failure that carries the evidence it already had:
  `result_id`, `executed`, `execution_state`, `completion_unknown`, `exit_code` and
  `failure_stage`. A local write failure after a completed run is reported as
  `completed` with `local_error: true`, never as `not_started`.
* Only a proven pre-send failure is `not_started`; a panicked or cancelled fan-out task
  is `unknown`; `error` and `local_error` are part of the projected row.
* Fan-out still reports every target, now with the right verdict per target.

### Result lifecycle
* `ResultStore::finish` releases the active slot whatever happens to the metadata write,
  and `ResultLease` closes a result whose producer disappears (task aborted, caller
  gone, panic) as `not_started` or `unknown` depending on whether anything was sent.
  Run and transfer results both use it.
* A terminal command that is accepted but whose terminal registry cannot be saved rolls
  the admission back: the command slot is cleared, the result is closed as
  `not_started`, and the terminal is not left permanently busy.

### Terminal
* The worker takes the command over and writes its first packet under the command lock:
  a `close` that ran first wins and nothing is sent; a worker that took over first makes
  `close` report `unknown`. The final state can no longer be flipped by a late worker.
* The worker refuses to overwrite a command that is no longer queued.

### Jobs
* `jms_job_wait` keeps each host's last answer: a scan that runs out of budget marks only
  the pairs it never observed with `watch_timeout: true` instead of replacing a known
  `done`/`running` with `unknown`.

### Sessions
* Session state is explicit: a rejected reuse after a restart reports `lost`, a queue
  timeout reports a non-blocking snapshot instead of a guess, and the "a registered id
  must be active" fallback is gone.

### Connections and terminals
* SSH authentication uses one absolute deadline (90 s) for algorithm negotiation, key,
  password and every challenge round, so a gateway that keeps prompting fails instead of
  holding the login gate.
* A long-poll terminal `read` no longer holds the command lock while waiting: the worker
  can publish `running` and write output immediately.

### Performance
* The tool catalog is built once per process and shared by every server instance, which
  also covers the stateless HTTP path that builds a server per request.
* Multi-target jobs share one `Arc<str>` script instead of copying it per target.
* Journal request locks are weak references and are pruned, so the lock table no longer
  grows with every request id ever seen.
* Staging borrows the serialized payload for its preview instead of copying it.

## 0.3.3

Correctness follow-up on the 0.3.2 lifecycle work, plus the latency fixes that the
higher concurrency exposed.

### Jobs
* `launch_state` is derived from execution evidence in one place: an unknown
  execution state stays `unknown`, a launcher that only timed out waiting for its
  runner (exit 5) stays `unknown`, and only the launcher's own refusals (exit 3/4)
  or a failure proven to happen before sending become `rejected`.
* `jms_job_wait` treats `cancelled` as terminal and bounds every status scan and
  sleep by the remaining budget; a scan that cannot finish reports
  `status=unknown, watch_timeout=true` without touching the remote job.
* Multi-target submission and status run with bounded concurrency (4 in flight).

### Sessions
* Registry saves take a lock across snapshot+write+rename: a stale snapshot can no
  longer be renamed over a newer one and silently drop a session after restart.
* A status query never waits on a shell that is executing: `sessions()` reports
  such a shell as `running` from a `try_lock` snapshot.
* The final result uses the session state the attempt already carries instead of
  re-locking the shell, so a finished request cannot wait behind the next command.

### Terminal
* Admission is atomic (check + reserve + install under one lock), so two concurrent
  execs cannot both start; a command is busy from admission, before its worker
  handle exists.
* The exec response is bound to the command that was admitted.
* One stream ending no longer ends the command while the other still holds a
  queued completion marker (`Data`/`StreamClosed`/`AllClosed`).
* `session_list` shows `running` for a terminal with a command in flight.

### Receipts and results
* A pre-send failure closes the result as `not_started` and releases its active
  slot instead of leaving a phantom active run.
* Fan-out keeps every target's outcome: a failed target becomes its own row.
* Terminal exec records its result id before sending, and `request_status`
  projects the live state of the stored result under both the rows and the
  top-level result id.
* Journal progress uses one lock per request instead of one global lock.

### Performance
* One REST client per inventory refresh (the detail fan-out shares its connection
  pool), and `ensure()` re-checks after taking the refresh lock so a slow
  cold-start refresh cannot trigger a second full fetch.
* Full tool schemas are built once and indexed; the advertised list is shared
  instead of cloned per call.
* Staging serializes a payload once and reuses the bytes for the size decision,
  the preview and the saved file.

### Tests
* `tools/list` budget is measured on the real envelope (real instructions text and
  each tool's own annotation flags): 7047 bytes, ~1.8k tokens *estimated*; the
  live service reports 6795 bytes for the tool list alone.

## 0.3.2

Lifecycle and state-transition pass. Every item below changes what the caller can
observe, and each has a regression test.

### Jobs
* A tracked `job_id` no longer implies a started job: the response carries
  `launch_state` (`acknowledged`/`rejected`/`unknown`), `launched` is true only for
  an acknowledgement, and rejected/unknown rows keep `stderr`, `result_id`,
  `execution_state` and `completion_unknown` so a failure cannot look like success.

### Connections
* The recovery lease now covers the whole remote exchange (submit, prime, capture,
  rsync transfer) instead of being dropped before the first byte, and an idle
  interactive terminal registers as a protection. A startup failure on a new
  channel can no longer replace a connection that other work still uses.
* Admission and the active counter are taken under one lock, so no new operation
  can enter once a replacement starts draining.

### Queue
* The execution slot travels through the grant channel as an RAII permit: a grant
  that is delivered but never claimed (cancelled task, dropped future) returns its
  capacity when the message is dropped.

### Terminal
* A closed output stream without its completion marker now ends the command as
  `unknown` immediately instead of polling a dead receiver until the deadline;
  `prime()` uses the same rule.
* Closing a terminal with a running command records the transition (`unknown`,
  `completion_unknown: true`, `failure_stage: closed_by_caller`) before the binding
  disappears; a queued command records `not_started`; finished work keeps its verdict.

### Persistence
* `ProgressSink::record` returns `BridgeResult<()>`; the writes that must exist
  before remote work (result-id association, prepared job receipt) are now fatal,
  so a failed persistence stops the operation instead of sending it untracked.
* The transfer result id is announced before `rsync` starts, not after it returns.

### Output contract
* `call` responses with `request_id` go through the same 8 KiB staging as direct
  calls; a staged summary always keeps `request_id`, `request_state`,
  `execution_state`, `completion_unknown`, `duplicate` and `execution_replayed`.
* The `fs` compact view no longer strips `staged`/`result_id`/`preview`/`note`.

### Other
* `session_list` reports the real state of each named shell instead of a hardcoded
  `lost: true`.
* Per-shell locking: the shells map is only held for lookup/insert, so two targets
  no longer serialize their whole sessions.
* The `tools/list` budget test measures the full envelope (annotations included):
  6478 bytes, ~1.6k tokens, from 10.2 KB before the options/discover split.
* Removed a leftover debug test that wrote into `/root`.

## 0.3.1

Correctness pass after an external review of `0.3.0`: the item below changes
behaviour, the rest closes gaps between modules.

### Behaviour changes
* The gateway host key is verified by default (`~/.ssh/known_hosts` or
  `bridge.known_hosts`); an unknown or changed key is refused instead of
  accepted silently.
* An asset with several permitted accounts is no longer resolved by guessing:
  set `bridge.preferred_account`, otherwise it stays explicitly unusable.
* `jms_job_cancel` reports the real outcome (`killed`, `status_before`,
  `already_finished`, launcher `result_id`) instead of forcing `ok: true`.
* `jms_list_assets` pages (`offset`/`limit`/`next_offset`), `jms_job_logs`
  defaults to a 4 KiB window, and any `call` response above 8 KiB is saved and
  returned as a bounded summary with a `result_id`.
* Authentication has a 60 s budget: a gateway that keeps prompting fails with an
  authentication error instead of holding the request.

### Fixed
* A run whose channel closed after the start marker but before any completion
  evidence is now `unknown`; an exit status that arrives after `Eof` is kept;
  an exit status without the start marker is never treated as success.
* `pump` flushes buffered output when the channel ends, so the tail of a run is
  not lost; split end markers are reassembled.
* Terminal commands wait for *both* streams, and a start+end pair in one packet
  registers as started.
* Named shells keep their launch configuration: reusing a `session_id` with a
  different container/image is refused, and a timed-out shell is closed and
  marked lost instead of being reused while an unknown command is in flight.
* A cancelled queued task returns its execution slot instead of leaking it, and
  cancelled waiters no longer inflate the queue depth.
* Request progress rows are written under one journal lock, so concurrent
  targets cannot overwrite each other; run/transfer progress records the result
  id before the response is written.
* `doctor` uses a throwaway state directory and never touches a live service;
  `probe` takes the state lock, or speaks to the running service over HTTP.
* stdio logging goes to stderr, so stdout carries protocol frames only.
* The rsync relay forwards protocol bytes that share a packet with the readiness
  marker.
* The job launcher acknowledges a job that already finished, and detached
  commands receive absolute paths instead of a `$R` the tmux server may not have.
* A transient error while reading one asset detail fails the whole refresh and
  keeps the previous snapshot; only an explicit 403/404 removes an asset.
* `NO_PROXY` is honoured for the REST client, and an inherited egress proxy is
  no longer used for hosts it excludes.
* The advertised schemas shrank from 10.2 KB to 5.8 KB; validation uses the
  complete definitions, and `discover(operation=<tool>)` returns them.
* `env` values are type-checked before execution (`{"A": 0}` is rejected instead
  of silently dropped), and the schema test that used to swallow validation
  errors now runs a valid and an invalid sample per tool.
* `session_list` reports both session kinds and `session_close` resolves the
  handle; the recovery tracker follows the pool's real connection generation and
  refuses to replace a connection that still carries named shells.
* A `run` fingerprint is computed over the normalized call, matching the Python
  bridge so an equivalent retry is recognized across implementations.

## 0.3.0

Rust reimplementation of `jms-agent-bridge` (reference `fd2085f`), following its migration plan.

### Added
* One resident runtime that owns the REST inventory, pooled SSH connections,
  persistent shells, saved results, request receipts and background work.
* Seven-tool MCP surface (`run`, `fs`, `terminal`, `read_result`, `discover`,
  `call`, `meta`) with compact responses by default and hidden operation schemas
  served on demand.
* Explicit execution states (`not_started` / `completed` / `unknown`) backed by
  remote markers, plus `request_id` receipts that make replays visible and never
  re-execute accepted work.
* Byte-exact saved streams with previews, `read_result` paging/tail/pattern.
* Transfers over a private Unix socket relay into the pooled SSH connection
  (`jms-bridge rsync-relay`), with readiness markers for the JumpServer gateway.
* Persistent shells, bound interactive terminals (open/exec/read/write/close),
  and detached jobs (tmux or setsid) with status/log/wait/cancel.
* Accelerator inspection that keeps the validated remote Python collector.
* `serve` (streamable HTTP `/mcp`, plus `/healthz` and `/service`) and `--stdio`
  transports, `doctor` and `probe` diagnostics.
* Proxy support for both REST and SSH (HTTP `CONNECT`, or `ssh_proxy_command`)
  and keyboard-interactive password authentication.

### Removed (relative to the Python bridge)
* `jms_cluster_*`, `jms_dev_*`, audit, ticket, workspace and attestation tools.
* YAML inventory as a source of truth; only an optional metadata overlay remains.
* asyncssh/paramiko and the `ssh`/`sshpass` command line.

### Fixed during bring-up
* Session registry treated a brand-new `session_id` as lost after a restart.
* rsync relay deadlocked on the first handshake and never closed the local
  socket when the remote side finished.
* Detached jobs could not expand the job root inside the launcher shell.
* The embedded inspection payload lost its Python indentation and could not
  register its synthetic modules for `dataclasses`.
