# Changelog

## 0.4.1

Follow-ups on the 0.4.0 teardown and progress work.

* The uplink closes its SSH channel explicitly when it stops on its own: aborting a task
  that holds the writer never sends SSH Close, so the channel is now released by the
  direction that owns it.
* Teardown ends the child before reaping the pumps. The stdout/stderr watchers are
  blocking reads that cannot be aborted early; they finish when the child's pipes close,
  so reaping first only spent the grace period and detached the handles.
* Live progress is served from memory (`ResultStore::live_progress`) and flushed to disk
  once every five ticks. A polling caller no longer forces a durable metadata write per
  second, and the overlay is dropped as part of the final verdict.
* Verified live: 1 GiB download, 24 in-flight samples (`progress_source: "rsync"`,
  `protocol_bytes` tracked separately), final row 100% of the exact stat size, SHA-256
  match.


## 0.4.0

Review round after 0.3.9: path handling, progress semantics and teardown edges.

### Fixed
* **Remote paths keep their spaces.** `-s` (`--protect-args`) is back in the archive
  flags. Without it rsync shell-escapes the paths it hands to the remote shell, and the
  relay passes argv straight to `exec "$@"`, so `/tmp/a b.bin` arrived as
  `/tmp/a\ b.bin` - a download missed the file and an upload could land under the
  escaped name. Verified end to end with `/tmp/a b.bin` (name and content identical both
  ways).
* **A failed or timed-out transfer no longer reports 100%.** The final snapshot only
  resets the total after a successful run; a cut-short transfer keeps the real total and
  its partial amount (live: 230 MB of 1 GiB reported as 21%, exit 124,
  `completion_unknown: true`). `eta_seconds` is cleared when the outcome is decided,
  because metadata updates merge.
* **Progress separates file bytes from protocol bytes.** `--info=progress2` numbers drive
  `bytes_done`/`progress_pct` (`progress_source: "rsync"`); relay traffic is reported as
  `protocol_bytes` for throughput and backpressure only. They differ as soon as
  compression, resume or a directory is involved.
* **The progress projection carries the verdict** (`ok`, `exit_code`,
  `completion_unknown`, `execution_state`), so a partial percentage is not mistaken for
  success.
* **A late progress tick cannot overwrite a verdict.** `annotate_if_running` refuses once
  the result is finished, and the reporter is aborted and awaited before the final
  metadata is written.
* **The reporter is no longer leaked** when the transfer receipt fails to persist: it is
  spawned only after the receipt is durable.
* **Teardown keeps its handles.** `quiesce()` aborts and awaits the accept task when it
  does not stop in time, instead of detaching it; a handshake that ignored the stop flag
  can no longer create a channel after the transfer was declared finished.
* **Idle deadline for blocking I/O.** `--blocking-io` means a stalled peer blocks inside
  the syscall, so the owner now watches the byte counters and ends the transfer after
  600 s without progress, reported the same way as a timeout.
* **`terminate` no longer parks a runtime worker** for up to 15 s: it polls the child
  with async sleeps.
* **The `-e` wrapper path is quoted for rsync**, which re-splits that value - a `TMPDIR`
  with a space no longer breaks every transfer.
* **`--info=progress2` is only passed to rsync 3.1+**; a 3.0.x binary passes the
  `-s --version` check but rejects the flag.
* **Config ranges are checked before narrowing to `u32`**, so a value that would only
  fit after truncation (e.g. `4297064448`) is rejected instead of silently accepted.
* **The relay test watchdog is joinable**: a passing run ends the thread instead of
  leaving a 90 s sleeper that could signal a recycled PID.


## 0.3.9

Transfers report their own progress, and the transfer path is tunable.

### Progress
* `fs upload`/`fs download` now count the bytes that actually cross the relay and
  return them as `progress: {bytes_done, total_bytes, progress_pct, rate_bps}`.
* While a transfer runs, `meta(ref="result:<id>", section="progress")` reports live
  numbers, renewed about once a second. The result id is available from
  `request_status(<request_id>)` (the row shows `result_status: running`), so a caller
  can watch a long transfer without holding the original call open.
* `total_bytes` comes from the local file for an upload and from one `stat` for a
  download, so the percentage and ETA are known from the first byte; when the size
  cannot be determined the fields are simply omitted.
* rsync's `--info=progress2` status lines are parsed as they arrive. They go to rsync's
  **stdout** (not stderr), so both streams are piped through a writer that appends to the
  result files and feeds the same counters.

### Tuning notes (limited evidence)
The knobs above were measured once against the shared gateway with a 1 GiB incompressible
file, medians of three transfers per variant, and the run was stopped early because the
gateway is a shared resource:

| variant | upload | download |
| --- | --- | --- |
| default (compress, 2 MiB window) | 81.5 MB/s | 108.1 MB/s |
| `rsync_compress = false` | 80.2 MB/s | 114.1 MB/s |
| `ssh_window_size = 8 MiB` | 103.6 MB/s | 111.3 MB/s |
| `ssh_window_size = 16 MiB` | 88.1 MB/s | 80.3 MB/s |

Run-to-run spread on this link is large (one variant swung from 111 to 39 MB/s between
passes, and one transfer died with a gateway-side broken pipe), so these numbers show
*no regression* and are not a ranking. A fair comparison needs a quiet link, alternating
variants, and per-direction CPU: only then should a default change.

### Robustness
* The remote shell is a single-token wrapper script in the transfer's private temp
  directory. A multi-word `-e` command made rsync materialise a helper next to this
  binary (`<dir>/.ps__<hash>`) that it later reaps; once reaped, every following
  transfer failed with "Failed to exec ... (deleted)" (rsync exit 14). The wrapper also
  removes a 25 MB copy per transfer.
* `-s` (protect-args) is gone for the same reason: the remote command is executed by the
  relay with `exec "$@"`, never through a remote shell, so it protected nothing.

### Tuning
* `bridge.ssh_window_size` (default 2 MiB) and `bridge.ssh_max_packet_size` (32 KiB)
  are handed to russh, and `bridge.rsync_compress` (default true) switches `rsync -z`.
  These are the two knobs the throughput work needs; both are validated on load.


## 0.3.8

Independent pumps, resumable transfers, and a shutdown rsync can survive.

### Relay
* The relay now runs one task per direction (socket->SSH, SSH->socket) instead of a
  single `select!` loop whose branch awaited the whole write. A write waiting for SSH
  window space can no longer stop the other direction from draining.
* A socket EOF half-closes the remote stdin and keeps the channel writer alive until
  the transfer stops; dropping it there used to tear the SSH channel down while the
  download direction was still streaming.

### Resumable transfers
* rsync now runs with `--partial-dir=.jms-partial`: an interrupted transfer keeps its
  data in a directory beside the destination, never under the final name, so
  `overwrite=false` still protects a complete file while a retry can reuse the partial.
* Timeout and error paths send SIGTERM first and only SIGKILL after 15 s, so rsync gets
  the chance to save its partial in its own cleanup. Verified live: a 256 MiB download
  interrupted at 3 s left `.jms-partial/` with no final file, and the retry with
  `overwrite=false` finished in 5.0 s with a matching SHA-256 (11.9 s from scratch).

### Notes
* The `.jms-partial` directory is left in place after a failed transfer on purpose; it
  is what makes the retry cheap. It is removed by rsync once the file completes.


## 0.3.7

One owner for the transfer, and progress that means progress.

### Transfer ownership
* `TransferOwner` holds the accept loop and both forwarding pumps and tears them down on
  every exit path. Before this, a failure while preparing the local side (log file,
  rsync spawn) left the accept task running for the life of the process, and a timeout
  left the pumps and their SSH channel alive.
* Teardown is ordered: stop accepting, reap the pumps, then read the evidence flag, so
  `sent` can no longer be snapshotted while a handshake is still updating it.

### Relay errors
* Both directions now publish their first failure into a shared slot; the process exits
  74 if either direction failed. The stdin->socket direction used to swallow errors and
  still exit 0, so a failed upload half looked like a clean end of stream.
* Errors are described with their `ErrorKind` (EAGAIN and EPIPE mean very different
  things here) and the byte count actually forwarded, incremented per successful write
  rather than per chunk. `Interrupted` is retried in both directions.
* A failure shuts the socket down, so the other direction stops instead of waiting for
  data that will never arrive.

### Idle budget
* "600 s without progress" now means what it says: `IdleBudget` records the last
  successful byte and is renewed by every write, with a separate total budget. The old
  helper started its 600 s clock when a chunk began and never refreshed it, so a slow
  but healthy transfer could fail while a stalled one could pass. Waiting is bounded
  and re-checked, so a blocking descriptor cannot hide the deadline either.

### Sessions
* The "shell is closing" rejection also reports `session_state: "lost"`, matching the
  restart rejection.

### Tests
* `relay_backpressure` now has a hard watchdog: if the relay ever deadlocks the child is
  killed at 90 s and the test fails instead of hanging.
* `IdleBudget`: intermittent progress keeps a transfer alive far beyond the idle limit,
  and a stalled writer times out without re-sending the prefix it already delivered.
* `ssh_proxy_command`: the helper keeps answering after the stream is built (the child
  used to be reaped immediately), and a helper that writes 300 KB to stderr still
  answers, which fails when the stderr drain is removed.


## 0.3.6

Large downloads work. The relay was being handed a non-blocking stdout and treated
`EAGAIN` as end of stream, so every long transfer stopped after a few hundred KB and
reported success.

### Two-way transfer
* rsync now starts the relay with `--blocking-io`, matching the synchronous writer in
  `rsync-relay`. Without it rsync gives a custom remote-shell a non-blocking stdout, a
  full pipe surfaces as `WouldBlock`, and the old relay returned 0 and exited - the
  remote side then saw EOF and both rsyncs reported "connection unexpectedly closed".
* The relay writes the protocol straight to fd 1 (no `stdout()` line buffer, whose
  flush can also return `WouldBlock`), retries `Interrupted`, waits out `WouldBlock`
  on the remaining suffix only - never re-sending a prefix - and gives up after 600 s
  without progress.
* A relay write or socket error is reported on stderr (never stdout, which carries the
  rsync protocol) with the byte count and errno, and the relay exits 74 instead of 0,
  so a truncated stream can never look like a clean transfer end.

Measured on the test asset with a 256 MiB incompressible file: upload 9.4 s
(28.7 MB/s), download 4.1 s (65.4 MB/s), size and SHA-256 verified; 64 MiB downloads
in 1.3 s. Before the fix the same download failed at 0.74-1.6 MB with rsync exit 12.

### Result lifecycle
* `ResultLease::borrowed` is gone. It held no store, so `save_serialized` neither
  finished nor abandoned its result: staged payloads stayed `status: running` with
  `active_results` never released. `save_serialized` now writes the payload and closes
  the result explicitly on both paths, and `write_staged` is the single place that
  owns that transition.

### Transport
* `ssh_proxy_command` keeps its `Child` inside `ProcessStream`: the child used to be
  dropped when the stream was built, and `kill_on_drop` killed the proxy immediately.
  The proxy's stderr is drained at debug level so a full pipe cannot stall it.

### Sessions
* A named session that is rejected after a restart reports `session_state: "lost"`
  instead of omitting the field.

### Tests
* New `tests/relay_backpressure.rs` drives the real relay binary with a *non-blocking*
  stdout (via `pre_exec`, exactly as rsync does) and a slow consumer: 8 MiB must arrive
  byte-exact with exit 0. It fails on the previous implementation.
* Staging lifecycle: a successful `save_serialized` must end `status: complete` with
  `finished_at`, byte sizes and no active entry; a payload write that fails after
  `create()` must leave no active entry.


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
