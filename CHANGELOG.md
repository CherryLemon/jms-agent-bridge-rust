# Changelog

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
