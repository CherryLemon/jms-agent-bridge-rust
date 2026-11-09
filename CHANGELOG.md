# Changelog

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
