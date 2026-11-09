# Verification

Everything below was executed against a live production deployment (JumpServer
`v4.10.18-ce` behind the KoKo SSH gateway) from the machine that hosts the
bridge, through that deployment's egress proxy. Host names, addresses and
credentials are deliberately not recorded here.

## Automated

| Suite | Command | Result |
| --- | --- | --- |
| Unit tests (guard, scheduler, results, journal, inventory, REST signing, schema, views, jobs, terminal, transport) | `cargo test --lib` | 97 passed |
| Offline contracts (tool list, schema validation, guard, receipts, saved-result reads, discovery) | `cargo test --test mcp_offline` | 1 passed |
| Exec-channel plumbing against a live bastion | `cargo test --test ssh_pipe -- --ignored` | passed (manual) |

## Live MCP session (`streamable HTTP`, stateless JSON at `/mcp`)

| # | Scenario | Observed |
| --- | --- | --- |
| 1 | `run` on two assets, shared 512-byte preview budget, `exit 3` | both rows `completed`, `exit_code 3`, `stdout_truncated`, `ok:false` |
| 2 | `run` `seq 1 200000` (>1.28 MB) then `read_result` | full stream paged to `eof` (1,288,895 bytes), `tail` and `pattern` correct |
| 3 | same `request_id` twice | second call `duplicate:true`, `execution_replayed:false`, same `result_id`, remote file written once |
| 4 | `session_id` reuse (`cd /tmp`, `export KEEP=42`) | second call shows `42` and `/tmp`; `session_close` succeeds |
| 5 | `fs` list/stat/read/search/glob/tree/checksum/read_many | all `ok`, line/byte cursors reported |
| 6 | `fs` upload + download of a 1.9 KB payload | `ok:true`, downloaded bytes identical, itemized `<f+++++++++`/`<f.st......` |
| 7 | `jms_submit_job` (tmux launcher) → status → logs → wait → cancel | `running`→`done` with pid and `exit_code`, logs by byte offset, `killed` reported |
| 8 | `run` with `timeout: 3` around `sleep 30` | `exit_code 124`, `timed_out`, `execution_state: unknown`, `completion_unknown: true` |
| 9 | `terminal open` → `exec python3 -i` → `write print(6*7)` → `eof` → `close` | prompt captured, `42` returned, state `closed` |
| 10 | `call jms_accelerator_status` on an accelerator host | 8 devices reported `busy`, with occupants, worker commands and container names |
| 11 | `call jms_exec` (legacy env/workdir path) | `ok`, `pwd` = `/root` from the asset's `workdir` |
| 12 | `call jms_inventory_reload`, `session_list`, `request_status`, `result_metadata` (summary/transport/timing/all), `meta(service, policy)` | all consistent: 99 permitted assets, receipts with `result_status` |
| 13 | hard `kill -9` mid-request, then restart | `request_status` reports `request_state: interrupted`, `completion_unknown: true`, nothing replayed |
| 14 | `discover` (categories, search, one operation schema, `topic=assets`, `topic=status`) | schemas served on demand; assets show `usable` and the resolved account |

## Deliberately not exercised here

| Area | Why | How to check |
| --- | --- | --- |
| Docker `container`/`image` execution | No Docker daemon on the probed assets | `run` with `container` on a host that has Docker |
| `session_id` loss across a normal (non-kill) restart | Requires restarting the resident service holding live shells | restart `serve`, then reuse the same `session_id`: expect `not_started` with "session state was lost" |
| Result expiry sweep (7 days) | Would need a week of wall clock | covered by unit tests with injected timestamps |
| Very large transfers (>1 GB) | Time budget | `fs` upload/download paginate by design; rsync streams without buffering |
| macOS/OpenSSH targets | Deployment is Linux-only | `platform` overlay field exists but probes assume GNU userland |

## Cross-host deployment check

The same release binary was copied to an unrelated asset and run there against
the gateway:

| Check | Result |
| --- | --- |
| `doctor` (REST) | full permitted inventory pulled over HTTPS, gateway version reported |
| `probe` (SSH) | refused as `not_started` |

The gateway did not accept the credentials this build provides from that host,
so the probe stopped before transmitting anything and reported `not_started`
rather than a partial success. The resident service therefore belongs on a host
whose authentication path (key or password) this build can complete.

## Notes and known limits

* The release binary in this workspace was built on Ubuntu 24.04 (glibc 2.39) and
  runs on Ubuntu 22.04 (glibc 2.35) with a `weak version GLIBC_2.39 not found`
  notice on stderr; the binary still executes correctly. Build on the oldest
  supported distribution, or in a `musl` target, for a warning-free artifact.
* JumpServer's gateway can drop channel bytes written before the target session
  is attached; every long-lived channel therefore waits for a readiness marker
  (`run`/`terminal`) or emits one from a remote shell wrapper (rsync relay).
* `fs` transfers go through a private Unix socket and a small relay child of the
  same binary (`jms-bridge rsync-relay <socket>`), so the local `rsync` must
  support `--protect-args` (`-s`, rsync 3.x).
* The interactive `terminal` packet is one physical line, so a foreground REPL
  read cannot consume the completion marker while `import x` still works.