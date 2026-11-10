# Verification

Everything below was executed against a live production deployment (JumpServer
`v4.10.18-ce` behind the KoKo SSH gateway) from the machine that hosts the
bridge, through that deployment's egress proxy. Host names, addresses and
credentials are deliberately not recorded here.

## Automated

| Suite | Command | Result |
| --- | --- | --- |
| Unit tests (guard, scheduler, results, journal, inventory, REST signing, schema, views, jobs, terminal, transport) | `cargo test --lib` | 154 passed |
| Relay backpressure (real binary, non-blocking stdout, slow consumer, 8 MiB) | `cargo test --test relay_backpressure` | 2 passed |
| Inventory refresh against a mock bastion (transient vs. explicit detail errors, account ambiguity) | `cargo test --test catalog_refresh` | 2 passed |
| Offline contracts (tool list, schema validation, guard, receipts, saved-result reads, discovery) | `cargo test --test mcp_offline` | 1 passed |
| Real `serve --stdio` subprocess: every stdout line parses as JSON-RPC while logging is at `info` | `cargo test --test mcp_stdio` | 1 passed |
| Exec-channel plumbing against a live bastion | `cargo test --test ssh_pipe -- --ignored` | passed (manual) |

Fixed in 0.3.6 (was: 64 MiB downloads failed with rsync exit 12 after 0.7-1.6 MB).
Root cause: rsync gives a custom remote-shell a non-blocking stdout unless
`--blocking-io` is passed, and the relay treated `EAGAIN` as end of stream and exited 0.

| 40 | 256 MiB upload | 9.36 s, 28.7 MB/s, exit 0, SHA-256 match |
| 41 | 256 MiB download | 4.11 s, 65.4 MB/s, exit 0, SHA-256 match |
| 42 | 64 MiB download | 1.29 s, 52.1 MB/s, exit 0, SHA-256 match |
| 43 | 8 MiB relay backpressure (non-blocking stdout) | full payload, exit 0, fails on the previous implementation |

Regression tests for the fifth review round (evidence monotonicity, result ownership):
`a_late_annotation_failure_keeps_the_completed_verdict`,
`an_unclassified_error_is_unknown_not_not_started`,
`a_failed_send_after_takeover_stays_unknown`,
`abandoning_a_result_releases_its_active_slot`.

Regression tests for the fourth review round (fault paths and state boundaries):
`a_store_failure_after_the_run_keeps_the_execution_evidence` (a local write failure
after a completed run stays `completed` and releases the active slot),
`a_presend_failure_is_still_reported_as_not_started`,
`closing_before_the_worker_takes_over_sends_nothing`,
`a_worker_that_took_over_first_is_reported_as_unknown_when_closed`,
`rolling_back_admission_only_clears_its_own_command`,
`a_long_poll_read_does_not_block_the_worker`,
`wait_rows_keep_known_statuses_and_flag_only_the_unwatched_ones`,
`the_tool_catalog_is_shared_process_wide`.

Regression tests for the third review round (evidence, races, admission):
`a_transmitted_but_unconfirmed_launch_stays_unknown`,
`a_launcher_that_only_timed_out_waiting_stays_unknown`,
`the_two_explicit_launcher_refusals_are_rejections`,
`a_failure_before_sending_is_a_rejection`,
`evidence_flows_through_the_classifier_into_the_row`,
`a_concurrent_save_cannot_overwrite_a_newer_snapshot` (fails without the registry
lock), `an_admitted_command_makes_the_terminal_busy_before_its_worker_exists`,
`a_single_closed_stream_is_reported_as_an_event_not_a_verdict`,
`a_cancelled_job_is_a_terminal_state_for_wait`.

Regression tests for the second review round (state and lifecycle):
`job_rows_distinguish_acknowledged_rejected_and_unknown` (launcher refusal is
never `launched`), `staged_summary_keeps_the_short_state_fields`,
`a_staged_payload_keeps_its_read_instructions`,
`granted_but_unclaimed_slot_is_returned` (permit dropped with its message),
`a_replacement_waits_until_the_active_operation_finishes` (lease held across the
remote exchange), `an_open_terminal_protects_its_connection`,
`a_closed_stream_without_its_marker_ends_the_command`,
`waiting_on_closed_streams_returns_immediately` and
`closing_a_terminal_records_the_right_command_state`.

Regression tests added for the defects found in the first review round: marker/exit-status
ordering (`start_then_close_without_status_is_unknown`,
`exit_status_arriving_after_eof_is_kept`,
`an_exit_status_without_the_start_marker_is_not_success`,
`end_marker_split_across_packets_is_reassembled`), terminal stream pairing
(`completion_needs_both_streams_and_matching_statuses`,
`capture_stream_waits_for_the_second_stream`), scheduler cancellation
(`cancelled_waiter_returns_its_slot`), journal fan-in
(`concurrent_progress_keeps_every_row`), rsync readiness
(`readiness_keeps_protocol_bytes_from_the_same_packet`), the job launcher
(`fast_job_is_acknowledged_even_though_its_process_is_gone`), host-key policy
(`missing_known_hosts_is_refused`, `known_hosts_defaults_to_the_ssh_file`) and
the tool-schema budget (`advertised_tools_stay_within_their_token_budget`,
`env_accepts_only_string_values`).

## Live MCP session (`streamable HTTP`, stateless JSON at `/mcp`)

| # | Scenario | Observed |
| --- | --- | --- |
| 1 | `run` on two assets, shared 512-byte preview budget, `exit 3` | both rows `completed`, `exit_code 3`, `stdout_truncated`, `ok:false` |
| 2 | `run` `seq 1 200000` (>1.28 MB) then `read_result` | full stream paged to `eof` (1,288,895 bytes), `tail` and `pattern` correct |
| 3 | same `request_id` twice | second call `duplicate:true`, `execution_replayed:false`, same `result_id`, remote file written once |
| 4 | `session_id` reuse (`cd /tmp`, `export KEEP=42`) | second call shows `42` and `/tmp`; `session_close` succeeds |
| 5 | `fs` list/stat/read/search/glob/tree/checksum/read_many | all `ok`, line/byte cursors reported |
| 6 | `fs` upload + download of a 1.9 KB payload | `ok:true`, downloaded bytes identical, itemized `<f+++++++++`/`<f.st......` |
| 7 | `jms_submit_job` (tmux launcher) → status → logs → wait → cancel | `running`→`done` with pid and `exit_code`, logs by byte offset; cancel reports `killed:true, status_before:"running", already_finished:false` plus the launcher `result_id` |
| 8 | `run` with `timeout: 3` around `sleep 30` | `exit_code 124`, `timed_out`, `execution_state: unknown`, `completion_unknown: true` |
| 9 | `terminal open` → `exec python3 -i` → `write print(6*7)` → `eof` → `close` | prompt captured, `42` returned, state `closed` |
| 10 | `call jms_accelerator_status` on an accelerator host | 8 devices reported `busy`, with occupants, worker commands and container names |
| 11 | `call jms_exec` (legacy env/workdir path) | `ok`, `pwd` = `/root` from the asset's `workdir` |
| 12 | `call jms_inventory_reload`, `session_list`, `request_status`, `result_metadata` (summary/transport/timing/all), `meta(service, policy)` | all consistent: 99 permitted assets, receipts with `result_status` |
| 13 | hard `kill -9` mid-request, then restart | `request_status` reports `request_state: interrupted`, `completion_unknown: true`, nothing replayed |
| 14 | `discover` (categories, search, one operation schema, `topic=assets`, `topic=status`) | schemas served on demand; assets show `usable` and the resolved account |
| 15 | `discover(operation="run")` | returns the complete schema (14 fields) that the advertised `options` entry point points at |
| 16 | `call jms_list_assets` | paged: `matched:99`, `returned:20`, `next_offset:20` instead of dumping the inventory |
| 17 | same `request_id`, arguments spelled with the documented defaults | still a `duplicate` with `execution_replayed:false` (fingerprint normalization) |
| 18 | same `request_id`, different script | refused: "request_id already claimed … (arguments cannot change)" |
| 19 | `session_close` on a `terminal(action="open")` handle | closed through the unified registry (`state:"closed"`) |
| 20 | persistent shell after the isolated-run rework (`cd /tmp`, `export KEEP=42`) | second call still shows `42` and `/tmp` |
| 21 | `jms_submit_job` with a job that finishes in under a second | `launched:true` and its log/exit code available immediately (no waiting for the process to die) |
| 22 | `jms_submit_job` response fields | `launch_state:"acknowledged"`, `launched:true`, `launcher:"tmux"`, plus `result_id` for the launcher transcript |
| 23 | `session_list` after `run(session_id=...)` | that handle reports `state:"active"`, `lost:false` (the earlier build always said `lost:true`) |
| 24 | `terminal open` → `exec sleep 40` → `close`, then `result_metadata` | result is `execution_state:"unknown"`, `completion_unknown:true`, `failure_stage:"closed_by_caller"` instead of staying `running` |
| 25 | `call jms_submit_job` with `request_id` on two targets | `request_state:"complete"` with per-target `launch_state`; the receipt path shares the call budget |
| 26 | measured `tools/list` from the running service | 7 tools, 6822 bytes on the wire (~1.6k tokens by the envelope estimate) |
| 27 | `discover(operation=...)` sizes | `run` 2799 B, `fs` 3673 B, `terminal` 2261 B, `jms_submit_job` 635 B |
| 28 | two concurrent `terminal exec` on one handle | first accepted and `running`, second refused with "terminal is busy"; the first response's `result_id` belongs to the first command |
| 29 | `session_list` while a `sleep 25` command runs | returns in ~0 s; the terminal row says `running`, the named-shell row says `active` |
| 30 | `terminal close` during a running command, then `result_metadata` | `execution_state:"unknown"`, `completion_unknown:true`, `failure_stage:"closed_by_caller"`, `executed:true` |
| 31 | `jms_job_wait` after a cancel | returns in 0.71 s with `status:"cancelled"`, `finished:true` |
| 32 | `jms_job_wait` with a budget shorter than the job | returns at ~3.25 s with `status:"unknown"`, `watch_timeout:true`; nothing is cancelled remotely |
| 33 | `jms_submit_job` on two targets | both `acknowledged`; the 8.4 s wall time is dominated by the second host's first login (paced by design), not by serialisation |
| 34 | `tools/list` measured on the wire | 7 tools, 6795 B for the list, ~7.0 KB with the server instructions |
| 35 | terminal exec after the takeover rework | `takeover-ok` returned, `state: completed` |
| 36 | `read(wait_ms=9000)` on a `sleep 4; echo` command started with `wait_ms=0` | returns after ~3.0 s with the output: the reader never blocks the worker |
| 37 | three stateless HTTP `run` calls | each returns its own output; the shared catalog is built once |
| 38 | cancel → `jms_job_wait` | returns in 0.64 s with `status:"cancelled"`, `finished:true` |
| 39 | `jms_job_wait` with `timeout:3` on a 40 s job | returns at 3.00 s keeping the last known `status:"running"` (no invented `unknown`) |

## Deliberately not exercised here

| Area | Why | How to check |
| --- | --- | --- |
| Docker `container`/`image` execution | No Docker daemon on the probed assets | `run` with `container` on a host that has Docker |
| A terminal command aborted mid-flight by a service restart | Requires killing the process with a command in flight | covered by unit tests (`ResultLease`, close transitions); a live kill would only re-verify the same paths |
| Launcher rejection paths (`no tmux and no setsid`, tmux refusing a session) | Both launchers exist on every probed asset | covered by the mapping test; nothing is claimed as `launched` without an acknowledgement |
| Connection replacement with live named shells | Needs a deliberately broken pooled connection while a shell is open | the recovery path now refuses to replace a connection that still carries shells (`protected` reflects them); unit test covers the tracker, not a real disconnect |
| `session_id` loss across a normal (non-kill) restart | Requires restarting the resident service holding live shells | restart `serve`, then reuse the same `session_id`: expect `not_started` with "session state was lost" |
| Result expiry sweep (7 days) | Would need a week of wall clock | covered by unit tests with injected timestamps |
| Very large transfers (>1 GB) | Time budget | `fs` upload/download paginate by design; rsync streams without buffering |
| macOS/OpenSSH targets | Deployment is Linux-only | `platform` overlay field exists but probes assume GNU userland |

## Cross-host deployment check

The same release binary was copied to an unrelated asset and run there against
the gateway:

| Check | Result |
| --- | --- |
| `doctor` (REST) | full permitted inventory pulled over HTTPS (99 assets), gateway version reported |
| `probe` (SSH) | refused as `not_started` on that host |

The resident service belongs on the host that holds the deployment's login
material; nothing was transmitted before the refusal, so the probe reported
`not_started` rather than a partial success.

## Cost profile

| Scenario | Measured cost |
| --- | --- |
| `initialize` + `tools/list` (7 tools, instructions, annotations) | 7047 B / ~1.8k tokens (estimate), 6795 B of tool list on the wire |
| `discover(operation="run")` | 2799 B |
| a compact single-host `run` response | ~0.4 KB |
| a `read_result` page | the requested `limit` (4 KiB default) |
| a staged `call` summary | < 4 KB, with `result_id` for the full payload |

The token numbers are tokenizer-independent *estimates* (`bytes/4` versus a
punctuation-density proxy, whichever is larger). They are stable enough to catch
regressions and must not be quoted as a model-specific measurement.

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