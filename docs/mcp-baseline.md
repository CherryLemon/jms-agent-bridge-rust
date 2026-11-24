# Offline MCP transport baseline (v4)

Build the bridge from the revision being compared and run the same fixture on
the same machine for both revisions. The Python 3.9+ harness uses the standard
library, a private temporary state directory, and the real bridge binary. Its
HTTP server listens only on loopback. It does not need a bastion, proxy,
host keys, credentials or a model API.

```sh
cargo build --locked --release
python3 tools/mcp_baseline.py --binary target/release/jms-bridge \
  --server-git-sha "$(git rev-parse HEAD)" --repeats 30 > baseline.json
```

Run on a quiet machine and keep the build profile, repeat count and fixture
constant. The explicit revision above is valid only if you built that binary
from the corresponding clean checkout. For an existing binary, use the
revision recorded by its build, not the current checkout. The harness cannot
infer or verify this mapping. The report includes that supplied revision,
plus SHA-256 digests of the binary and the exact fixture bytes.

A wrong reply or unexpected error fails the run instead of contaminating
percentiles. A missing tool used by the fixture fails the run; extra tools
are allowed. The report records the complete declared tool-name set and the
actual declaration response sizes.

| Step | Real protocol / offline fixture scope |
| --- | --- |
| Initialize, initialized notification, and tools/list | Real stdio JSON-RPC framing and stateless Streamable HTTP requests. Declaration sizes come from the actual initialization and tool-list replies. |
| Job status and log schema discovery | Real on-demand schema lookups. Neither job is executed and remote status/log probes are not measured. |
| Saved log page | Real byte-offset read of a synthetic local saved result. |
| Lost-reply receipt | Real lookup against a seeded local receipt with no live owner. First recovery and subsequent reads are separate rows. This is not an injected network disconnect. The fixture asserts no replay. |
| Terminal read | Real unknown-handle rejection. No terminal is opened. |

- **Calls and errors:** `messages` counts all JSON-RPC submissions, including
  the notification; `tool_calls` counts only `tools/call`. Startup (one
  initialize, one notification, one tools/list) and repeated workload calls
  are reported separately. The negative terminal
  case contributes one expected MCP error per iteration. A reconciled receipt
  with `completion_unknown` is a valid tool response, not an MCP error.
- **Bytes:** stdio counts UTF-8 frames including the newline; Streamable HTTP
  counts the request and response bodies, **not** HTTP headers, TCP or TLS
  overhead. Declaration sizes exclude transport framing. Treat these as a
  payload/stdio-frame baseline, not an HTTP wire-byte measurement.
- **Latency:** nearest-rank P50/P95, per operation, measured until the complete
  response is collected. The HTTP client opens a fresh connection for each
  request; timings include that setup. Stdio initialization may include process
  startup. Notification latencies are omitted (stdio has no acknowledgement).
  Rows with only one sample, including the first receipt recovery, are a single
  observation, not a stable percentile.
- **Model tokens and SSH probes:** both are `null` (unmeasured). This fixture
  touches no remote host and does not use byte-to-token estimates. A later
  loopback SSH/REST fixture with counters can cover actual remote job/log and
  terminal success paths, followed by a controlled lost-reply experiment.

Report v3 adds `fixture_tasks`: a task is one full validated iteration of
the offline fixture, excluding startup. First and subsequent iterations have
separate task counts, calls, expected errors, payload bytes and wall-clock
P50/P95. A one-repeat run leaves the subsequent group null. This metric does
not stand in for a real submit → wait → logs replay or a remote SSH probe.

Report v4 adds a separate `mock_job_workflow` section. It replays a pinned
three-asset scenario in process, using one submit, two waits (the second
watches only the pending handle), and three log reads, including the failed
job. It checks all terminal states, exit codes, and logs before counting a
workflow as complete. In this fixture, each complete workflow has two done
jobs and one failed job (exit 7), and models 3 launch, 4 status, and 3 log
probes. The probe denominator is completed workflows; the reported
`targets_per_workflow` also allows per-target normalization.

These are **mock counts**, not observed server calls or backend probes. They
are deliberately reported once outside both real transport summaries. The
real stdio/HTTP fixture and its hash are unchanged; actual SSH probes and
model tokens are still unmeasured. Use the report to validate counting and
workflow semantics, not to infer server latency, probe savings or bytes
for multi-target jobs. A deterministic loopback backend and instrumented
actual dispatch remain necessary for those comparisons.

The existing unit-test limit on the advertised declaration stays in place:
`cargo test --lib advertised_tools_stay_within_their_token_budget`.

A matched sanity run (debug builds, Linux x86-64, 30 iterations per transport,
same fixture) completed three startup messages, 150 workload tool calls and
30 expected terminal errors per transport on both builds:

| Source build | Tool-list JSON bytes | Initialize JSON bytes | Stdio workload response frames | HTTP workload response bodies |
| --- | ---: | ---: | ---: | ---: |
| `7d62f6c`, original | 6,468 | 824 | 66,406 B | 66,256 B |
| `6d3560b`, initial combined first-wave candidate (adds `job`) | 5,966 | 829 | 77,566 B | 77,416 B |

The startup byte improvement is separate from repeated workload traffic and
does not imply that workload replies shrank. These figures are checks of the
fixture, not thresholds or model token measurements.

## Matched job workflow over loopback

Use the separate bench to compare the legacy `call` job operations with the
public `job` tool against the **same binary** and workload. It requires
Python and Paramiko (tested with 3.5.1). Install this optional test dependency in
a virtual environment and run with only loopback networking available:

```sh
python3 tools/mcp_job_measure.py --binary target/release/jms-bridge \
  --server-git-sha "$(git rev-parse HEAD)" --repeats 5 > matched-job.json
```

Each repeat starts with a new bridge, state directory and scripted backend for
each variant and transport. Legacy uses the same keyed submit and polls each
job through an independent legacy wait; public uses a single batched wait and
continues using only its pending handles. Both read the same two logs via the
corresponding entry point. The fixture makes one job finish with exit code 7
and one remain pending through the first wait deadline, then finish with exit
code 0. Wrong results or unexpected errors abort the measurement.

The report counts accepted REST catalog requests and individual SSH exec
payloads by role. The SSH emulator speaks the bridge's framing and returns
canned replies; it never executes shell commands. Counts are actual loopback
requests, not the mock denominators elsewhere in this document. Reported
bytes cover actual MCP stdio framing or HTTP bodies only. HTTP headers,
TCP, SSH wire bytes and model tokens are unmeasured. Timing spans submit
through both validated log results and includes the intentional wait; it is
not a production latency estimate. Poll counts can vary with timing; JSON
byte counts can also vary with emitted evidence and IDs. Startup measurement
continues to belong to the separate standard-library baseline. The matched
workflow does not discard responses or inject an SSH disconnect; the existing
offline lost-reply receipt fixture remains separate.

### Matched pilot

Server `fdfb1b5a15ac67fa96d45e1348a4d258cc7f4df6`, Rust 1.89 release,
Python/Paramiko protocol client, cold process state each repeat, three
repeats for each transport and façade. Every workflow returned the expected
one successful job, one failed job, first-wait timeout, and both logs.

| Transport | Façade | MCP calls per workflow | SSH execs per workflow | Request + response bytes across 3 | P50 / P95 ms |
|---|---|---:|---:|---:|---:|
| HTTP | Legacy | 6 | 9 | 11,192 | 6,521 / 6,522 |
| HTTP | Public | 5 | 9 | 12,250 | 6,519 / 6,520 |
| stdio | Legacy | 6 | 9 | 11,227 | 6,525 / 6,525 |
| stdio | Public | 5 | 9 | 12,278 | 6,522 / 6,522 |

The public path saved one call in this scenario, with unchanged SSH probe
counts and more MCP bytes. These small-sample, deadline-dominated measurements
do not establish a latency or model-token improvement.

### Opt-in acknowledged submit reply discard

```sh
python3 tools/mcp_job_lost_reply.py --binary target/release/jms-bridge \
  --server-git-sha "$(git rev-parse HEAD)" --repeats 2 > lost-job-reply.json
```

This separate probe uses the same canned assets and real public job calls over
both transports. It reads one exact, successful submit response from the
transport, quarantines it in a test oracle, then fails that call at the
application boundary. The caller never sees the submit payload and never
issues a replacement submit. It restarts the bridge, queries its durable
receipt using only the original request ID, and reads the saved launch command
results using the recovered result IDs. This recovery phase must issue no
SSH requests; any catalog requests (including HTTP bridge startup) are
counted separately. A bridge with a different local state directory then follows only the
recovered asset/job handles, validating both terminal exit codes and both
logs. The oracle finally verifies exact ID equality and the backend counters
must show exactly one launch per asset.

The report includes the discarded reply's bytes because they were transferred,
even though the application did not receive them. Elapsed time includes the
simulated discard, two bridge restarts and follow-up. The result demonstrates
recovery after a **fully received and acknowledged** response, not mid-frame
loss, in-flight process failure, transport cancellation or SSH outage.
The workload report above and the seeded interrupted-receipt test are
unchanged and cover different failure boundaries.

### Additional matched shapes

The default `--case mixed-timeout` keeps the existing fixture. Two other
pinned cases use the same legacy/public comparison, independently over stdio
and Streamable HTTP:

| Case | Targets | Expected terminal outcomes | Wait behavior |
| --- | ---: | --- | --- |
| `one-target` | 1 | One success | No continuation expected |
| `above-concurrency` | 6 | Four successes and two failures (exit 7) | No continuation expected; emulator holds each status handler for 80 ms |

Six targets exceed the four in-flight public job-wait status probes in
the pinned server; the synthetic delay makes overlap visible without
requiring remote work. The observed peak counts overlapping handlers in
the loopback emulator, not server internals or a limit inferred from one
timing sample. The one-target run is a control for façade overhead when
no batching is possible. Each completed workflow requires one launch and
one log read per target and status coverage for every target; unexpected
errors, duplicate launches and missing logs fail the run.

Run the same case, server binary, repeat count and machine for both
façades. The CLI does that within one invocation and reports the case,
fixture hash, Python and Paramiko versions, and repeat count per
transport and façade. For example:

```sh
for shape in one-target above-concurrency; do
  python3 tools/mcp_job_measure.py --binary target/release/jms-bridge \
    --server-git-sha "$(git rev-parse HEAD)" --case "$shape" --repeats 5 \
    > "matched-job-$shape.json"
done
```

Separate MCP call counts from REST/catalog and SSH request counts. A
shorter workflow or fewer MCP rounds need not use fewer SSH probes or
fewer MCP bytes. The synthetic handler delay is part of the measured
elapsed time; it is not a production latency estimate.
