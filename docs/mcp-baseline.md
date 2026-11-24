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

#### Measured loopback pilot (one and six targets)

Both façades ran on the same Linux x86-64 workstation against the Rust
1.89 release binary built from server commit
`ab1311e15fde03ba4ebbcc639795fd3bb5389041` with
`cargo build --offline --locked --release`. Binary SHA-256:
`eb9383ce88352f9fc2387a442e02ccb1d91a2d37245880dd5b97b9b14a9c22f2`.
The client used Python 3.13.5 and Paramiko 3.5.1. The process, bridge state
and canned backend were fresh for every workflow, with three completed
workflows per row. The exact fixture SHA-256s are:

- `one-target`: `0f63ff03bc9f98417b56d6d26c68e53c55c995e1df30b43d20d9636c056170ac`
- `above-concurrency`: `ee6624c666881c42abb691448332bb78f3709c2bfde8af80640cd3d29b67bda9`

| Case | Transport | Façade | MCP submit / wait / logs per workflow | SSH launch / status / log per workflow | Peak status handlers | MCP payload B across 3 | Workflow P50 / P95 ms |
| --- | --- | --- | --- | --- | --- | ---: | ---: |
| 1 target | HTTP | Legacy | 1 / 1 / 1 | 1 / 1 / 1 | 1 | 5,666 | 6.873 / 7.819 |
| 1 target | HTTP | Public | 1 / 1 / 1 | 1 / 1 / 1 | 1 | 6,780 | 7.301 / 7.780 |
| 1 target | stdio | Legacy | 1 / 1 / 1 | 1 / 1 / 1 | 1 | 5,684 | 12.464 / 29.821 |
| 1 target | stdio | Public | 1 / 1 / 1 | 1 / 1 / 1 | 1 | 6,798 | 12.024 / 12.177 |
| 6 targets | HTTP | Legacy | 1 / 6 / 6 | 6 / 6 / 6 | 1 | 25,140 | 25,526.539 / 25,545.945 |
| 6 targets | HTTP | Public | 1 / 1 / 6 | 6 / 6 / 6 | 4 | 23,391 | 25,199.871 / 25,201.583 |
| 6 targets | stdio | Legacy | 1 / 6 / 6 | 6 / 6 / 6 | 1 | 25,218 | 25,529.346 / 25,530.392 |
| 6 targets | stdio | Public | 1 / 1 / 6 | 6 / 6 / 6 | 4 | 23,438 | 25,205.621 / 25,206.402 |

Each row had zero duplicate launches, unexpected MCP errors or wait
timeouts. There was one accepted catalog list plus one catalog lookup per
target per workflow in both façades. The one-target rows completed three
successful jobs each. The six-target rows each completed 12 successful jobs
and six expected exit-7 jobs, with validated terminal IDs, exit codes and
exact per-target canned logs. An exit-7 job is a validated workload
outcome, not an MCP error.

The public façade used the same number of calls for one target and saved
five MCP waits for six targets. SSH request counts were unchanged. MCP
payload rose by about 20% for one target and fell by about 7% for six.
Payload includes the request and complete response body/frame, with
initialization excluded. Elapsed time starts at submit and includes the
fixture's 80 ms status-handler delay in the six-target case and any bridge
submit scheduling. The reported P95 is the maximum of three observations.
These figures do not estimate live SSH or production latency, HTTP wire
bytes or model token usage.

### Growing log / offset replay

`--case growing-log` uses one canned job, a small initial log, then a
deterministic append before the second read. It validates the exact content,
reported size, job ID and advancing byte offset on every page (including a
final empty read at EOF). This exercises an increasing watermark and page
continuation without process creation on the emulator or actual wall-clock log
writes. It is an offset example, not a generation-cursor or file-rotation test.

Measured on both façades and transports, three fresh runs per arm, server
`4b0e956aa9e4d7bb8a1173462744e76cc2587c7e`; release SHA-256
`6d53b26e8ecf926d4c3d4458b4a11e5252f19c3a679d2ecfe99f3a0e88ddce7c`;
fixture SHA-256
`96a3ef5bd4a1dc8a87a791238b206711b834a290f9ecb3d1e652a7dfac7319bc`.
Python 3.13.5 / Paramiko 3.5.1. All arms completed all workflows,
with no wait timeout or duplicate launch. Per workflow: 6 MCP calls
(1 submit, 1 wait, 4 log reads), 6 corresponding SSH execs, and 2 synthetic
REST catalog requests; these counts did not change between façades.

| Transport | Three-task MCP bytes legacy → public | Legacy P50/P95 ms | Public P50/P95 ms |
| --- | ---: | ---: | ---: |
| stdio | 15,672 → 16,570 | 14.728 / 16.772 | 14.880 / 15.704 |
| HTTP | 15,636 → 16,535 | 10.803 / 11.358 | 10.889 / 11.716 |

Bytes and elapsed time exclude initialization, as in the other matched
job workflow reports. These are protocol observations, not model tokens
or production latency. A larger response for submit does not imply that
the logging read itself sends a larger response.

### Startup budget snapshot

The same `4b0e956aa9e4d7bb8a1173462744e76cc2587c7e` release was measured
with the standard-library harness and fixture SHA-256
`41a47f923725a2423043886879be8e5197e18ef89486b032a74553ec3412be56`.
Each transport had one startup (three messages) followed by 30 validated
iterations (150 calls, 30 expected missing-terminal errors). Both returned
eight tools in a 6,441-byte JSON `tools/list` reply and an 829-byte
initialize JSON reply, without transport framing. The existing declaration
budget test is a separate full-envelope budget of 7,168 bytes and 1,800
estimated tokens; those tokens are not model usage.

| Transport | Startup request / response bytes | 30-iteration request / response bytes |
| --- | ---: | ---: |
| stdio frames | 260 / 7,272 | 20,266 / 83,836 |
| HTTP bodies | 257 / 7,270 | 20,116 / 83,686 |

Repeated schema discovery is part of the workload, never of startup. These
rows describe this exact release and fixture; they are not a same-run
comparison to the historical debug-build numbers at the top of this page.

### Warm terminal channel

Run the separate benchmark for public Terminal versus legacy call on both
transports. It opens one real loopback SSH channel, acknowledges READY and
exactly two sequential canned terminal packets, and closes the channel.
The fixture never starts a shell or executes a command. The first packet
returns a small stdout payload; the second is silent. Both must produce
terminal completion, exit zero, and distinct result IDs on the same session.
The deterministic order is not a controlled test of the effect of output
on latency. An extra packet or extra channel fails acceptance.

```sh
python3 tools/mcp_terminal_measure.py --binary target/release/jms-bridge \
  --server-git-sha "$(git rev-parse HEAD)" --repeats 5 > warm-terminal.json
```

Five fresh processes per façade and transport, Python 3.13.5 / Paramiko
3.5.1, server release `4b0e956aa9e4d7bb8a1173462744e76cc2587c7e`
(SHA-256 `6d53b26e8ecf926d4c3d4458b4a11e5252f19c3a679d2ecfe99f3a0e88ddce7c`; fixture SHA-256
`18d83199523ceab0736eb7f766d46956b26e1c799cb335f86478513c3bf9293f`). The measured binary is the same release
used for the preceding startup/log snapshot. This documentation and tooling
change does not rebuild that binary.

Every workflow completed with four MCP calls (open, output, silent, close),
one backend SSH channel, two acknowledged command packets on that channel,
two catalog requests, and no duplicate command. A terminal command packet is
not a fresh SSH exec-channel request. No startup RPCs, network headers or
transport teardown time are counted here; stdio includes LF and HTTP counts
only bodies. Per-step nearest-rank P95 is the maximum of five samples.
Some local SSH connections logged a reset during teardown after acceptance.
No outcome below is an estimate of production latency or model usage.

| Transport | Façade | MCP bytes, five workflows | Cold open P50/P95 ms | Warm output P50/P95 ms | Warm silent P50/P95 ms | Close P50/P95 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| http | legacy | 10,810 | 3.963 / 4.308 | 1.236 / 1.325 | 0.963 / 1.226 | 0.605 / 0.642 |
| http | public | 10,610 | 3.622 / 3.667 | 1.175 / 1.467 | 0.985 / 1.111 | 0.728 / 0.811 |
| stdio | legacy | 10,850 | 9.137 / 10.375 | 1.137 / 1.292 | 0.755 / 0.978 | 0.513 / 0.589 |
| stdio | public | 10,650 | 9.271 / 10.065 | 0.986 / 1.182 | 0.836 / 0.994 | 0.405 / 0.458 |

### Job result text token count

The Job benchmark can optionally count the exact MCP result text block of
each successful workload call using `tiktoken==0.12.0` and `o200k_base`.
Install the optional dependency and populate its encoding cache before an
offline run. Counting happens after measuring each workflow, without
re-serializing the result text. This excludes requests, declarations,
JSON-RPC framing, model message wrappers and provider or cache usage.
The report leaves `model_tokens` unset (JSON null).

```sh
for case in one-target above-concurrency growing-log; do
  python3 tools/mcp_job_measure.py --binary target/release/jms-bridge \
    --server-git-sha 4b0e956aa9e4d7bb8a1173462744e76cc2587c7e --case "$case" --repeats 3 \
    --result-tokenizer o200k_base > "$case-tokens.json"
done
```

The measurement reused the preceding pinned release and binary SHA-256,
with identical runtime sources and Cargo files. Python 3.13.5, Paramiko
3.5.1; vocabulary SHA-256
`446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d`.
Each cell totals three completed workflows per façade, with no duplicate
launches. Response bytes are HTTP bodies or stdio frames including LF.

| Case | Transport | MCP calls, legacy → public | Response bytes, legacy → public | Result text tokens, legacy → public |
| --- | --- | ---: | ---: | ---: |
| One target | HTTP | 9 → 9 | 3,552 → 4,868 | 789 → 1,177 (+49.2%) |
| One target | stdio | 9 → 9 | 3,559 → 4,874 | 783 → 1,165 (+48.8%) |
| Above concurrency limit | HTTP | 39 → 24 | 15,768 → 16,904 | 3,722 → 4,721 (+26.8%) |
| Above concurrency limit | stdio | 39 → 24 | 15,805 → 16,928 | 3,708 → 4,681 (+26.2%) |
| Growing log | HTTP | 18 → 18 | 11,522 → 12,838 | 2,935 → 3,368 (+14.8%) |
| Growing log | stdio | 18 → 18 | 11,540 → 12,857 | 2,963 → 3,365 (+13.6%) |

The above-concurrency run reduces MCP calls by 38.5% while the returned
text costs more tokens under the selected encoding. Submit accounts for
most of the token increase in all six comparisons (e.g. 1,751 → 2,729
tokens in the HTTP above-concurrency run). These are aggregate results,
not guarantees about individual runs or the model's billed input.

### Offline: reversible submit projection

This is an experiment for #15, not a server response mode. Replay each
captured, successfully decoded result text through a local projection and
compare both forms with the same tokenizer. Only direct Job submit can
change: for an entirely acknowledged inline batch, omit each redundant
`asset_id` when equal to `target`, and omit `launched: true` when
`launch_state` is `acknowledged`. Re-expand to the original object and
reject any mismatch. Preserve IDs, job handles, request state, scopes,
continuations and other diagnostic fields. The staged, failed, ambiguous,
unknown and explicitly duplicate/replayed examples are unchanged. The
legacy façade, wait and logs are unchanged.

```sh
# Use the pinned release and the pre-populated tiktoken 0.12.0 cache.
for case in one-target growing-log above-concurrency; do
  python3 tools/mcp_job_projection.py --binary target/release/jms-bridge \
    --server-git-sha 4b0e956aa9e4d7bb8a1173462744e76cc2587c7e \
    --case "$case" --repeats 3 > "$case-projection.json"
done
```

Same release binary and vocabulary hashes as the preceding section.
Three workflows per façade/transport/case, 36 completed, no duplicate
launches. Each public submit sample changes; all measured legacy submit,
wait and log samples are identical. Table entries total three workflows,
use `o200k_base`, and exclude outer JSON-RPC/MCP framing. Byte counts
refer to decoded UTF-8 result text, not HTTP or stdio wire bytes.

| Workload | Transport | Public submit text bytes | Public submit text tokens | Public workflow result tokens |
| --- | --- | ---: | ---: | ---: |
| One target | HTTP | 2,515 → 2,317 | 814 → 736 | 1,171 → 1,093 |
| One target | stdio | 2,515 → 2,317 | 818 → 740 | 1,177 → 1,099 |
| Growing log | HTTP | 2,515 → 2,317 | 806 → 728 | 3,331 → 3,253 |
| Growing log | stdio | 2,515 → 2,317 | 815 → 737 | 3,355 → 3,277 |
| Six targets | HTTP | 7,247 → 6,059 | 2,678 → 2,210 | 4,640 → 4,172 |
| Six targets | stdio | 7,248 → 6,060 | 2,692 → 2,224 | 4,666 → 4,198 |

For six targets, the projection cuts submit tokens by about 17%, and
public workflow result tokens by 10%. Projected workflow totals still
exceed matched legacy (HTTP 3,723; stdio 3,707).

**Decision: defer changes to the server protocol.** The pairwise test
verifies JSON parsing and semantic round-trip locally. The actual
workflows consume the unmodified server replies; it does not establish
projected client task completion, extra reads, latency or provider
usage. None of the projection is sent over MCP. The benchmark does not
change defaults or persisted receipts. Keep #15 open for terminal and
explicit text formats, actual compact/full consumption, and integrated
staged and lost-reply evaluation. No conditional output is prototyped.

### Offline: repeated canonical asset UUIDs

This experiment for #14 counts occurrences of known fixture UUIDs in the
structured result fields `target`, `targets`, `asset_id` and
`expected_asset_id`. It substitutes short illustrative strings (`fx1`,
`fx2`, ...) in a local copy and checks that inverse substitution restores
the entire parsed object. Free-text fields and other IDs are untouched.
An alias in an existing identity field or a non-bijective mapping fails
the check. The client uses the original unmodified results to finish the
workflow. No tools receive aliases and no lookup is added.

```sh
# Use the pinned release and pre-populated tiktoken 0.12.0 cache.
for case in one-target growing-log above-concurrency; do
  python3 tools/mcp_job_asset_tokens.py --binary target/release/jms-bridge \
    --server-git-sha 4b0e956aa9e4d7bb8a1173462744e76cc2587c7e \
    --case "$case" --repeats 3 > "$case-asset-tokens.json"
done
```

Same release binary and vocabulary hashes as above. Each row totals three
completed workflows; 36 completed with no duplicate launch. Text bytes are
decoded UTF-8, not wire bytes. Both columns count the same captured result
texts with `o200k_base`, before and after substitution. Requests, tool
declarations, wrapper text, and any amortized handle discovery costs are
excluded. This is independent of the submit projection above; the two
savings must not be added.

| Case | Transport / façade | UUID occurrences | Result text bytes | Result text tokens |
| --- | --- | ---: | ---: | ---: |
| One target | HTTP / legacy | 3 | 2,391 → 2,292 | 760 → 715 |
| One target | HTTP / public | 15 | 3,570 → 3,075 | 1,160 → 935 |
| One target | stdio / legacy | 3 | 2,393 → 2,294 | 782 → 737 |
| One target | stdio / public | 15 | 3,570 → 3,075 | 1,168 → 943 |
| Growing log | HTTP / legacy | 3 | 9,109 → 9,010 | 2,974 → 2,929 |
| Growing log | HTTP / public | 15 | 10,285 → 9,790 | 3,335 → 3,110 |
| Growing log | stdio / legacy | 3 | 9,108 → 9,009 | 2,936 → 2,891 |
| Growing log | stdio / public | 15 | 10,288 → 9,793 | 3,319 → 3,094 |
| Six targets | HTTP / legacy | 18 | 10,527 → 9,933 | 3,707 → 3,437 |
| Six targets | HTTP / public | 72 | 12,850 → 10,474 | 4,628 → 3,548 |
| Six targets | stdio / legacy | 18 | 10,528 → 9,934 | 3,716 → 3,446 |
| Six targets | stdio / public | 72 | 12,852 → 10,476 | 4,658 → 3,578 |

In the public six-target workload the difference is 1,080 result text
tokens across three workflows (about 23%). The fixture UUIDs are
zero-heavy and the aliases deliberately short, so this is a workload
observation, not a production estimate. No model usage was measured.

**Decision: defer exposing handles.** This local reversible transform
checks text semantics only; it does not check live selection, deployment
scope, retention across restart, inventory changes, or access revocation.
Any future pilot must independently measure resolver behavior, selection
accuracy and added discovery/lookup calls across authorized scopes before
protocol adoption. #14 remains open.

### Portable receipt across local bridge instances

This is the single-job portability check for #9. Instance A makes one
synthetic submission and receives the real MCP acknowledgement. Then A
exits; B starts with a separate HOME, state directory and absent
credentials path. A and B use the same authorized synthetic endpoint,
but B receives only the inline remote handle and invokes the exact
read-only `next_action` through the MCP dispatcher. It then retrieves the
matching log from the portable handle, repeating both reads twice.
Neither the original command nor a write is sent by B. Trying the
bridge-local request ID on B returns an error.

Instance C has another synthetic catalog with the same display name and a
different canonical UUID. Invoking the portable status action there is
rejected after catalog access and before any SSH action. The local
fixture opens loopback listeners only. The SSH emulator returns canned
data; it does not run a shell or interpret user commands.

```sh
python3 tools/mcp_job_portable_receipt.py --binary target/release/jms-bridge \
  --server-git-sha 4b0e956aa9e4d7bb8a1173462744e76cc2587c7e --repeats 3
```

Same release binary as above; fixture
`0f63ff03bc9f98417b56d6d26c68e53c55c995e1df30b43d20d9636c056170ac`.

| Transport | Complete workflows | Synthetic launches | Status reads | Log reads | Foreign local IDs rejected | Out-of-scope assets rejected | Duplicate launches |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP | 3 | 3 | 6 | 6 | 3 | 3 | 0 |
| stdio | 3 | 3 | 6 | 6 | 3 | 3 | 0 |

This differs from the lost-reply experiment: B does not reopen the
original journal and recovery starts from an acknowledged inline receipt.
The instances are separate processes on one machine, not a distributed
environment. This run covers a single authorized job and two rejection
cases. Mixed outcomes, staged results, and the full failure-state
reconciliation matrix still need their own evidence. No production
access, server change or deployment.
