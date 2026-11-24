# Offline MCP transport baseline (v3)

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
