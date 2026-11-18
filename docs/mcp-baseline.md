# Offline MCP transport baseline (v1)

Build the bridge from the revision being compared and run the same fixture on
the same machine for both revisions. The Python 3.9+ harness uses the standard
library, a private temporary state directory, and the real bridge binary. Its
HTTP server listens only on loopback. It does not need a bastion, proxy,
host keys, credentials or a model API.

```sh
cargo build --locked --release
python3 tools/mcp_baseline.py --binary target/release/jms-bridge --repeats 30 > baseline.json
```

Run on a quiet machine and keep the build profile, repeat count and fixture
constant. Archive the JSON alongside the binary's Git revision. A wrong reply
or unexpected error fails the run instead of contaminating percentiles.

| Step | Real protocol / offline fixture scope |
| --- | --- |
| Initialize, initialized notification, and tools/list | Real stdio JSON-RPC framing and stateless Streamable HTTP requests. Declaration sizes come from the actual initialization and tool-list replies. |
| Job status and log schema discovery | Real on-demand schema lookups. Neither job is executed and remote status/log probes are not measured. |
| Saved log page | Real byte-offset read of a synthetic local saved result. |
| Lost-reply receipt | Real lookup against a seeded local receipt with no live owner. First recovery and subsequent reads are separate rows. This is not an injected network disconnect. The fixture asserts no replay. |
| Terminal read | Real unknown-handle rejection. No terminal is opened. |

- **Calls and errors:** `messages` counts all JSON-RPC submissions, including
  the notification; `tool_calls` counts only `tools/call`. The negative terminal
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

The existing unit-test limit on the advertised declaration stays in place:
`cargo test --lib advertised_tools_stay_within_their_token_budget`.

A sanity run on `7d62f6c` (debug build, Linux x86-64, 30 iterations per
transport) completed 182 MCP messages, 150 tool calls and 30 expected terminal
errors per transport. The largest tool-list reply was 6,470 JSON bytes on both
transports; initialize was 824 JSON bytes. Total stdio request/response frames
were 21,947/261,359 bytes; total HTTP bodies were 21,765/261,178 bytes. These
figures are a check of the fixture, not thresholds for future runs.
