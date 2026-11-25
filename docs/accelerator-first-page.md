# Accelerator status first response

`call(operation="jms_accelerator_status", arguments={...})` defaults to a compact
scheduling snapshot. Each resolved asset contributes one row in request order
(aliases resolving to the same asset retain the existing deduplication). A valid
exact selector missing from inventory yields an unresolved row; no SSH probe is
made for that selector. Other requested targets are unaffected.

- Read `host`, `state`, and, when available, `free`/`total`. `unknown` counts
  unverified devices. For a partially usable node only, `free_devices` lists
  verified IDs; `free_devices_more` indicates omitted IDs, when applicable.
- A busy machine with confirmed processes but uniformly low utilization may
  report `activity=occupied_low_util`. It is not free. A shortened `reason` is
  provided for unknown/incomplete evidence. An inventory-stale response does
  not offer a formerly free or partial asset as available.
- This is a snapshot, not a reservation. Recheck selected devices immediately
  before allocating them.
- Small compact responses use `details_action` to open the original detailed
  snapshot. If a response stages, `next_action` retains the prior saved-result
  form and `diagnostics_action` can open the detailed snapshot directly.
  Neither continuation re-probes the machine. Use `detail="full"` for the
  previous detailed envelope when it fits, and the same stored result when it
  does not.

## Related paths

`job status`, `job list`, their legacy aliases, and large legacy
`jms_list_assets` pages use generic output staging. The generic envelope may
retain small scalar fields but only has a text preview for long row arrays.
Use smaller inventory pages where possible. Typed submit/wait staging already
preserves handles and resume instructions; offset-based log paging already
preserves a typed cursor. This change leaves those contracts untouched. This
is a static audit of paths, not evidence of live failure on those operations.

## Offline acceptance

`tools/mcp_accelerator_first_page.py` runs the same synthetic 1/4/8 asset input
over stdio and Streamable HTTP. It verifies that the snapshot answers the
allocation question in one call, all requested verdicts are present and in
order, and reading detail pages adds no SSH probes. Report allocation
decision and full-detail workflows separately. Token figures use local
`o200k_base`, not provider-billed usage.

Matched synthetic results: one run per target count and transport. The 8-node
case exceeds the old generic output budget.

| Transport | Nodes | Decision calls old/new | Decision result tokens old/new | Full detail calls old/new | Full detail result tokens old/new | SSH snapshot + enrichment (both) |
|---|---:|---:|---:|---:|---:|---:|
| stdio | 1 | 1 / 1 | 412 / 120 | 2 / 2 | 1080 / 788 | 1 + 0 |
| stdio | 4 | 1 / 1 | 2314 / 235 | 4 / 4 | 6380 / 4316 | 4 + 2 |
| stdio | 8 | 5 / 1 | 5651 / 434 | 11 / 7 | 13736 / 8525 | 8 + 4 |
| http | 1 | 1 / 1 | 408 / 110 | 2 / 2 | 1073 / 776 | 1 + 0 |
| http | 4 | 1 / 1 | 2316 / 231 | 4 / 4 | 6398 / 4302 | 4 + 2 |
| http | 8 | 5 / 1 | 5650 / 424 | 11 / 7 | 13743 / 8504 | 8 + 4 |

Stale and incomplete states also have Rust unit coverage. The missing-target
check ran on both transports: only the two permitted assets were probed.
