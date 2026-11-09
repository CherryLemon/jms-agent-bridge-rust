# Switching from the Python bridge

The Rust service was written so that a switch does not lose dedupe evidence.

## State is compatible

`~/.local/state/jms-bridge` has the same layout in both implementations:

```
results/<result_id>/{meta.json,stdout.log,stderr.log,result.json}
requests/<sha256(request_id)>/state.json
assets.json
```

The request receipt and its fingerprint are computed the same way
(`sha256` over the canonical JSON of `[operation, arguments]`, sorted keys, no
spaces, UTF-8), so the Rust service reads Python receipts as its own:

* `request_status` on a Python-written receipt returns the same
  `request_id`/`request_state`/response without re-executing anything;
* reusing that `request_id` with different arguments is refused with
  "request_id already claimed … (arguments cannot change)", exactly as before.

This was verified against a live receipt produced by the running Python service
(`pd-functional-r16-reasoning-low-c1-once`, `jms_submit_job`, `complete`), copied
into a scratch state directory and served by the Rust binary.

## Recommended switch

1. Stop the Python service from accepting new work and let running requests
   finish (or accept that they become `interrupted`).
2. Keep the existing state directory. Do **not** clear it: it holds the dedupe
   receipts for everything already executed.
3. Start `jms-bridge serve` with the same `JMS_BRIDGE_STATE_DIR`.
4. Old interactive shells cannot be revived by either implementation; a session
   id that was live before the switch reports `not_started` with
   "session state was lost". Open a new one.
5. Point the MCP client at the new endpoint (`http://127.0.0.1:8766/mcp` by
   default) and keep using the same seven tools.

## Rollback

The receipt format is bidirectional for the fields that matter (id, operation,
fingerprint, state, response), so stopping the Rust service and starting the
Python one on the same state directory keeps dedupe working. New receipts
written by Rust are plain JSON with the same keys; the Python journal ignores
any extra field it does not know.

## Stricter defaults in the Rust bridge

Three behaviours are deliberately fail-closed where the Python bridge was
permissive. They are listed here because they change what a copied config does:

| Topic | Python bridge | Rust bridge |
| --- | --- | --- |
| Gateway host key | verification only when `known_hosts` is configured | always verified against `~/.ssh/known_hosts` (or `bridge.known_hosts`); an unknown or changed key is refused |
| Assets with several permitted accounts | resolved by name | stay unresolved until `bridge.preferred_account` names one; `discover(topic="assets")` explains why |
| SSH authentication | may include interactive steps | must complete with a key or password; anything else fails fast with an authentication error |

## Contract details worth knowing when switching

| Field | Meaning |
| --- | --- |
| `launch_state` | `acknowledged` (the launcher confirmed the job), `rejected` (the launcher answered that nothing started), `unknown` (transmitted, verdict lost). Only `acknowledged` sets `launched: true`. |
| `job_id` | Returned for every outcome, including `rejected`, so a lost reply can always be reconciled. |
| staging | A `call` response above 8 KiB is saved and summarised with `staged: true`, `result_id` and `note`; the summary always keeps `request_id`, `request_state`, `execution_state` and `completion_unknown`. |
| terminal close | Closing a terminal with a command in flight records `unknown`/`completion_unknown: true`; a queued command records `not_started`. |

Persistence is a precondition, not a side effect: if the result id or the prepared
job receipt cannot be written, the operation stops before anything is sent.

## Not supported

* SSH agent authentication is not implemented: provide `bastion.ssh_key` (with
  an unencrypted key file, or a key the running agent already unlocked) or a
  password.
* Only Linux targets are tested; the remote probes assume GNU userland.

## What is not carried over

* Result directories are shared, so `read_result` keeps working for both. Saved
  results expire after the configured TTL either way.
* Filesystem worker registrations, pool connections and shell handles are
  process state and are intentionally not persisted.
* The Python `hosts.yaml` alias inventory is not a source of truth in Rust; only
  its metadata overlay (`asset_id` → `env_setup`/`workdir`/`platform`) is read.