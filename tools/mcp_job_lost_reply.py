#!/usr/bin/env python3
"""Opt-in loopback probe: discard a completed public job-submit response."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import tempfile
import time

from mcp_job_loopback import LoopbackJobs
from mcp_job_measure import Client, FIXTURE, connected, follow_jobs, summarize


REQUEST_ID = "offline-lost-job-submit"


def job_records(rows, expected_targets):
    records = {}
    for row in rows:
        target = row.get("asset_id")
        job_id, result_id = row.get("job_id", ""), row.get("result_id", "")
        if (target not in expected_targets or target in records
                or row.get("launch_state") != "acknowledged"
                or not re.fullmatch(r"[0-9a-f]{8}", job_id)
                or not re.fullmatch(r"[0-9a-f]{32}", result_id)):
            raise RuntimeError("submission did not record a unique acknowledged job and result")
        records[target] = (job_id, result_id)
    if records.keys() != expected_targets:
        raise RuntimeError("submission did not cover all synthetic targets")
    return records


def drop_acknowledged_submit(exchange, expected_targets, oracle):
    """Intercept one real received response; never give its IDs to the caller."""
    def wrapped(body, reply):
        tx, response = exchange(body, reply)
        request = json.loads(body)
        params = request.get("params", {})
        args = params.get("arguments", {})
        if (request.get("method") != "tools/call" or params.get("name") != "job"
                or args.get("action") != "submit"):
            return tx, response
        if args.get("request_id") != REQUEST_ID or oracle:
            raise RuntimeError("expected exactly one keyed submit")
        envelope = json.loads(response)
        result = envelope.get("result", {})
        if envelope.get("id") != request.get("id") or result.get("isError"):
            raise RuntimeError("cannot discard an unacknowledged submit")
        payload = json.loads(result["content"][0]["text"])
        if not payload.get("ok") or payload.get("request_id") != REQUEST_ID:
            raise RuntimeError("submit was not acknowledged")
        oracle.update(records=job_records(payload["submissions"], expected_targets),
                      request_bytes=tx, response_bytes=len(response))
        raise DroppedSubmitReply

    return wrapped


class DroppedSubmitReply(Exception):
    """A confirmed response was removed before the application client saw it."""


def sample(binary, fixture, mode, root):
    targets = {row["id"] for row in fixture["targets"]}
    oracle = {}
    with LoopbackJobs(root, fixture).serving() as server:
        with connected(binary, root, server.config, mode) as exchange:
            client = Client(drop_acknowledged_submit(exchange, targets, oracle), legacy=False)
            start = time.perf_counter_ns()
            try:
                client.job("submit", targets=[row["id"] for row in fixture["targets"]],
                           command=fixture["command"], request_id=REQUEST_ID)
            except DroppedSubmitReply:
                pass
            else:
                raise RuntimeError("original submit reply reached the caller")

        # Reopen only the original local request/result store to recover IDs via meta.
        after_submit = server.counts.copy()
        with connected(binary, root, server.config, mode) as exchange:
            recovery = Client(exchange, legacy=False)
            receipt = recovery.tool("request_status", "meta", ref=f"request:{REQUEST_ID}",
                                    section="all")
            if (receipt.get("request_id") != REQUEST_ID or receipt.get("operation") != "jms_submit_job"
                    or receipt.get("request_state") != "complete"
                    or receipt.get("completion_unknown") is not False
                    or receipt.get("execution_replayed") is not False):
                raise RuntimeError(f"unexpected recovery receipt: {receipt!r}")
            recovered = job_records(receipt["submission_receipts"], targets)
            for _, result_id in recovered.values():
                result = recovery.tool("saved_result", "read_result", result_id=result_id,
                                       offset=0, limit=64)
                if result.get("text") != "LAUNCHER=setsid\n":
                    raise RuntimeError("recorded launch result was not readable")

        recovery_requests = server.counts - after_submit
        if any(kind.startswith("ssh_") for kind in recovery_requests):
            raise RuntimeError("receipt or saved result used SSH during local recovery")

        # A fresh store cannot access the journal and has no original reply: it
        # follows only the target/job handles furnished by the recovery caller.
        handles = [{"target": target, "job_id": job_id}
                   for target, (job_id, _) in recovered.items()]
        with connected(binary, root, server.config, mode, state="independent") as exchange:
            follower = Client(exchange, legacy=False)
            states, timed_out = follow_jobs(
                follower, {**fixture, "first_timeout": 8, "followup_timeout": 8},
                handles, require_timeout=False,
            )
        elapsed = (time.perf_counter_ns() - start) / 1e6

        # Independently compare to the dropped response only AFTER all recovery
        # operations have consumed the recovered IDs.
        if recovered != oracle["records"]:
            raise RuntimeError("durable receipt did not preserve the dropped job and result IDs")
        if (server.errors or after_submit["ssh_launch"] != len(targets)
                or server.counts["ssh_launch"] != after_submit["ssh_launch"]
                or server.counts["ssh_logs"] != len(targets)):
            raise RuntimeError(f"invalid launch/probe evidence: {server.counts!r}, {server.errors!r}")

        clients = (recovery, follower)
        return {
            "elapsed_ms": elapsed, "timed_out": timed_out,
            "backend_requests": server.counts.copy(), "terminal_jobs": states,
            "recovery_backend_requests": recovery_requests,
            "calls": sum((client.counts for client in clients), Counter({"submit": 1})),
            **{field: sum((Counter({step: sizes[field] for step, sizes in client.bytes.items()})
                           for client in clients), Counter({"submit": oracle[field]}))
               for field in ("request_bytes", "response_bytes")},
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--server-git-sha", required=True)
    parser.add_argument("--repeats", type=int, default=1)
    args = parser.parse_args()
    if args.repeats < 1 or not re.fullmatch(r"[0-9a-fA-F]{40}", args.server_git_sha):
        parser.error("require positive repeats and a full server source SHA")
    source = FIXTURE.read_bytes()
    fixture = json.loads(source)
    cohorts = {}
    for mode in ("stdio", "http"):
        samples = []
        for _ in range(args.repeats):
            with tempfile.TemporaryDirectory(prefix="jms-job-lost-response-") as directory:
                samples.append(sample(args.binary.resolve(), fixture, mode, Path(directory)))
        cohorts[mode] = summarize(samples)
        cohorts[mode]["discarded_acknowledged_submit_replies"] = len(samples)
        cohorts[mode]["duplicate_ssh_launches"] = 0
        cohorts[mode]["recovery_backend_requests"] = dict(sum(
            (row["recovery_backend_requests"] for row in samples), Counter()
        ))
    print(json.dumps({
        "scope": "completed MCP response discarded at client boundary; canned loopback backend",
        "server_git_sha": args.server_git_sha.lower(),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "fixture": FIXTURE.name,
        "fixture_sha256": hashlib.sha256(source).hexdigest(),
        "targets_per_workflow": len(fixture["targets"]),
        "model_tokens": None,
        "byte_scope": {"stdio": "UTF-8 JSON + LF", "http": "HTTP bodies only"},
        "transports": cohorts,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
