#!/usr/bin/env python3
"""Check that a previous bridge can read a newer local Job receipt without replay."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import tempfile

from mcp_job_loopback import LoopbackJobs
from mcp_job_lost_reply import REQUEST_ID, DroppedSubmitReply, drop_acknowledged_submit, job_records
from mcp_job_measure import CASES, Client, connected
from mcp_job_portable_receipt import guarded

FIXTURE = CASES["one-target"]


def require_receipt(receipt, targets):
    if (receipt.get("request_id") != REQUEST_ID
            or receipt.get("operation") != "jms_submit_job"
            or receipt.get("request_state") != "complete"
            or receipt.get("completion_unknown") is not False
            or receipt.get("execution_replayed") is not False):
        raise RuntimeError("rollback did not preserve a completed, unreplayed receipt")
    return job_records(receipt.get("submission_receipts", []), targets)


def ssh_delta(backend, before, **expected):
    observed = {k: v for k, v in (backend.counts - before).items() if k.startswith("ssh_")}
    if backend.errors or observed != expected:
        raise RuntimeError(f"unexpected loopback probes: {observed}, expected {expected}")


def sample(candidate, previous, fixture, mode, root):
    source, = fixture["targets"]
    target = source["id"]
    oracle = {}
    with LoopbackJobs(root, fixture).serving() as backend:
        with connected(candidate, root, backend.config, mode) as exchange:
            client = Client(drop_acknowledged_submit(exchange, {target}, oracle), legacy=False)
            try:
                client.job("submit", targets=[target], command=fixture["command"],
                           request_id=REQUEST_ID)
            except DroppedSubmitReply:
                pass
            else:
                raise RuntimeError("original submit reply reached the application")
        ssh_delta(backend, Counter(), ssh_launch=1)
        after_submit = backend.counts.copy()

        # Exclusive process lifetimes, same temporary state directory. The previous
        # binary is restricted to the existing legacy/read-only tool calls below.
        with connected(previous, root, backend.config, mode) as exchange:
            receipt_args = {"operation": "request_status", "arguments": {"request_id": REQUEST_ID}}
            reader = Client(guarded(exchange, {"tool": "call", "arguments": receipt_args}), legacy=True)
            records = require_receipt(reader.tool("receipt", "call", **receipt_args), {target})
            job_id, result_id = records[target]
            page_args = {"result_id": result_id, "offset": 0, "limit": 64}
            reader.exchange = guarded(exchange, {"tool": "read_result", "arguments": page_args})
            page = reader.tool("saved_result", "read_result", **page_args)
            if page.get("result_id") != result_id or page.get("text") != "LAUNCHER=setsid\n":
                raise RuntimeError("rollback returned the wrong saved launch result")
            ssh_delta(backend, after_submit)

            status_args = {"operation": "jms_job_status", "arguments": {"targets": [target], "job_id": job_id}}
            reader.exchange = guarded(exchange, {"tool": "call", "arguments": status_args})
            status = reader.tool("status", "call", **status_args)
            rows = status.get("status", [])
            if (status.get("ok") is not True or len(rows) != 1
                    or rows[0].get("host") != source["name"] or rows[0].get("job_id") != job_id
                    or rows[0].get("status") != "done" or rows[0].get("exit_code") != "0"):
                raise RuntimeError("rollback did not observe the intended completed job")
            logs_args = {"operation": "jms_job_logs", "arguments": {
                "host": target, "job_id": job_id, "offset": 0, "max_bytes": 1024}}
            reader.exchange = guarded(exchange, {"tool": "call", "arguments": logs_args})
            logs = reader.tool("logs", "call", **logs_args)
            if (logs.get("ok") is not True or logs.get("job_id") != job_id
                    or logs.get("log") != source["log"]):
                raise RuntimeError("rollback read the wrong job log")

        # Check IDs only after the old client completes the workflow using the journal.
        if records != oracle["records"]:
            raise RuntimeError("rollback changed the original acknowledged IDs")
        ssh_delta(backend, after_submit, ssh_status=1, ssh_logs=1)
        return Counter({"completed_workflows": 1, "discarded_submit_replies": 1,
                        "recovered_receipts": 1, "saved_results": 1, "ssh_launch": 1,
                        "ssh_status": 1, "ssh_logs": 1, "duplicate_launches": 0,
                        "candidate_calls": 1, "previous_calls": sum(reader.counts.values())})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("candidate", "previous"):
        parser.add_argument(f"--{role}", required=True, type=Path)
        parser.add_argument(f"--{role}-git-sha", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    report = {"scope": "synthetic loopback, same local state, separate bridge lifetimes"}
    for role in ("candidate", "previous"):
        revision = getattr(args, f"{role}_git_sha").lower()
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            parser.error("require full source SHAs")
        with getattr(args, role).open("rb") as binary:
            report[role] = {"source_sha": revision, "binary_sha256": hashlib.file_digest(binary, "sha256").hexdigest()}
    if (report["candidate"]["source_sha"] == report["previous"]["source_sha"]
            or report["candidate"]["binary_sha256"] == report["previous"]["binary_sha256"]):
        parser.error("require two distinct source revisions and binaries")
    if not 1 <= args.repeats <= 20:
        parser.error("require 1 to 20 repeats")
    source = FIXTURE.read_bytes()
    report["fixture_sha256"] = hashlib.sha256(source).hexdigest()
    report["transports"] = {}
    for mode in ("stdio", "http"):
        results = Counter()
        for _ in range(args.repeats):
            with tempfile.TemporaryDirectory(prefix="jms-rollback-") as directory:
                results.update(sample(args.candidate.resolve(), args.previous.resolve(),
                                      json.loads(source), mode, Path(directory)))
        report["transports"][mode] = dict(results)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
