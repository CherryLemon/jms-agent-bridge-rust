#!/usr/bin/env python3
"""Check mixed failed/pending job handoff with canned loopback only."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import tempfile

from mcp_job_loopback import LoopbackJobs
from mcp_job_measure import Client, connected
from mcp_job_portable_receipt import guarded, status_action

FIXTURE = Path(__file__).with_name("mcp-job-loopback-fixture.json")


def check_mixed(receipt, failed, running, code):
    rows = {row["target"]: row for row in receipt["status"]}
    if (receipt["finished"] is not False or receipt["pending_scope"] != "remote_job"
            or receipt["pending"] != [running] or receipt["next_action"] != status_action(running)
            or len(receipt["status"]) != 2 or set(rows) != {failed["target"], running["target"]}):
        raise RuntimeError("mixed wait did not preserve exactly the unfinished handle")
    failure, live = rows[failed["target"]], rows[running["target"]]
    if (failure["ok"] is not True or failure["job_id"] != failed["job_id"]
            or failure["status"] != "failed" or str(failure["exit_code"]) != str(code)
            or live["ok"] is not True or live["job_id"] != running["job_id"]
            or live["status"] != "running"):
        raise RuntimeError("mixed wait changed per-target evidence")


def sample(binary, fixture, mode, root):
    origin, follower = root / "origin", root / "follower"
    origin.mkdir()
    follower.mkdir()
    failed, running = fixture["targets"]
    # Hold the running job until the origin exits, then advance only the canned clock.
    case = {**fixture, "targets": [failed, {**running, "pending_seconds": 3600}]}
    with LoopbackJobs(origin, case).serving() as backend:
        with connected(binary, origin, backend.config, mode) as exchange:
            client = Client(exchange, legacy=False)
            submit = client.job("submit", targets=[failed["id"], running["id"]],
                                command=fixture["command"], request_id="offline-mixed-job")
            handles = submit["jobs"]
            if (submit["ok"] is not True or submit["jobs_scope"] != "remote_job"
                    or len(handles) != 2 or [h["target"] for h in handles] != [failed["id"], running["id"]]
                    or any(set(h) != {"target", "job_id"}
                           or not re.fullmatch(r"[0-9a-f]{8}", h["job_id"]) for h in handles)):
                raise RuntimeError("unexpected launch receipt")
            mixed = client.job("wait", jobs=handles, timeout=2, interval=0.5)
            check_mixed(mixed, *handles, failed["exit_code"])
        failure, remaining = handles
        action = mixed["next_action"]
        log_action = {"tool": "job", "arguments": {"action": "logs", **failure,
                                                  "offset": 0, "max_bytes": 1024}}
        with backend.lock:
            before = backend.counts.copy()
            failed_probes = backend.per_asset["ssh_status"][failed["id"]]
            backend.jobs[(remaining["target"], remaining["job_id"].encode())] = 0
        with connected(binary, follower, backend.config, mode) as exchange:
            reader = Client(guarded(exchange, action, log_action), legacy=False)
            for _ in range(2):
                result = reader.tool("status", action["tool"], **action["arguments"])
                rows = result["status"]
                if (result["ok"] is not True or len(rows) != 1
                        or rows[0]["job_id"] != remaining["job_id"]
                        or rows[0]["status"] != "done" or str(rows[0]["exit_code"]) != "0"):
                    raise RuntimeError("pending action did not resolve to the original job")
            page = reader.tool("logs", log_action["tool"], **log_action["arguments"])
            if (page["ok"] is not True or page["job_id"] != failure["job_id"]
                    or page["log"] != failed["log"]):
                raise RuntimeError("failed job log was not retained")
        if (backend.errors or before["ssh_launch"] != 2 or backend.counts["ssh_launch"] != 2
                or backend.per_asset["ssh_launch"] != Counter({failed["id"]: 1, running["id"]: 1})
                or backend.per_asset["ssh_status"][failed["id"]] != failed_probes
                or backend.counts["ssh_status"] - before["ssh_status"] != 2
                or backend.per_asset["ssh_logs"] != Counter({failed["id"]: 1})):
            raise RuntimeError("read-only handoff probed a wrong target or sent another launch")
    return Counter({"launch": 2, "failed_rows_retained": 1, "pending_actions": 1,
                    "follower_status": 2, "follower_failed_logs": 1})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--server-git-sha", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1 or not re.fullmatch(r"[0-9a-fA-F]{40}", args.server_git_sha):
        parser.error("require positive repeats and a full server source SHA")
    source = FIXTURE.read_bytes()
    fixture = json.loads(source)
    results = {}
    for mode in ("stdio", "http"):
        events = Counter()
        for _ in range(args.repeats):
            with tempfile.TemporaryDirectory(prefix="jms-mixed-") as directory:
                events.update(sample(args.binary.resolve(), fixture, mode, Path(directory)))
        results[mode] = {"completed_workflows": args.repeats, **events, "duplicate_launches": 0}
    with args.binary.open("rb") as binary:
        sha = hashlib.file_digest(binary, "sha256").hexdigest()
    print(json.dumps({"scope": "local canned loopback, separate bridge processes",
                      "fixture_sha256": hashlib.sha256(source).hexdigest(),
                      "server_git_sha": args.server_git_sha, "binary_sha256": sha,
                      "transports": results}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
