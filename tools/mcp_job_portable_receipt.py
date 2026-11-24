#!/usr/bin/env python3
"""Validate one portable job receipt across independent local bridge instances."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import tempfile

from mcp_job_loopback import LoopbackJobs
from mcp_job_measure import CASES, Client, connected

FIXTURE = CASES["one-target"]
REQUEST = "offline-portable-job-receipt"
OTHER_UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def status_action(handle):
    return {"tool": "call", "arguments": {"operation": "jms_job_status",
            "arguments": {"targets": [handle["target"]], "job_id": handle["job_id"]}}}


def guarded(exchange, *allowed):
    def read_only(body, reply):
        msg = json.loads(body)
        if msg.get("method") == "tools/call":
            params = msg["params"]
            actual = {"tool": params["name"], "arguments": params["arguments"]}
            if actual not in allowed:
                raise RuntimeError("unexpected recovery tool or arguments")
        elif msg.get("method") not in {"initialize", "notifications/initialized"}:
            raise RuntimeError("unexpected recovery RPC method")
        return exchange(body, reply)
    return read_only


def require_denied(client, action):
    result, _ = client.rpc("tools/call", {"name": action["tool"],
                            "arguments": action["arguments"]})
    if result.get("isError") is not True:
        raise RuntimeError("expected explicit recovery rejection")


def sample(binary, fixture, mode, root):
    source = fixture["targets"][0]
    origin, follower, restricted = (root / label for label in ("origin", "follower", "restricted"))
    for directory in (origin, follower, restricted):
        directory.mkdir()

    with LoopbackJobs(origin, fixture).serving() as backend:
        with connected(binary, origin, backend.config, mode) as exchange:
            receipt = Client(exchange, legacy=False).job(
                "submit", targets=[source["id"]], command=fixture["command"], request_id=REQUEST)
            handles = receipt.get("jobs", [])
            if (receipt.get("ok") is not True or receipt.get("jobs_scope") != "remote_job"
                    or receipt.get("request_id_scope") != "bridge_local" or len(handles) != 1):
                raise RuntimeError("no acknowledged portable receipt")
            handle = handles[0]
            if (set(handle) != {"target", "job_id"} or handle["target"] != source["id"]
                    or not re.fullmatch(r"[0-9a-f]{8}", handle["job_id"])):
                raise RuntimeError("unexpected portable handle shape")
            next_action = receipt.get("next_action")
            if next_action != status_action(handle):
                raise RuntimeError("invalid or non-portable next_action")

        # Origin process and connection have exited. Follower has a different HOME,
        # state and absent credentials path. Both share the authorized fixture
        # endpoint config, but the follower cannot consult the origin's journal.
        before = backend.counts.copy()
        if before["ssh_launch"] != 1:
            raise RuntimeError("fixture must acknowledge exactly one launch")
        local_action = {"tool": "meta", "arguments": {"ref": f"request:{REQUEST}"}}
        log_action = {"tool": "job", "arguments": {
            "action": "logs", **handle, "offset": 0, "max_bytes": 1024}}
        with connected(binary, follower, backend.config, mode) as exchange:
            reader = Client(guarded(exchange, next_action, log_action, local_action), legacy=False)
            require_denied(reader, local_action)
            for _ in range(2):
                status = reader.tool("status", next_action["tool"], **next_action["arguments"])
                rows = status.get("status", [])
                if (status.get("ok") is not True or len(rows) != 1
                        or rows[0].get("job_id") != handle["job_id"]
                        or rows[0].get("status") != "done" or rows[0].get("exit_code") != "0"):
                    raise RuntimeError(f"unexpected portable status: {status!r}")
                log = reader.tool("logs", log_action["tool"], **log_action["arguments"])
                if (log.get("ok") is not True or log.get("job_id") != handle["job_id"]
                        or log.get("log") != source["log"]):
                    raise RuntimeError("portable log lookup changed the receipt or output")
        if (backend.errors or backend.counts["ssh_launch"] != 1
                or backend.counts["ssh_status"] - before["ssh_status"] != 2
                or backend.counts["ssh_logs"] - before["ssh_logs"] != 2):
            raise RuntimeError(f"unexpected fixture events: {backend.counts!r}, {backend.errors!r}")

    # Same display name, different authorized canonical UUID; it must not be
    # selected when the original canonical UUID is absent from this catalog.
    other = {**fixture, "targets": [{**source, "id": OTHER_UUID}]}
    with LoopbackJobs(restricted, other).serving() as backend:
        with connected(binary, restricted, backend.config, mode) as exchange:
            client = Client(guarded(exchange, next_action), legacy=False)
            require_denied(client, next_action)
        if (backend.errors or backend.counts["catalog_list"] < 1
                or any(key.startswith("ssh_") for key in backend.counts)):
            raise RuntimeError("denied fixture reached SSH or never checked current catalog")
    return Counter({"launch": 1, "remote_status": 2, "remote_log": 2,
                    "foreign_local_id_denied": 1, "out_of_scope_asset_denied": 1})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
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
            with tempfile.TemporaryDirectory(prefix="jms-portable-") as directory:
                events.update(sample(args.binary.resolve(), fixture, mode, Path(directory)))
        results[mode] = {"completed_workflows": args.repeats, **events, "duplicate_launches": 0}
    with args.binary.open("rb") as binary:
        binary_sha256 = hashlib.file_digest(binary, "sha256").hexdigest()
    print(json.dumps({
        "scope": "separate local bridge processes, synthetic catalogs and canned SSH",
        "server_git_sha": args.server_git_sha, "binary_sha256": binary_sha256,
        "fixture_sha256": hashlib.sha256(source).hexdigest(), "transports": results,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
