#!/usr/bin/env python3
"""Verify a real staged Job logs response, locally and across a bridge restart."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import tempfile

from mcp_job_loopback import LoopbackJobs
from mcp_job_measure import CASES, Client, connected
from mcp_job_portable_receipt import guarded, require_denied

FIXTURE = CASES["one-target"]
LOG = '段\\路径 "β" 🌕\n' * 450
PAGE_LIMIT = 4096


def read_action(result_id, offset):
    return {"tool": "read_result", "arguments": {
        "result_id": result_id, "stream": "result", "offset": offset, "limit": PAGE_LIMIT}}


def check_page(page, result_id, offset, total):
    next_offset = page["next_offset"]
    if (page["result_id"] != result_id or page.get("stream", "result") != "result"
            or page["offset"] != offset or page.get("total_bytes", total) != total
            or not offset < next_offset <= total
            or len(page["text"].encode("utf-8")) != next_offset - offset
            or page["eof"] is not (next_offset == total)):
        raise RuntimeError("staged byte cursor or identity changed")
    return next_offset


def guarded_page(exchange, client, result_id, offset, total, *, emitted=None):
    expected = read_action(result_id, offset)
    action = expected if emitted is None else emitted
    if action != expected:
        raise RuntimeError("staged action changed stream, result identity, or first byte cursor")
    # Restrict this call to the exact local result ID and current byte cursor.
    client.exchange = guarded(exchange, action)
    try:
        page = client.tool("read_result", action["tool"], **action["arguments"])
    finally:
        client.exchange = exchange
    return page["text"], check_page(page, result_id, offset, total)


def sample(binary, fixture, mode, root, *, require_next_action=False):
    origin, foreign = root / "origin", root / "foreign"
    origin.mkdir()
    foreign.mkdir()
    source = {**fixture["targets"][0], "log": LOG}
    with LoopbackJobs(origin, {**fixture, "targets": [source]}).serving() as backend:
        with connected(binary, origin, backend.config, mode) as exchange:
            client = Client(exchange, legacy=False)
            launched = client.job("submit", targets=[source["id"]], command=fixture["command"],
                                  request_id="offline-staged-job-log")
            handles = launched["jobs"]
            if launched["ok"] is not True or len(handles) != 1 or handles[0]["target"] != source["id"]:
                raise RuntimeError("expected one acknowledged canned launch")
            handle = handles[0]
            staged = client.job("logs", **handle, offset=0, max_bytes=16384)
            total = staged["bytes"]
            rid = staged["result_id"]
            if (staged["staged"] is not True or staged["ok"] is not True
                    or staged["operation"] != "jms_job_logs" or staged["job_id"] != handle["job_id"]
                    or not 8192 < total <= 32768 or "log" in staged
                    or staged["next_offset"] != len(LOG.encode())):
                raise RuntimeError("expected defined staged log summary")
            emitted = staged.get("next_action")
            if require_next_action and (emitted is None or staged.get("result_id_scope") != "bridge_local"):
                raise RuntimeError("staged reply omitted the local result scope or read-only action")
            piece, offset = guarded_page(exchange, client, rid, 0, total, emitted=emitted)
        chunks = [piece]
        with connected(binary, origin, backend.config, mode) as exchange:
            client = Client(exchange, legacy=False)
            while offset < total:
                piece, offset = guarded_page(exchange, client, rid, offset, total)
                chunks.append(piece)
        blob = "".join(chunks)
        payload = json.loads(blob)
        if (len(chunks) < 3 or len(blob.encode()) != total or payload["ok"] is not True
                or payload["job_id"] != handle["job_id"] or payload["offset"] != 0
                or payload["next_offset"] != staged["next_offset"] or payload["log"] != LOG):
            raise RuntimeError("staged payload was truncated or did not round-trip")
        with connected(binary, foreign, backend.config, mode) as exchange:
            action = read_action(rid, 0)
            require_denied(Client(guarded(exchange, action), legacy=False), action)
        if backend.errors or {k: v for k, v in backend.counts.items() if k.startswith("ssh_")} != {
            "ssh_launch": 1, "ssh_logs": 1
        }:
            raise RuntimeError("local result reads must not access the synthetic SSH backend")
    return Counter({"launch": 1, "remote_logs": 1, "staged_results": 1,
                    "staged_bytes": total, "local_pages": len(chunks), "foreign_id_denied": 1})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--server-git-sha", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--require-next-action", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20 or not re.fullmatch(r"[0-9a-fA-F]{40}", args.server_git_sha):
        parser.error("require 1 to 20 repeats and a full server source SHA")
    source = FIXTURE.read_bytes()
    fixture = json.loads(source)
    results = {}
    for mode in ("http", "stdio"):
        events = Counter()
        for _ in range(args.repeats):
            with tempfile.TemporaryDirectory(prefix="jms-staged-") as directory:
                events.update(sample(args.binary.resolve(), fixture, mode, Path(directory),
                                     require_next_action=args.require_next_action))
        results[mode] = {"workflows": args.repeats, **events}
    with args.binary.open("rb") as binary:
        sha = hashlib.file_digest(binary, "sha256").hexdigest()
    print(json.dumps({"scope": "local canned loopback only", "server_git_sha": args.server_git_sha,
                      "binary_sha256": sha, "fixture_sha256": hashlib.sha256(source).hexdigest(),
                      "log_sha256": hashlib.sha256(LOG.encode()).hexdigest(),
                      "required_next_action": args.require_next_action,
                      "transports": results}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
