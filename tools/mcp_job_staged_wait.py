#!/usr/bin/env python3
"""Verify public staged batch wait using preseeded, canned local status only."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import tempfile

from mcp_job_loopback import LoopbackJobs
from mcp_job_measure import Client, connected
from mcp_job_portable_receipt import guarded, require_denied
from mcp_job_staged_result import guarded_page, read_action

FIXTURE = Path(__file__).with_name("mcp-job-loopback-fixture.json")


def seeded_case(fixture):
    # One canned asset avoids measuring first-login pacing; handles still have distinct job IDs.
    target = fixture["targets"][0]["id"]
    row = {**fixture["targets"][0]}
    handles = []
    for i in range(8):
        h = {"target": target, "job_id": f"{i + 1:08x}"}
        if i < 6:
            h["artifact_paths"] = [f"/synthetic/{i}/{j}/" + "数" * 75 for j in range(4)]
        handles.append(h)
    return {**fixture, "targets": [row]}, handles


def check_summary_budget(staged):
    if len(json.dumps(staged, ensure_ascii=False, separators=(",", ":")).encode()) > 8192:
        raise RuntimeError("compact staged wait summary exceeds 8192 UTF-8 bytes")
    if staged.get("ok") is not False or staged.get("finished") is not False:
        raise RuntimeError("staged wait changed the top-level incomplete outcome")


def check_staged(staged, running):
    check_summary_budget(staged)
    total, rid = staged["bytes"], staged["result_id"]
    if (staged["staged"] is not True or staged["operation"] != "jms_job_wait"
            or staged["finished"] is not False or staged["pending"] != running
            or staged["pending_scope"] != "remote_job"
            or staged.get("next_action") is not None
            or staged["result_id_scope"] != "bridge_local"
            or not re.fullmatch(r"[0-9a-f]{32}", rid)
            or not 8192 < total <= 32768 or "status" in staged
            or staged["diagnostics_action"] != read_action(rid, 0)):
        raise RuntimeError(f"unexpected synthetic staged wait: {json.dumps(staged, ensure_ascii=False)[:1200]}")
    return total, rid


def check_payload(payload, handles):
    if (payload.get("ok") is not False or payload["finished"] is not False
            or payload["pending"] != handles[-2:]
            or payload.get("next_action") is not None
            or "diagnostics_action" in payload or len(payload["status"]) != len(handles)):
        raise RuntimeError("staged payload changed mixed wait evidence")
    for i, (row, handle) in enumerate(zip(payload["status"], handles)):
        state = "running" if i >= 6 else "failed"
        if (row["target"], row["job_id"], row["status"], row["ok"]) != (
                handle["target"], handle["job_id"], state, True):
            raise RuntimeError("wrong staged row identity or state")
        if i < 6:
            if str(row["exit_code"]) != "7":
                raise RuntimeError("wrong terminal exit code")
            expected_refs = [{"target": handle["target"], "job_id": handle["job_id"],
                              "path": path, "verified": False,
                              "options": {"expected_asset_id": handle["target"]}}
                             for path in handle["artifact_paths"]]
            if row.get("artifact_refs") != expected_refs:
                raise RuntimeError("staged wait changed synthetic artifact references")


def backend_ops(backend):
    with backend.lock:
        return {k: v for k, v in backend.counts.items() if k.startswith("ssh_")}


def status_snapshot(backend):
    with backend.lock:
        return backend.status_counts_by_job.copy()


def require_observed_pending(follow, handles, before, after):
    expected = {(h["target"], h["job_id"]) for h in handles}
    rows = follow.get("status", [])
    actual = {(r.get("target"), r.get("job_id")) for r in rows}
    if (follow.get("pending") != handles or actual != expected or len(rows) != len(handles)
            or follow.get("ok") is not False or follow.get("finished") is not False
            or follow.get("inventory_timed_out") is True
            or any(r.get("status") != "running" or r.get("ok") is not True
                   or r.get("probed") is False for r in rows)):
        raise RuntimeError("fresh bridge did not observe both exact pending jobs running")
    delta = after - before
    if set(delta) != {(target, job_id.encode()) for target, job_id in expected}:
        raise RuntimeError("foreign status phase did not probe exactly the expected identities")
    return delta.total()


def sample(binary, fixture, mode, root):
    origin, foreign = root / "origin", root / "foreign"
    origin.mkdir()
    foreign.mkdir()
    case, handles = seeded_case(fixture)
    with LoopbackJobs(origin, case).serving() as backend:
        with backend.lock:
            backend.jobs.update({(h["target"], h["job_id"].encode()): 0 for h in handles})
            for h in handles[-2:]:
                backend.jobs[(h["target"], h["job_id"].encode())] = float("inf")
        with connected(binary, origin, backend.config, mode) as exchange:
            client = Client(exchange, legacy=False)
            staged = client.job("wait", jobs=handles, timeout=5, interval=0.5)
            total, rid = check_staged(staged, handles[-2:])
            before_reads = backend_ops(backend)
            if set(before_reads) != {"ssh_status"}:
                raise RuntimeError("fixture must only observe canned statuses")
            piece, offset = guarded_page(exchange, client, rid, 0, total,
                                         emitted=staged["diagnostics_action"])
        chunks = [piece]
        with connected(binary, origin, backend.config, mode) as exchange:
            client = Client(exchange, legacy=False)
            while offset < total:
                piece, offset = guarded_page(exchange, client, rid, offset, total)
                chunks.append(piece)
        blob = "".join(chunks)
        if len(chunks) < 3 or len(blob.encode()) != total:
            raise RuntimeError("staged wait did not round-trip across restart")
        check_payload(json.loads(blob), handles)
        with connected(binary, foreign, backend.config, mode) as exchange:
            action = read_action(rid, 0)
            require_denied(Client(guarded(exchange, action), legacy=False), action)
            if backend_ops(backend) != before_reads:
                raise RuntimeError("local diagnostics triggered a synthetic backend operation")
            before_follow = status_snapshot(backend)
            follow = Client(exchange, legacy=False).job("wait", jobs=staged["pending"], timeout=5, interval=0.5)
            foreign_probes = require_observed_pending(follow, handles[-2:], before_follow,
                                                       status_snapshot(backend))
        if backend.errors or set(backend_ops(backend)) != {"ssh_status"}:
            raise RuntimeError("read-only wait called an unexpected synthetic operation")
    return Counter(staged_waits=1, local_pages=len(chunks), foreign_id_denied=1,
                   staged_bytes=total, portable_pending_pairs=2, failed_rows_retained=6,
                   status_probes=before_reads["ssh_status"], foreign_inline_status_probes=foreign_probes)


def overflow_sample(binary, fixture, mode, root):
    origin, foreign = root / "origin", root / "foreign"
    origin.mkdir()
    foreign.mkdir()
    row = fixture["targets"][0]
    target = row["id"]
    handles = [{"target": target, "job_id": f"{i + 1:08x}",
                "artifact_paths": [f"/synthetic/{i}/{j}/" + "数" * 75 for j in range(4)]}
               for i in range(10)]
    with LoopbackJobs(origin, {**fixture, "targets": [row]}).serving() as backend:
        with backend.lock:
            backend.jobs.update({(target, h["job_id"].encode()): float("inf") for h in handles})
        with connected(binary, origin, backend.config, mode) as exchange:
            client = Client(exchange, legacy=False)
            staged = client.job("wait", jobs=handles, timeout=3, interval=0.5)
            check_summary_budget(staged)
            rid = staged["result_id"]
            typed = {"ref": rid}
            if (staged["pending"] != typed or staged["pending_scope"] != "bridge_local"
                    or staged.get("next_action") is not None
                    or staged["diagnostics_action"] != read_action(rid, 0)):
                raise RuntimeError("oversize pending handles must use the local typed reference")
            read_before = backend_ops(backend)
            offset = 0
            chunks = []
            while offset < staged["bytes"]:
                part, offset = guarded_page(exchange, client, rid, offset, staged["bytes"],
                                            emitted=staged["diagnostics_action"] if offset == 0 else None)
                chunks.append(part)
            if backend_ops(backend) != read_before:
                raise RuntimeError("local page read reached canned backend")
            payload = json.loads("".join(chunks))
            if payload.get("ok") is not False or payload.get("finished") is not False:
                raise RuntimeError("typed payload changed the top-level incomplete outcome")
            portable = payload["pending"]
            if portable != handles:
                raise RuntimeError("local diagnostics did not retain exact pending pairs")
            again = client.job("wait", jobs=typed, timeout=1, interval=0.5)
            if (again.get("pending_scope") != "bridge_local"
                    or again.get("pending") != {"ref": again.get("result_id")}):
                raise RuntimeError("origin did not consume its own continuation")
        before_denied = backend_ops(backend)
        with connected(binary, foreign, backend.config, mode) as exchange:
            action = {"tool": "job", "arguments": {"action": "wait", "jobs": typed,
                                                   "timeout": 1, "interval": 0.5}}
            require_denied(Client(guarded(exchange, action), legacy=False), action)
            if backend_ops(backend) != before_denied:
                raise RuntimeError("foreign continuation reached synthetic backend")
            # Only a bounded portable unit is needed to establish fresh-state reuse.
            # The unchanged original array would simply stage again.
            before_follow = status_snapshot(backend)
            resumed = Client(exchange, legacy=False).job("wait", jobs=portable[:2],
                                                         timeout=5, interval=0.5)
            foreign_probes = require_observed_pending(resumed, portable[:2], before_follow,
                                                       status_snapshot(backend))
        if backend.errors or set(backend_ops(backend)) != {"ssh_status"}:
            raise RuntimeError("unexpected backend operation")
    return Counter(typed_refs_local=1, typed_refs_foreign_denied=1, typed_local_pages=len(chunks),
                   materialized_pending_pairs=len(portable), materialized_pairs_reused=2,
                   foreign_materialized_status_probes=foreign_probes)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--server-git-sha", required=True)
    p.add_argument("--repeats", type=int, default=3)
    a = p.parse_args()
    if not 1 <= a.repeats <= 20 or not re.fullmatch(r"[0-9a-fA-F]{40}", a.server_git_sha):
        p.error("require 1 to 20 repeats and a full server source SHA")
    source = FIXTURE.read_bytes()
    fixture = json.loads(source)
    results = {}
    for mode in ("stdio", "http"):
        events = Counter()
        for _ in range(a.repeats):
            with tempfile.TemporaryDirectory(prefix="jms-staged-wait-") as directory:
                events.update(sample(a.binary.resolve(), fixture, mode, Path(directory)))
            with tempfile.TemporaryDirectory(prefix="jms-staged-handles-") as directory:
                events.update(overflow_sample(a.binary.resolve(), fixture, mode, Path(directory)))
        results[mode] = {**events, "launches": 0, "remote_logs": 0, "ssh_ops_during_local_reads": 0}
    with a.binary.open("rb") as binary:
        sha = hashlib.file_digest(binary, "sha256").hexdigest()
    print(json.dumps({"scope": "local canned staged wait, preseeded status only",
                      "fixture_sha256": hashlib.sha256(source).hexdigest(),
                      "server_git_sha": a.server_git_sha, "binary_sha256": sha,
                      "transports": results}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
