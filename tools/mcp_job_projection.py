#!/usr/bin/env python3
"""Paired, local-only experiment for reversible successful Job submit compaction."""
import argparse
from collections import Counter, defaultdict
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import re

from mcp_job_measure import CASES, measure


def encode_view(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def compact_submit(raw):
    """Model-side encoding experiment; the server never emits this view."""
    value = json.loads(raw)
    if (not isinstance(value, dict) or value.get("ok") is not True
            or value.get("staged") or value.get("completion_unknown")
            or value.get("duplicate") or value.get("execution_replayed")):
        return raw
    rows, jobs = value.get("submissions"), value.get("jobs")
    if not isinstance(rows, list) or not rows or not isinstance(jobs, list):
        return raw
    for row in rows:
        if (not isinstance(row, dict) or row.get("launch_state") != "acknowledged"
                or row.get("launched") is not True or not isinstance(row.get("target"), str)
                or not row["target"] or row.get("asset_id") != row["target"]):
            return raw
    for row in rows:
        del row["asset_id"], row["launched"]
    return encode_view(value)


def expand_submit(compact):
    value = json.loads(compact)
    for row in value["submissions"]:
        row["asset_id"] = row["target"]
        row["launched"] = True
    return value


def observe(metrics, count, mode, facade, results):
    for step, raw in results:
        cohort = metrics[mode][facade][step]
        original = json.loads(raw)
        compact = compact_submit(raw) if step == "submit" and facade == "public" else raw
        if compact != raw:
            if expand_submit(compact) != original:
                raise RuntimeError("projection is not reversible")
            cohort["changed"] += 1
        cohort.update({"samples": 1, "exact_result_bytes": len(raw.encode("utf-8")),
                       "projected_result_bytes": len(compact.encode("utf-8")),
                       "exact_result_tokens": count(raw), "projected_result_tokens": count(compact)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--server-git-sha", required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1 or not re.fullmatch(r"[0-9a-fA-F]{40}", args.server_git_sha):
        parser.error("require positive repeats and a full server source SHA")
    if version("tiktoken") != "0.12.0":
        parser.error("install tiktoken 0.12.0 and prewarm the encoding cache")
    import tiktoken
    tokenizer = tiktoken.get_encoding("o200k_base")
    metrics = defaultdict(lambda: defaultdict(lambda: defaultdict(Counter)))
    fixture = CASES[args.case].read_bytes()
    measured = measure(args.binary.resolve(), json.loads(fixture), args.repeats,
                       observe_results=lambda *entry: observe(
                           metrics, lambda text: len(tokenizer.encode_ordinary(text)), *entry))
    with args.binary.open("rb") as binary:
        binary_sha256 = hashlib.file_digest(binary, "sha256").hexdigest()
    print(json.dumps({
        "case": args.case, "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
        "server_git_sha": args.server_git_sha,
        "binary_sha256": binary_sha256,
        "encoding": "tiktoken 0.12.0 / o200k_base",
        "scope": "paired decoded result text, synthetic Job backend, projection never sent on wire",
        "model_tokens": None, "repeats_per_transport_facade": args.repeats,
        "measurements": measured, "paired_result_text": metrics,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
