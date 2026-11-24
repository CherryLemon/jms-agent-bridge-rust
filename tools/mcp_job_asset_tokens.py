#!/usr/bin/env python3
"""Measure repeated synthetic asset UUID text; never resolve or send a handle."""
import argparse
from collections import Counter, defaultdict
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import re

from mcp_job_measure import CASES, measure
from mcp_job_projection import encode_view

CANONICAL = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
SINGULAR = {"asset_id", "target", "expected_asset_id"}


def map_identity_fields(value, mapping):
    if isinstance(value, list):
        return [map_identity_fields(item, mapping) for item in value]
    if not isinstance(value, dict):
        return value
    out = {}
    for key, item in value.items():
        if key in SINGULAR and isinstance(item, str):
            out[key] = mapping.get(item, item)
        elif key == "targets" and isinstance(item, list):
            out[key] = [mapping.get(t, t) if isinstance(t, str)
                        else map_identity_fields(t, mapping) for t in item]
        else:
            out[key] = map_identity_fields(item, mapping)
    return out


def fixture_aliases(fixture):
    ids = [row["id"] for row in fixture["targets"]]
    if (not ids or len(set(ids)) != len(ids)
            or any(not CANONICAL.fullmatch(aid) for aid in ids)):
        raise ValueError("require unique canonical fixture UUIDs")
    return {aid: f"fx{i}" for i, aid in enumerate(sorted(ids), 1)}


def paired(raw, aliases):
    obj = json.loads(raw)
    counts = Counter()

    def replace(aid, default):
        if aid in aliases:
            counts[aid] += 1
        return aliases.get(aid, default)

    # Count only occurrences the structural rewriter actually sees.
    class ObservedMapping(dict):
        def get(self, key, default=None):
            return replace(key, default)

    candidate = map_identity_fields(obj, ObservedMapping())
    inverse = {alias: aid for aid, alias in aliases.items()}
    if len(inverse) != len(aliases) or map_identity_fields(candidate, inverse) != obj:
        raise ValueError("fixture alias collision in identity fields")
    return (encode_view(candidate) if counts else raw), sum(counts.values())


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
    data = CASES[args.case].read_bytes()
    fixture = json.loads(data)
    aliases = fixture_aliases(fixture)
    metrics = defaultdict(lambda: defaultdict(lambda: defaultdict(Counter)))

    def observe(mode, facade, results):
        for step, raw in results:
            projected, instances = paired(raw, aliases)
            metrics[mode][facade][step].update({
                "samples": 1,
                "uuid_references": instances,
                "exact_result_bytes": len(raw.encode()),
                "candidate_result_bytes": len(projected.encode()),
                "exact_result_tokens": len(tokenizer.encode_ordinary(raw)),
                "candidate_result_tokens": len(tokenizer.encode_ordinary(projected)),
            })

    measured = measure(args.binary.resolve(), fixture, args.repeats, observe_results=observe)
    with args.binary.open("rb") as binary:
        binary_sha256 = hashlib.file_digest(binary, "sha256").hexdigest()
    print(json.dumps({
        "case": args.case, "fixture_sha256": hashlib.sha256(data).hexdigest(),
        "server_git_sha": args.server_git_sha, "binary_sha256": binary_sha256,
        "encoding": "tiktoken 0.12.0 / o200k_base",
        "scope": "paired decoded synthetic result text; no handles transmitted or resolved",
        "repeats_per_transport_facade": args.repeats, "model_tokens": None,
        "measurements": measured, "paired_result_text": metrics,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
