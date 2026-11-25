#!/usr/bin/env python3
"""Compare Job submit views as consumed by the same completed loopback workflow."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile

from mcp_job_loopback import LoopbackJobs
from mcp_job_measure import CASES, Client, connected, workflow


class MeasuredClient(Client):
    def __init__(self, exchange, variant, count_tokens):
        super().__init__(exchange, legacy=variant == "legacy", count_result_tokens=count_tokens)
        self.variant = variant
        self.call_tokens = Counter()

    def tool(self, step, tool, **arguments):
        if step == "submit" and self.variant == "brief":
            arguments["view"] = "brief"
        text = json.dumps(arguments, separators=(",", ":"), ensure_ascii=False)
        self.call_tokens[step] += self.count_result_tokens(tool + "\n" + text)
        response = super().tool(step, tool, **arguments)
        if step == "submit" and self.variant == "brief":
            jobs, result_ids = response.get("jobs", []), response.get("result_ids", [])
            if (response.get("view") != "brief" or "submissions" in response
                    or not jobs or len(jobs) != len(result_ids)):
                raise RuntimeError("server did not emit the requested inline brief receipt")
        return response


def sample(binary, fixture, mode, variant, root, count):
    with LoopbackJobs(root, fixture).serving() as backend:
        with connected(binary, root, backend.config, mode) as exchange:
            client = MeasuredClient(exchange, variant, count)
            states, pending = workflow(client, fixture)
            expected = Counter("failed" if row["exit_code"] else "done" for row in fixture["targets"])
            if states != expected or pending:
                raise RuntimeError("workflow changed its completed job states")
        exact = Counter({row["id"]: 1 for row in fixture["targets"]})
        if (backend.errors or backend.per_asset["ssh_launch"] != exact
                or backend.per_asset["ssh_logs"] != exact
                or backend.per_asset["ssh_status"].keys() != exact.keys()):
            raise RuntimeError("workflow launch, status or logs did not cover the original targets")
        return {
            "completed_workflows": 1,
            "mcp_calls": client.counts.total(),
            "submit_input_tokens": client.result_tokens()["submit"],
            "tool_result_input_tokens": client.result_tokens().total(),
            "tool_call_output_tokens_proxy": client.call_tokens.total(),
            "ssh_launch": backend.counts["ssh_launch"],
            "ssh_status": backend.counts["ssh_status"],
            "ssh_logs": backend.counts["ssh_logs"],
            "duplicate_ssh_launches": backend.counts["ssh_launch"] - len(exact),
        }


def check_journal(binary, mode, root):
    fixture = json.loads(CASES["one-target"].read_bytes())
    target = fixture["targets"][0]["id"]
    with LoopbackJobs(root, fixture).serving() as backend:
        with connected(binary, root, backend.config, mode) as exchange:
            plain = Client(exchange, legacy=False)
            args = {"action": "submit", "targets": [target], "command": fixture["command"],
                    "request_id": "brief-view-is-not-mutation"}
            brief = plain.tool("submit", "job", **args, view="brief")
            full = plain.tool("submit", "job", **args, view="full")
            receipt = plain.tool("request_status", "call", operation="request_status",
                                 arguments={"request_id": args["request_id"]})
            handle, = brief["jobs"]
            result_id, = brief["result_ids"]
            row, = receipt["submission_receipts"]
            if (brief["view"] != "brief" or full.get("view") == "brief"
                    or full.get("duplicate") is not True or full.get("execution_replayed") is not False
                    or brief["jobs"] != full["jobs"] or row["asset_id"] != handle["target"]
                    or row["job_id"] != handle["job_id"] or row["result_id"] != result_id):
                raise RuntimeError("view changed the durable request identity or recovery evidence")
            result = plain.tool("saved_result", "read_result", result_id=result_id, offset=0, limit=64)
            if result.get("result_id") != result_id or result.get("text") != "LAUNCHER=setsid\n":
                raise RuntimeError("brief lost the original launcher result")
        ssh = {k: v for k, v in backend.counts.items() if k.startswith("ssh_")}
        if backend.errors or ssh != {"ssh_launch": 1}:
            raise RuntimeError("view switch caused a duplicate launch or remote recovery")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--case", choices=("one-target", "above-concurrency"), required=True)
    parser.add_argument("--repeats", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20:
        parser.error("require 1 to 20 repeats per variant/transmission")
    import tiktoken
    encoding = tiktoken.get_encoding("o200k_base")
    count = lambda value: len(encoding.encode_ordinary(value))
    source = CASES[args.case].read_bytes()
    binary = args.binary.resolve()
    report = {
        "case": args.case,
        "fixture_sha256": hashlib.sha256(source).hexdigest(),
        "encoding": "o200k_base",
        "model_usage": None,
        "transports": {},
    }
    with binary.open("rb") as f:
        report["binary_sha256"] = hashlib.file_digest(f, "sha256").hexdigest()
    for mode in ("stdio", "http"):
        variants = ("legacy", "full", "brief")
        cohorts = {v: Counter() for v in variants}
        for iteration in range(args.repeats):
            for variant in (variants if iteration % 2 == 0 else tuple(reversed(variants))):
                with tempfile.TemporaryDirectory(prefix="jms-job-brief-") as folder:
                    cohorts[variant].update(sample(binary, json.loads(source),
                                                   mode, variant, Path(folder), count))
        with tempfile.TemporaryDirectory(prefix="jms-job-brief-journal-") as folder:
            check_journal(binary, mode, Path(folder))
        report["transports"][mode] = dict(journal_verified=True, workflows=cohorts)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
