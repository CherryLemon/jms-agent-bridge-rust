#!/usr/bin/env python3
"""Measure legacy vs public job workflow against a canned loopback backend."""
import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
import json
import math
import platform
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

from mcp_baseline import PROTOCOL, await_http, encode, exchange_http, stdio
from mcp_job_loopback import LoopbackJobs


FIXTURE = Path(__file__).with_name("mcp-job-loopback-fixture.json")
CASES = {
    "mixed-timeout": FIXTURE,
    "one-target": Path(__file__).with_name("mcp-job-one-target-fixture.json"),
    "above-concurrency": Path(__file__).with_name("mcp-job-above-concurrency-fixture.json"),
    "growing-log": Path(__file__).with_name("mcp-job-growing-log-fixture.json"),
}


@contextmanager
def connected(binary, root, config, mode, *, state="state"):
    command = [str(binary), "serve", "--config", str(config), "--no-lock"]
    if mode == "stdio":
        command.append("--stdio")
    else:
        with socket.socket() as check:
            check.bind(("127.0.0.1", 0))
            port = check.getsockname()[1]
        command += ["--host", "127.0.0.1", "--port", str(port)]
    env = {"HOME": str(root), "PATH": "/usr/bin:/bin", "JMS_LOG": "warn",
           "JMS_BRIDGE_STATE_DIR": str(root / state),
           "JMS_BRIDGE_CREDENTIALS": str(root / "absent.toml")}
    with tempfile.TemporaryFile() as errors, subprocess.Popen(
        command, env=env, bufsize=0, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=errors,
    ) as process:
        try:
            exchange = ((lambda body, reply: stdio(process, body, reply, timeout=30)) if mode == "stdio"
                        else (lambda body, reply: exchange_http(port, body, reply, timeout=30)))
            if mode == "http":
                await_http(port, process)
            yield exchange
        except Exception:
            errors.seek(0)
            print(errors.read().decode(errors="replace"), end="", file=sys.stderr)
            raise
        finally:
            process.kill()
            process.wait(timeout=5)


class Client:
    def __init__(self, exchange, legacy, *, count_result_tokens=None):
        self.count_result_tokens = count_result_tokens
        self.result_texts = []
        self.exchange = exchange
        self.legacy = legacy
        self.counts = Counter()
        self.bytes = {}
        self.id = 0
        self.rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                "clientInfo": {"name": "job-loopback", "version": "1"}})
        self.exchange(encode({"jsonrpc": "2.0", "method": "notifications/initialized"}), False)

    def rpc(self, method, params):
        self.id += 1
        tx, response = self.exchange(encode({"jsonrpc": "2.0", "id": self.id,
                                              "method": method, "params": params}), True)
        value = json.loads(response)
        if value.get("id") != self.id or "error" in value:
            raise RuntimeError(f"invalid RPC response: {value!r}")
        return value["result"], (tx, len(response))

    def job(self, step, *, request_id=None, **args):
        if self.legacy:
            operations = {"submit": "jms_submit_job", "wait": "jms_job_wait",
                          "logs": "jms_job_logs"}
            if step == "logs":
                args["host"] = args.pop("target")
            tool = "call"
            arguments = {"operation": operations[step], "arguments": args}
        else:
            tool = "job"
            arguments = {"action": step, **args}
        if request_id is not None:
            arguments["request_id"] = request_id
        return self.tool(step, tool, **arguments)

    def tool(self, step, tool, **arguments):
        result, sizes = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        if result.get("isError"):
            raise RuntimeError(f"{step} MCP error: {result!r}")
        self.counts[step] += 1
        stats = self.bytes.setdefault(step, Counter())
        stats.update({"request_bytes": sizes[0], "response_bytes": sizes[1]})
        result_text = result["content"][0]["text"]
        if self.count_result_tokens is not None:
            self.result_texts.append((step, result_text))
        return json.loads(result_text)

    def result_tokens(self):
        counts = Counter()
        if self.count_result_tokens is not None:
            for step, result_text in self.result_texts:
                counts[step] += self.count_result_tokens(result_text)
        return counts


def workflow(client, fixture):
    targets = {row["id"]: row for row in fixture["targets"]}
    submitted = client.job("submit", targets=list(targets), command=fixture["command"],
                           request_id="offline-matched-job-workflow")
    handles = [{"target": row.get("target", row.get("asset_id")), "job_id": row["job_id"]}
               for row in submitted["jobs"]]
    if not submitted["ok"] or Counter(row["target"] for row in handles) != Counter(targets.keys()):
        raise RuntimeError(f"unexpected submission: {submitted!r}")
    require_timeout = fixture.get("require_timeout", True)
    states, timed_out = follow_jobs(client, fixture, handles, require_timeout=require_timeout)
    if timed_out != require_timeout:
        raise RuntimeError("fixture unexpectedly needed a continuation")
    return states, timed_out


def follow_jobs(client, fixture, handles, *, require_timeout=True):
    targets = {row["id"]: row for row in fixture["targets"]}
    first = fixture["first_timeout"]
    followup = fixture["followup_timeout"]
    interval = fixture["interval"]
    terminal = {}
    if client.legacy:
        # Legacy wait only accepts one job ID, so one independent wait per handle.
        pending = []
        for handle in handles:
            result = client.job("wait", targets=[handle["target"]], job_id=handle["job_id"],
                                timeout=first, interval=interval)
            if result["finished"]:
                terminal[handle["target"]] = result["status"][0]
            else:
                pending.append(handle)
        timed_out = bool(pending)
        for handle in pending:
            result = client.job("wait", targets=[handle["target"]], job_id=handle["job_id"],
                                timeout=followup, interval=interval)
            if not result["finished"]:
                raise RuntimeError(f"legacy continuation did not finish: {result!r}")
            terminal[handle["target"]] = result["status"][0]
    else:
        result = client.job("wait", jobs=handles, timeout=first, interval=interval)
        pending = result["pending"]
        timed_out = not result["finished"]
        ids = {handle["target"] for handle in pending}
        terminal.update((row["target"], row) for row in result["status"]
                        if row["target"] not in ids)
        if pending:
            result = client.job("wait", jobs=pending, timeout=followup, interval=interval)
            if not result["finished"] or result["pending"]:
                raise RuntimeError(f"public continuation did not finish: {result!r}")
            terminal.update((row["target"], row) for row in result["status"])
    if require_timeout and not timed_out:
        raise RuntimeError("fixture did not exercise continuation after the first wait deadline")
    states = Counter()
    for handle in handles:
        aid = handle["target"]
        source = targets[aid]
        row = terminal[aid]
        expected = "failed" if source["exit_code"] else "done"
        if (not row["ok"] or row["job_id"] != handle["job_id"] or row["status"] != expected
                or int(row["exit_code"]) != source["exit_code"]):
            raise RuntimeError(f"unexpected terminal receipt: {row!r}")
        if "append_log" in source:
            follow_growing_log(client, handle, source)
        else:
            page = client.job("logs", **handle, offset=0, max_bytes=1024)
            if not page["ok"] or page["log"] != source["log"]:
                raise RuntimeError(f"unexpected log page: {page!r}")
        states[expected] += 1
    return states, timed_out


LOG_PAGE_BYTES = 1024


def follow_growing_log(client, handle, source):
    initial = source["log"].encode("ascii")
    appended = source["append_log"].encode("ascii")
    if not (0 < len(initial) <= LOG_PAGE_BYTES < len(appended)):
        raise ValueError("growing fixture must exercise more than one append page")
    total = initial + appended
    expected_pages = [(len(initial), initial)] + [
        (len(total), appended[i:i + LOG_PAGE_BYTES])
        for i in range(0, len(appended), LOG_PAGE_BYTES)
    ] + [(len(total), b"")]
    offset = 0
    for expected_size, body in expected_pages:
        page = client.job("logs", **handle, offset=offset, max_bytes=LOG_PAGE_BYTES)
        if (not page["ok"] or page["job_id"] != handle["job_id"]
                or page["offset"] != offset or page["size"] != expected_size
                or page["next_offset"] != offset + len(body)
                or page["log"].encode("ascii") != body):
            raise RuntimeError(f"unexpected growing log page at {offset}: {page!r}")
        offset = page["next_offset"]


def summarize(samples):
    times = sorted(row["elapsed_ms"] for row in samples)
    result = {"completed_workflows": len(samples),
              "workflows_with_wait_timeout": sum(row["timed_out"] for row in samples)}
    for percentile in (50, 95):
        result[f"p{percentile}_ms"] = round(times[math.ceil(percentile * len(times) / 100) - 1], 3)
    for key in ("calls", "backend_requests", "terminal_jobs", "request_bytes", "response_bytes"):
        result[key] = dict(sum((Counter(row[key]) for row in samples), Counter()))
    return result


def measure(binary, fixture, repeats, *, count_result_tokens=None):
    cohorts = {mode: {variant: [] for variant in ("legacy", "public")}
               for mode in ("stdio", "http")}
    for mode, variants in cohorts.items():
        for iteration in range(repeats):
            # Counterbalance ordering without sharing warm state between cohorts.
            for variant in (("public", "legacy") if iteration % 2 else ("legacy", "public")):
                with tempfile.TemporaryDirectory(prefix="jms-job-matched-") as directory:
                    root = Path(directory)
                    with LoopbackJobs(root, fixture).serving() as server:
                        with connected(binary, root, server.config, mode) as exchange:
                            client = Client(exchange, legacy=variant == "legacy",
                                            count_result_tokens=count_result_tokens)
                            start = time.perf_counter_ns()
                            try:
                                states, timed_out = workflow(client, fixture)
                            except Exception as error:
                                raise RuntimeError(f"fixture counts {server.counts!r}, errors {server.errors!r}") from error
                            elapsed = (time.perf_counter_ns() - start) / 1e6
                        if server.errors:
                            raise RuntimeError(f"loopback SSH fixture errors: {server.errors!r}")
                        expected_jobs = len(fixture["targets"])
                        expected_log_counts = Counter({
                            row["id"]: 2 + math.ceil(len(row["append_log"].encode("ascii")) / LOG_PAGE_BYTES)
                            if "append_log" in row else 1
                            for row in fixture["targets"]
                        })
                        if (server.counts["ssh_launch"] != expected_jobs
                                or server.counts["ssh_logs"] != sum(expected_log_counts.values())
                                or server.counts["ssh_status"] < expected_jobs):
                            raise RuntimeError(f"unexpected backend request counts: {server.counts!r}")
                        expected_counts = Counter({row["id"]: 1 for row in fixture["targets"]})
                        for operation, expected in (("ssh_launch", expected_counts),
                                                    ("ssh_logs", expected_log_counts)):
                            if server.per_asset[operation] != expected:
                                raise RuntimeError(f"unexpected per-asset {operation}: {server.per_asset[operation]!r}")
                        if server.per_asset["ssh_status"].keys() != expected_counts.keys():
                            raise RuntimeError("status probes did not cover exactly the expected targets")
                        variants[variant].append({
                            "elapsed_ms": elapsed, "calls": client.counts, "timed_out": timed_out,
                            "terminal_jobs": states, "backend_requests": server.counts.copy(),
                            "peak_status_handlers": server.peak_status_handlers,
                            "result_tokens": client.result_tokens(),
                            **{field: {step: size[field] for step, size in client.bytes.items()}
                               for field in ("request_bytes", "response_bytes")},
                        })
    return {
        mode: {
            variant: {
                **summarize(samples),
                "duplicate_launches": 0,  # Invalid workflows are rejected, not summarized.
                **({"tool_result_tokens_by_operation": dict(sum(
                    (row["result_tokens"] for row in samples), Counter())),
                    "tool_result_tokens": sum(sum(row["result_tokens"].values()) for row in samples)}
                   if count_result_tokens is not None else {}),
                "observed_peak_backend_status_handlers": max(
                    row["peak_status_handlers"] for row in samples),
            }
            for variant, samples in variants.items()
        }
        for mode, variants in cohorts.items()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--server-git-sha", required=True)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--case", choices=CASES, default="mixed-timeout")
    parser.add_argument("--result-tokenizer", choices=("o200k_base",),
                        help="optional offline count for MCP tool result text (not provider usage)")
    args = parser.parse_args()
    if args.repeats < 1 or not re.fullmatch(r"[0-9a-fA-F]{40}", args.server_git_sha):
        parser.error("require positive repeats and a full server source SHA")
    fixture_bytes = CASES[args.case].read_bytes()
    fixture = json.loads(fixture_bytes)
    from paramiko import __version__ as paramiko_version

    token_counter = None
    token_scope = None
    if args.result_tokenizer:
        from importlib.metadata import version

        import tiktoken
        tokenizer = tiktoken.get_encoding(args.result_tokenizer)
        token_counter = lambda text: len(tokenizer.encode_ordinary(text))
        token_scope = {"library": "tiktoken", "version": version("tiktoken"),
                       "encoding": args.result_tokenizer,
                       "input": "one exact MCP text content block per successful workload call",
                       "excludes": "tool declarations, requests, wrapping messages and provider usage"}
    result = {
        "client": {"python": platform.python_version(), "paramiko": paramiko_version},
        "scope": "real MCP and loopback backend requests; canned job execution",
        "byte_scope": {"stdio": "UTF-8 JSON + LF", "http": "HTTP bodies only"},
        "server_git_sha": args.server_git_sha.lower(),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
        "case": args.case,
        "repeats_per_transport_facade": args.repeats,
        "process_state": "fresh server, state directory and emulator per workflow",
        "targets_per_workflow": len(fixture["targets"]),
        "synthetic_status_delay_ms": fixture.get("status_delay_ms", 0),
        "model_tokens": None,
        **({"tool_result_token_scope": token_scope} if token_scope is not None else {}),
        "transports": measure(args.binary.resolve(), fixture, args.repeats,
                              count_result_tokens=token_counter),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
