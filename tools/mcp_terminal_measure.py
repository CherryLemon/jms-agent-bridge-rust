#!/usr/bin/env python3
"""Compare Terminal facades using one synthetic persistent SSH channel."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import re
import tempfile
import threading
import time

from mcp_job_loopback import LoopbackJobs
from mcp_job_measure import Client, connected, summarize

FIXTURE = Path(__file__).with_name("mcp-terminal-warm-fixture.json")


class LoopbackTerminal(LoopbackJobs):
    """Only acknowledges exact fixture scripts; never interprets shell input."""

    def __init__(self, root, case):
        super().__init__(root, case)
        self.channel_finished = threading.Event()

    @staticmethod
    def line(channel, pending):
        while b"\n" not in pending:
            chunk = channel.recv(1024)
            if not chunk:
                if not pending:
                    return None
                raise ValueError("truncated terminal packet")
            pending.extend(chunk)
            if len(pending) > 4096:
                raise ValueError("oversize terminal packet")
        end = pending.index(b"\n") + 1
        result = bytes(pending[:end])
        del pending[:end]
        return result

    def ssh_command(self, channel, asset):
        try:
            self.count("ssh_terminal_channels")
            if asset not in self.assets:
                raise ValueError("unknown fixture asset")
            channel.settimeout(5)
            pending = bytearray()
            ready = self.line(channel, pending) or b""
            nonces = re.findall(rb"READY([0-9a-f]{32})", ready)
            if len(nonces) != 2 or nonces[0] != nonces[1]:
                raise ValueError("invalid terminal READY")
            self.marker(channel, b"\x1eREADY" + nonces[0] + b"\x1f")
            for command in self.case["commands"]:
                packet = self.line(channel, pending) or b""
                starts = re.findall(rb"START([0-9a-f]{32})", packet)
                ends = re.findall(rb"END([0-9a-f]{32})", packet)
                literal = b"builtin eval -- $'" + command["script"].encode("ascii") + b"';"
                if len(starts) != 2 or starts != ends or starts[0] != starts[1] or literal not in packet:
                    raise ValueError("unexpected fixture terminal packet")
                self.count("ssh_terminal_packets")
                nonce = starts[0]
                self.marker(channel, b"\x1eSTART" + nonce + b"\x1f")
                if command["stdout"]:
                    channel.sendall(command["stdout"].encode())
                if command["stderr"]:
                    channel.sendall_stderr(command["stderr"].encode())
                self.marker(channel, b"\x1eEND" + nonce + b":" + str(command["exit_code"]).encode() + b"\x1f")
            if self.line(channel, pending) is not None:
                raise ValueError("unexpected extra terminal command")
        except Exception as error:
            with self.lock:
                self.errors.append(str(error))
        finally:
            try:
                channel.close()
            finally:
                self.channel_finished.set()


def terminal(client, step, action, **fields):
    if client.legacy:
        return client.tool(step, "call", operation=f"terminal_{action}", arguments=fields)
    roots = {k: fields.pop(k) for k in ("target", "session", "script") if k in fields}
    return client.tool(step, "terminal", action=action, **roots, options=fields)


def measure_sample(client, fixture):
    start = time.perf_counter_ns()
    opened = terminal(client, "open", "open", target=fixture["targets"][0]["id"],
                      request_id="warm-terminal-open")
    if not opened["ok"] or opened["state"] != "idle":
        raise RuntimeError(f"unexpected open: {opened!r}")
    session = opened["session"]
    open_ms = (time.perf_counter_ns() - start) / 1e6
    seen = set()
    commands_ms = {}
    for index, command in enumerate(fixture["commands"]):
        start = time.perf_counter_ns()
        step = "exec_output" if command["stdout"] or command["stderr"] else "exec_silent"
        executed = terminal(client, step, "exec", session=session, script=command["script"],
                            wait_for="completed", request_id=f"warm-terminal-command-{index}")
        if (not executed["ok"] or executed["session"] != session or executed["state"] != "completed"
                or executed["executed"] is not True or executed["exit_code"] != command["exit_code"]
                or any(executed.get(stream, "") != command[stream] for stream in ("stdout", "stderr"))
                or executed.get("more", False) or not executed["result_id"]
                or executed["result_id"] in seen):
            raise RuntimeError(f"unexpected terminal completion: {executed!r}")
        seen.add(executed["result_id"])
        commands_ms[step] = (time.perf_counter_ns() - start) / 1e6
    start = time.perf_counter_ns()
    closed = terminal(client, "close", "close", session=session, request_id="warm-terminal-close")
    if not closed["ok"] or closed["session"] != session or closed["state"] != "closed":
        raise RuntimeError(f"unexpected close: {closed!r}")
    return {"open": open_ms, **commands_ms, "close": (time.perf_counter_ns() - start) / 1e6}


def measure(binary, fixture, repeats):
    report = {}
    for mode in ("stdio", "http"):
        results = {arm: [] for arm in ("legacy", "public")}
        for iteration in range(repeats):
            for arm in (("legacy", "public") if iteration % 2 == 0 else ("public", "legacy")):
                with tempfile.TemporaryDirectory(prefix="jms-warm-terminal-") as directory:
                    root = Path(directory)
                    with LoopbackTerminal(root, fixture).serving() as server:
                        with connected(binary, root, server.config, mode) as exchange:
                            client = Client(exchange, legacy=arm == "legacy")
                            try:
                                elapsed = measure_sample(client, fixture)
                                if not server.channel_finished.wait(2):
                                    raise RuntimeError("fixture channel did not close")
                            except Exception as error:
                                raise RuntimeError(f"fixture errors {server.errors!r}, counts {server.counts!r}") from error
                        expected = Counter({"ssh_terminal_channels": 1, "ssh_terminal_packets": 2,
                                            "catalog_list": 1, "catalog_asset": 1})
                        if server.errors or server.counts != expected:
                            raise RuntimeError(f"unexpected fixture backend: {server.counts!r}, {server.errors!r}")
                        results[arm].append({"elapsed_ms": sum(elapsed.values()), "step_ms": elapsed,
                            "calls": client.counts, "backend_requests": server.counts.copy(),
                            "timed_out": False, "terminal_jobs": {},
                            **{field: {step: size[field] for step, size in client.bytes.items()}
                               for field in ("request_bytes", "response_bytes")}})
        report[mode] = {}
        for arm, rows in results.items():
            data = summarize(rows)
            for unrelated in ("workflows_with_wait_timeout", "terminal_jobs"):
                del data[unrelated]
            per_step = {}
            for step in rows[0]["step_ms"]:
                step_stats = summarize([{**row, "elapsed_ms": row["step_ms"][step]} for row in rows])
                per_step[step] = {p: step_stats[p] for p in ("p50_ms", "p95_ms")}
            report[mode][arm] = {**data, "per_step": per_step, "duplicate_commands": 0}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--server-git-sha", required=True)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if args.repeats < 1 or not re.fullmatch("[0-9a-fA-F]{40}", args.server_git_sha):
        parser.error("require positive repeats and a full server SHA")
    from paramiko import __version__ as paramiko_version

    raw = FIXTURE.read_bytes()
    print(json.dumps({
        "server_git_sha": args.server_git_sha.lower(),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(raw).hexdigest(),
        "client": {"python": platform.python_version(), "paramiko": paramiko_version},
        "repeats_per_transport_facade": args.repeats,
        "scope": "actual MCP and synthetic persistent SSH channel; no shell executed",
        "byte_scope": {"stdio": "UTF-8 JSON + LF", "http": "HTTP bodies only"},
        "model_tokens": None,
        "transports": measure(args.binary.resolve(), json.loads(raw), args.repeats),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
