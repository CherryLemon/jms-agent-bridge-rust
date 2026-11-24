#!/usr/bin/env python3
"""Drive real MCP transports against a private local bridge; no live bastion."""
import argparse
from collections import defaultdict
from contextlib import contextmanager
import hashlib
import http.client
import json
import math
from pathlib import Path
import re
import select
import socket
import subprocess
import tempfile
import time


PROTOCOL = "2025-06-18"
TIMEOUT = 5
FIXTURE = Path(__file__).with_name("mcp-baseline-fixture.json")


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


@contextmanager
def bridge(binary, mode, root, fixture):
    root.mkdir()
    state = root / "state"
    result_id, request_id = fixture["result_id"], fixture["request_id"]
    result = state / "results" / result_id
    result.mkdir(parents=True)
    (result / "meta.json").write_bytes(encode({
        "kind": "run", "host": "offline", "result_id": result_id,
        "status": "complete", "ok": True, "created_at": int(time.time()),
    }))
    (result / "stdout.log").write_text(fixture["stdout"], encoding="utf-8")
    request = state / "requests" / hashlib.sha256(request_id.encode()).hexdigest()
    request.mkdir(parents=True)
    (request / "state.json").write_bytes(encode({
        "request_id": request_id, "request_state": "running",
        "execution_results": [{"host": "offline", "result_id": result_id, "kind": "run"}],
    }))
    # Keep this socket bound but not listening. Even accidental attempts cannot
    # reach an existing service. The environment below does not inherit proxies,
    # auth, host keys, or J(M)S configuration from the caller.
    with socket.socket() as bastion:
        bastion.bind(("127.0.0.1", 0))
        bastion_port = bastion.getsockname()[1]
        config = root / "config.toml"
        config.write_text(f'[bastion]\nurl = "http://127.0.0.1:{bastion_port}"\n'
                          f'ssh_port = {bastion_port}\n[bridge]\n', encoding="utf-8")
        args = [str(binary), "serve", "--config", str(config), "--no-lock"]
        if mode == "stdio":
            args += ["--stdio"]
        else:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            args += ["--host", "127.0.0.1", "--port", str(port)]
        with (root / "stderr.log").open("wb") as stderr:
            with subprocess.Popen(
                args, env={
                    "HOME": str(root), "PATH": "/usr/bin:/bin", "JMS_LOG": "warn",
                    "JMS_BRIDGE_STATE_DIR": str(state),
                    "JMS_BRIDGE_CREDENTIALS": str(root / "nonexistent.toml"),
                }, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                bufsize=0,
            ) as process:
                try:
                    if mode == "stdio":
                        yield lambda body, reply: stdio(process, body, reply)
                    else:
                        await_http(port, process)
                        yield lambda body, reply: exchange_http(port, body, reply)
                finally:
                    process.kill()
                    process.wait(timeout=TIMEOUT)


def stdio(process, body, reply):
    # One request is outstanding at a time and the payload is always small.
    outgoing = body + b"\n"
    process.stdin.write(outgoing)
    if not reply:
        return len(outgoing), b""
    deadline = time.monotonic() + TIMEOUT
    received = bytearray()
    while not received.endswith(b"\n"):
        remaining = max(0, deadline - time.monotonic())
        if not select.select([process.stdout], [], [], remaining)[0]:
            raise TimeoutError("stdio response deadline")
        chunk = process.stdout.read(65536)
        if not chunk:
            raise RuntimeError("bridge closed stdio before sending a full response")
        received.extend(chunk)
    return len(outgoing), bytes(received)


def await_http(port, process):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError("bridge did not start HTTP on loopback")


def exchange_http(port, body, reply):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=TIMEOUT)
    try:
        conn.request("POST", "/mcp", body, {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL,
        })
        response = conn.getresponse()
        data = response.read()
        if response.status != (200 if reply else 202):
            raise RuntimeError(f"unexpected HTTP {response.status}: {data!r}")
        return len(body), data
    finally:
        conn.close()


def declared_tools(listed, fixture):
    required = {step["tool"] for step in fixture["steps"]}
    declared = {tool["name"] for tool in listed["tools"]}
    missing = required - declared
    if missing:
        raise RuntimeError(f"missing fixture tools: {', '.join(sorted(missing))}")
    return sorted(declared)


def task_summary(samples):
    """Summarize only complete, validated fixture iterations."""
    count = len(samples)
    if not count:
        return None
    elapsed = sorted(sample["elapsed_ms"] for sample in samples)
    return {
        "completed": count,
        "tool_calls": sum(sample["tool_calls"] for sample in samples),
        "expected_mcp_errors": sum(sample["expected_mcp_errors"] for sample in samples),
        "request_bytes": sum(sample["request_bytes"] for sample in samples),
        "response_bytes": sum(sample["response_bytes"] for sample in samples),
        "p50_ms": round(elapsed[math.ceil(0.50 * count) - 1], 3),
        "p95_ms": round(elapsed[math.ceil(0.95 * count) - 1], 3),
    }


def benchmark(exchange, fixture, repeats):
    samples = defaultdict(list)
    tasks = []
    rpc_id = 0

    def call(label, method, params=None, reply=True, expect=None, error_contains=None):
        nonlocal rpc_id
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        if reply:
            rpc_id += 1
            message["id"] = rpc_id
        body = encode(message)
        started = time.perf_counter_ns()
        tx, response = exchange(body, reply)
        elapsed_ms = (time.perf_counter_ns() - started) / 1e6
        value = json.loads(response) if response else {}
        if reply and value.get("id") != rpc_id:
            raise RuntimeError(f"{label}: response ID did not match")
        if not reply and response:
            raise RuntimeError(f"{label}: unexpected notification response")
        error = value.get("error")
        result = value.get("result", {})
        tool_error = bool(result.get("isError"))
        if error_contains is not None:
            if not (error or tool_error) or error_contains not in str(value):
                raise RuntimeError(f"{label}: expected error {error_contains!r}, got {value!r}")
        elif error or tool_error:
            raise RuntimeError(f"{label}: unexpected MCP error {value!r}")
        if expect is not None:
            actual = json.loads(result["content"][0]["text"])
            for key, expected in expect.items():
                if actual.get(key) != expected:
                    raise RuntimeError(f"{label}: expected {key}={expected!r}, got {actual!r}")
        # JSON size uses raw UTF-8 MCP payload, without any stdio line terminator.
        samples[label].append((elapsed_ms, tx, len(response), bool(error or tool_error),
                               len(response.removesuffix(b"\n"))))
        return result

    init = call("initialize", "initialize", {
        "protocolVersion": PROTOCOL, "capabilities": {},
        "clientInfo": {"name": "mcp-baseline", "version": "1"},
    })
    if init["serverInfo"]["name"] != "jms-bridge":
        raise RuntimeError("unexpected server")
    bridge_version = init["serverInfo"]["version"]
    call("initialized_notification", "notifications/initialized", reply=False)
    listed = call("tools_list", "tools/list")
    declared = declared_tools(listed, fixture)
    startup_labels = set(samples)
    tool_calls = {step["name"] for step in fixture["steps"]}
    for iteration in range(repeats):
        iteration_rows = []
        iteration_started = time.perf_counter_ns()
        for step in fixture["steps"]:
            label = step["name"]
            if label == "lost_reply_receipt" and iteration == 0:
                # The first lookup reconciles orphaned state; subsequent reads
                # are ordinary lookups. Do not mix their latency distributions.
                label = "lost_reply_receipt_recovery"
                tool_calls.add(label)
            call(label, "tools/call", {
                "name": step["tool"], "arguments": step["arguments"],
            }, expect=step.get("expect"), error_contains=step.get("error_contains"))
            iteration_rows.append(samples[label][-1])
        tasks.append({
            "elapsed_ms": (time.perf_counter_ns() - iteration_started) / 1e6,
            "tool_calls": len(iteration_rows),
            "request_bytes": sum(row[1] for row in iteration_rows),
            "response_bytes": sum(row[2] for row in iteration_rows),
            "expected_mcp_errors": sum(row[3] for row in iteration_rows),
        })

    def summarize(label, rows):
        elapsed, tx, rx, errors, _ = zip(*rows)
        sorted_times = sorted(elapsed)
        return {
            "messages": len(rows), "tool_calls": len(rows) if label in tool_calls else 0,
            "request_bytes": sum(tx), "response_bytes": sum(rx),
            "mcp_errors": sum(errors),
            # stdio notifications have no server acknowledgement; don't time them.
            "p50_ms": None if label == "initialized_notification" else
                round(sorted_times[math.ceil(0.50 * len(rows)) - 1], 3),
            "p95_ms": None if label == "initialized_notification" else
                round(sorted_times[math.ceil(0.95 * len(rows)) - 1], 3),
        }

    def phase(labels):
        details = {label: summarize(label, rows) for label, rows in samples.items()
                   if label in labels}
        fields = ("messages", "tool_calls", "request_bytes", "response_bytes", "mcp_errors")
        return {
            "totals": {key: sum(stats[key] for stats in details.values()) for key in fields},
            "per_operation": details,
        }

    return {
        "bridge_version": bridge_version,
        "startup": phase(startup_labels),
        "workload": phase(samples.keys() - startup_labels),
        "fixture_tasks": {
            "scope": "one complete offline fixture iteration",
            "first_iteration": task_summary(tasks[:1]),
            "subsequent_iterations": task_summary(tasks[1:]),
        },
        "declarations": {
            "tools": declared,
            "initialize_response_json_bytes": samples["initialize"][0][4],
            "tools_list_response_json_bytes": samples["tools_list"][0][4],
        },
    }


def main():
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("--binary", type=Path, required=True)
    arg.add_argument("--server-git-sha", required=True,
                     help="full Git commit ID of the source used to build --binary")
    arg.add_argument("--repeats", type=int, default=30)
    options = arg.parse_args()
    if options.repeats < 1:
        arg.error("--repeats must be positive")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", options.server_git_sha):
        arg.error("--server-git-sha must be a full 40-hex Git commit ID")
    fixture_bytes = FIXTURE.read_bytes()
    fixture = json.loads(fixture_bytes)
    binary_sha256 = hashlib.sha256()
    with options.binary.open("rb") as binary:
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            binary_sha256.update(chunk)
    data = {
        "report_version": 3,
        "server_git_sha": options.server_git_sha.lower(),
        "binary_sha256": binary_sha256.hexdigest(),
        "fixture": FIXTURE.name,
        "fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
        "repeats": options.repeats,
        "model_tokens": None,
        "ssh_probes": None,
        "byte_scope": {"stdio": "UTF-8 JSON + LF", "http": "HTTP bodies only"},
        "transports": {},
    }
    with tempfile.TemporaryDirectory(prefix="jms-mcp-baseline-") as tmp:
        for mode in ("stdio", "http"):
            with bridge(options.binary.resolve(), mode, Path(tmp) / mode, fixture) as exchange:
                data["transports"][mode] = benchmark(exchange, fixture, options.repeats)
    print(json.dumps(data, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
