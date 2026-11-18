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


def benchmark(exchange, fixture, repeats):
    samples = defaultdict(list)
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
    tool_calls = {step["name"] for step in fixture["steps"]}
    for iteration in range(repeats):
        listed = call("tools_list", "tools/list")
        if {tool["name"] for tool in listed["tools"]} != {
            "run", "fs", "terminal", "read_result", "discover", "call", "meta",
        }:
            raise RuntimeError("unexpected tool declarations")
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

    details = {label: summarize(label, rows) for label, rows in samples.items()}
    totals = {key: sum(stats[key] for stats in details.values()) for key in
              ("messages", "tool_calls", "request_bytes", "response_bytes", "mcp_errors")}
    return {
        "bridge_version": bridge_version,
        "totals": totals,
        "per_operation": details,
        "declaration_bytes": {
            "initialize_response_json": samples["initialize"][0][4],
            "tools_list_response_json_max": max(row[4] for row in samples["tools_list"]),
        },
    }


def main():
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("--binary", type=Path, required=True)
    arg.add_argument("--repeats", type=int, default=30)
    options = arg.parse_args()
    if options.repeats < 1:
        arg.error("--repeats must be positive")
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data = {
        "report_version": 1,
        "fixture": FIXTURE.name,
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
