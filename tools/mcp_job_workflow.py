"""Deterministic in-process job workflow probe; not an MCP or SSH measurement."""
from collections import Counter
import hashlib
import json
from pathlib import Path


FIXTURE = Path(__file__).with_name("mcp-job-workflow-fixture.json")
TERMINAL = {"done", "failed"}


def handle(row):
    return {key: row[key] for key in ("target", "job_id")}


def key(row):
    return row["target"], row["job_id"]


def replay(fixture, call):
    """Follow reusable handles, then validate each terminal status and log."""
    expected = {key(row): row for row in fixture["targets"]}
    if not expected or len(expected) != len(fixture["targets"]):
        raise ValueError("fixture requires unique, nonempty job handles")
    submitted = call("submit", targets=[target for target, _ in expected],
                     request_id="offline-job-workflow", command="printf synthetic")
    pending = submitted["jobs"]
    if not submitted.get("ok") or Counter(map(key, pending)) != Counter(expected.keys()):
        raise RuntimeError("submit did not return the expected handles")
    terminal = {}
    for _ in range(fixture["max_wait_calls"]):
        watched = set(map(key, pending))
        reply = call("wait", jobs=pending)
        still_pending = set()
        for row in reply["status"]:
            job = key(row)
            if job not in watched:
                raise RuntimeError("wait returned an unknown or duplicate job")
            watched.remove(job)
            if row["status"] in TERMINAL:
                fixture_row = expected[job]
                if (row["status"], row["exit_code"]) != (
                    fixture_row["states"][-1], fixture_row["exit_code"]
                ):
                    raise RuntimeError("unexpected terminal state or exit code")
                terminal[job] = row["status"]
            elif row["status"] == "running":
                still_pending.add(job)
            else:
                raise RuntimeError("unexpected nonterminal state")
        pending = reply["pending"]
        if (watched or Counter(map(key, pending)) != Counter(still_pending)
                or reply["finished"] != (not pending)):
            raise RuntimeError("wait did not preserve the pending handles")
        if not pending:
            break
    if pending:
        raise RuntimeError("fixture exhausted its wait call budget")
    for job, row in expected.items():
        page = call("logs", **handle(row), offset=0, max_bytes=1024)
        if not page.get("ok") or page["log"] != row["text"]:
            raise RuntimeError(f"unexpected log for {job}")
    return Counter(terminal.values())


def mock_sample(fixture):
    rows = {key(row): row for row in fixture["targets"]}
    calls = Counter()
    probes = Counter()
    polls = Counter()

    def call(action, **arguments):
        calls[action] += 1
        if action == "submit":
            if arguments["targets"] != [target for target, _ in rows]:
                raise RuntimeError("submit targeted the wrong fixture assets")
            probes["launch"] += len(rows)
            return {"ok": True, "jobs": [handle(row) for row in rows.values()]}
        if action == "wait":
            status, pending = [], []
            for job_handle in arguments["jobs"]:
                job = key(job_handle)
                row = rows[job]
                states = row["states"]
                if polls[job] >= len(states):
                    raise RuntimeError("wait probed a terminal job again")
                state = states[polls[job]]
                polls[job] += 1
                probes["status"] += 1
                status.append({**job_handle, "status": state,
                               "exit_code": row["exit_code"] if state in TERMINAL else None})
                if state not in TERMINAL:
                    pending.append(job_handle)
            return {"status": status, "finished": not pending, "pending": pending}
        if action != "logs":
            raise RuntimeError(f"unsupported fixture action {action!r}")
        probes["log"] += 1
        return {"ok": True, "log": rows[key(arguments)]["text"]}

    terminal = replay(fixture, call)
    return calls, probes, terminal


def mock_workflow_report(repeats):
    fixture_bytes = FIXTURE.read_bytes()
    fixture = json.loads(fixture_bytes)
    calls, probes, terminal = Counter(), Counter(), Counter()
    for _ in range(repeats):
        step_calls, step_probes, states = mock_sample(fixture)
        calls.update(step_calls)
        probes.update(step_probes)
        terminal.update(states)
    return {
        "scope": "in-process scripted mock; no bridge, MCP transport, SSH, bytes or timing",
        "fixture": FIXTURE.name,
        "fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
        "completed_workflows": repeats,
        "targets_per_workflow": len(fixture["targets"]),
        "modeled_calls_by_step": dict(calls),
        "simulated_probes_by_kind": dict(probes),
        "simulated_probes_per_workflow": sum(probes.values()) / repeats,
        "terminal_jobs_by_state": dict(terminal),
    }
