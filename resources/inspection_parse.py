"""Node-side accelerator parsing, sent over the resident SSH connection.

This module is executed *remotely* by every inspection run, next to the collector
and the vendored per-vendor parsers, so the fleet keeps the parsing rules that were
written against captured vendor output instead of re-deriving them on the bridge.
It prints one JSON object: the parsed node snapshot, or the process-detail reply.

Globals injected by the wrapper: ``__jms_f`` (vendored families) and ``__jms_p``
(the collector).
"""

import csv
import io
import json
import math
import re

FAMILIES = __jms_f["FAMILIES"]
Proc = __jms_f["Proc"]


def device_state(card, complete, process_known, shared_processes=False):
    if card.health and card.health.upper() not in ("OK", "NORMAL", "GOOD"):
        return "unhealthy"
    if card.procs and not card.procs_shared:
        return "busy"
    if card.util is not None and math.isfinite(card.util) and card.util >= 5:
        return "busy"
    memory_valid = (
        card.mem_used is not None
        and card.mem_total is not None
        and math.isfinite(card.mem_used)
        and math.isfinite(card.mem_total)
        and 0 <= card.mem_used <= card.mem_total
        and card.mem_total > 0
    )
    if memory_valid and card.mem_used / card.mem_total > 0.10:
        return "memory_held"
    if (
        not complete
        or not process_known
        or shared_processes
        or not memory_valid
        or card.util is None
        or not math.isfinite(card.util)
        or not 0 <= card.util < 5
    ):
        return "unknown"
    return "free"


def process_table_known(family, text, raw):
    if family == "nvidia":
        return (
            len(raw.get("queries", [])) >= 2
            and not raw["queries"][1].get("error")
            and raw["queries"][1].get("rc") == 0
        )
    if family == "hygon":
        return "##HYGON-PROCS" in text and not raw.get("errors")
    return bool(
        re.search(
            r"(?i)(process(?:es)?\s*:|process\s+(?:id|name)|\bPID\b|no running processes)",
            text,
        )
    )


def normalize_bus(value):
    parts = value.lower().split(":")
    return ":".join([parts[0].lstrip("0") or "0", *parts[1:]])


def fix_nvidia_processes(cards, raw):
    """Keep a PID even when its memory is N/A; never silently drop unknown rows."""
    queries = raw.get("queries", [])
    if len(queries) < 2:
        return ["missing NVIDIA process query"]
    buses, errors = {}, []
    gpu_rows = [
        r for r in csv.reader(io.StringIO(queries[0]["stdout"])) if any(x.strip() for x in r)
    ]
    if len(gpu_rows) != len(cards) or len({c.index for c in cards}) != len(cards):
        errors.append("NVIDIA device table incomplete or malformed")
    for row in gpu_rows:
        if len(row) >= 8 and row[0].strip().isdigit():
            buses[normalize_bus(row[-1].strip())] = int(row[0])
    by_id = {c.index: c for c in cards}
    for card in cards:
        card.procs = []
    for row in csv.reader(io.StringIO(queries[1]["stdout"])):
        if not row or not any(x.strip() for x in row):
            continue
        if len(row) < 4 or not row[1].strip().isdigit():
            errors.append("unparsed NVIDIA process row")
            continue
        owner = by_id.get(buses.get(normalize_bus(row[0].strip())))
        if owner is None:
            errors.append("NVIDIA process device could not be mapped")
            continue
        try:
            mem = float(row[-1].strip().split()[0])
        except (ValueError, IndexError):
            mem = None
        owner.procs.append(
            Proc(
                pid=int(row[1]),
                user=None,
                name=",".join(row[2:-1]).strip(),
                mem_mib=mem,
            )
        )
    return errors


def parse_snapshot(snapshot):
    devices, processes, errors = [], {}, []
    for key, raw in snapshot.get("vendors", {}).items():
        if key not in FAMILIES:
            errors.append(key + ": unsupported accelerator tool")
            continue
        text = raw.get("text", "")
        problems = list(raw.get("errors", []))
        try:
            parsed = FAMILIES[key].parse(text)
        except (ValueError, IndexError, TypeError, KeyError) as exc:
            errors.append(key + ": parser error " + type(exc).__name__)
            continue
        if parsed.error or not parsed.cards:
            errors.append(key + ": " + (parsed.error or "no devices parsed"))
            continue
        if key == "nvidia":
            problems.extend(fix_nvidia_processes(parsed.cards, raw))
        known = process_table_known(key, text, raw)
        if not known:
            problems.append("process table unavailable or unrecognized")
        errors.extend(key + ": " + p for p in problems)
        shared = any(c.procs_shared and c.procs for c in parsed.cards)
        for card in parsed.cards:
            device_id = key + ":" + str(card.index)
            state = device_state(card, not problems, known, shared)
            devices.append(
                {
                    "id": device_id,
                    "family": key,
                    "index": card.index,
                    "physical_card": card.card if card.card is not None else card.index,
                    "model": card.name,
                    "state": state,
                    "util_pct": card.util,
                    "memory_used_mib": card.mem_used,
                    "memory_total_mib": card.mem_total,
                    "temperature_c": card.temp,
                    "power_w": card.power,
                    "health": card.health,
                    "process_table_known": known,
                    "process_scope": "host" if shared else "device",
                    "pids": []
                    if card.procs_shared
                    else sorted({p.pid for p in card.procs if p.pid is not None}),
                }
            )
            for process in card.procs:
                if process.pid is None:
                    continue
                row = processes.setdefault(
                    process.pid,
                    {
                        "pid": process.pid,
                        "user": process.user,
                        "name": process.name,
                        "devices": [],
                        "memory_by_device_mib": {},
                        "scope": "host" if card.procs_shared else "device",
                    },
                )
                if not card.procs_shared:
                    if device_id not in row["devices"]:
                        row["devices"].append(device_id)
                    row["memory_by_device_mib"][device_id] = process.mem_mib
    if not devices:
        state = "unknown" if snapshot.get("vendors") else "no_accelerator_detected"
    elif errors:
        state = "partial" if any(d["state"] == "free" for d in devices) else "unknown"
    elif all(d["state"] == "free" for d in devices):
        state = "free"
    elif any(d["state"] == "free" for d in devices):
        state = "partial"
    elif any(d["state"] == "busy" for d in devices):
        state = "busy"
    elif any(d["state"] == "unhealthy" for d in devices):
        state = "unhealthy"
    elif any(d["state"] == "memory_held" for d in devices):
        state = "memory_held"
    else:
        state = "unknown"
    return {
        "state": state,
        "devices": devices,
        "processes": list(processes.values()),
        "errors": errors,
        "node": snapshot.get("node", {}),
        "sampled_at": snapshot.get("finished_at"),
        "whole_node_available": bool(devices) and state == "free",
    }


def __jms_entry(options):
    if options.get("mode") == "processes":
        # The collector's own main() prints the process-detail reply.
        __jms_p["main"](options)
        return
    snapshot = __jms_p["collect"]()
    print(json.dumps(parse_snapshot(snapshot), ensure_ascii=False, separators=(",", ":")))