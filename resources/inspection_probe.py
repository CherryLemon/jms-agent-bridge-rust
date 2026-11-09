"""Read-only stdlib collector, sent over the resident SSH connection on stdin.

Vendor command choices follow jms-top (Apache-2.0); no login, installation,
environment-file sourcing, accelerator workload, or remote file writes occur.
"""

import glob
import json
import os
import pwd
import re
import shutil
import subprocess
import time
from pathlib import Path

MAX_BYTES = 512 * 1024
TOOLS = {
    "nvidia": ("nvidia-smi", ["/usr/local/nvidia/bin/nvidia-smi"]),
    "ascend": ("npu-smi", ["/usr/local/Ascend/driver/tools/npu-smi"]),
    "mthreads": ("mthreads-gmi", ["/usr/local/musa/bin/mthreads-gmi"]),
    "kunlunxin": ("xpu-smi", ["/usr/local/xpu/bin/xpu-smi"]),
    "metax": ("mx-smi", ["/opt/mxdriver/bin/mx-smi"]),
    "enflame": ("efsmi", ["/opt/tops/bin/efsmi"]),
    "tsingmicro": ("tsm_smi", []),
    "thead": ("ppu-smi", ["/usr/local/PPU_SDK/ppu-smi/bin/ppu-smi"]),
    "iluvatar": ("ixsmi", ["/usr/local/corex*/bin/ixsmi"]),
    "hygon": ("hy-smi", ["/opt/hyhal/bin/hy-smi"]),
}


def read(path, limit=65536):
    with open(path, "rb") as stream:
        return stream.read(limit).decode("utf-8", "replace")


def command(argv, timeout=12, env=None):
    """Bound output in memory and kill only this collector's timed-out child."""
    import selectors

    clean_env = dict(os.environ, LC_ALL="C", LANG="C")
    if env:
        clean_env.update(env)
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_env,
            stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        return {"rc": None, "stdout": "", "stderr": str(exc), "error": "launch_failed"}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    error = None
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as poll:
            for name in buffers:
                poll.register(getattr(proc, name), selectors.EVENT_READ, name)
            while poll.get_map():
                if time.monotonic() >= deadline:
                    error = "timeout"
                    break
                for key, _ in poll.select(min(0.2, max(0, deadline - time.monotonic()))):
                    block = os.read(key.fd, 65536)
                    if not block:
                        poll.unregister(key.fileobj)
                        continue
                    remaining = MAX_BYTES - sum(map(len, buffers.values()))
                    buffers[key.data].extend(block[:remaining])
                    if len(block) > remaining:
                        error = "output_limit"
                        break
                if error:
                    break
            if error:
                proc.kill()
            try:
                proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                error = "timeout"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()
    return {
        "rc": proc.returncode,
        "error": error,
        **{name: value.decode("utf-8", "replace") for name, value in buffers.items()},
    }


def find_tool(name, patterns):
    found = shutil.which(name)
    if found:
        return found
    for pattern in patterns:
        for candidate in sorted(glob.glob(pattern), reverse=True):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def node_info():
    result = {"hostname": os.uname().nodename, "cpu_count": os.cpu_count()}
    try:
        result["load"] = list(os.getloadavg())
        mem = dict(
            re.findall(
                r"^(MemTotal|MemAvailable):\s+(\d+)",
                read("/proc/meminfo"),
                re.MULTILINE,
            )
        )
        result["memory_total_mib"] = int(mem["MemTotal"]) / 1024
        result["memory_available_mib"] = int(mem["MemAvailable"]) / 1024
        result["uptime_seconds"] = float(read("/proc/uptime").split()[0])
    except (OSError, ValueError, KeyError, IndexError):
        result["incomplete"] = True
    return result


def hygon_extra():
    sections, errors = ["##HYGON-VRAM"], []
    for device in sorted(Path("/sys/class/drm").glob("card[0-9]*/device")):
        if not (device / "mem_info_vram_total").exists():
            continue
        try:
            sections.append(
                "{} {} {}".format(
                    device.parent.name,
                    int(read(device / "mem_info_vram_used")),
                    int(read(device / "mem_info_vram_total")),
                )
            )
        except (OSError, ValueError):
            errors.append("VRAM sysfs unavailable")
    sections.append("##HYGON-PROCS")
    base = Path("/sys/class/kfd/kfd/proc")
    if not base.exists():
        errors.append("KFD process list unavailable")
    else:
        try:
            for p in base.iterdir():
                if p.name.isdigit():
                    # The PID alone establishes occupancy even if the process exits.
                    try:
                        user = pwd.getpwuid(Path("/proc", p.name).stat().st_uid).pw_name
                        name = read("/proc/" + p.name + "/comm").strip()
                    except (OSError, KeyError):
                        user, name = "?", "[unavailable]"
                    sections.append(f"{p.name} {user} {name}")
        except OSError:
            errors.append("KFD process list unreadable")
    return "\n".join(sections), errors


def collect():
    report = {
        "schema_version": 1,
        "started_at": time.time(),
        "node": node_info(),
        "vendors": {},
    }
    for family, (name, paths) in TOOLS.items():
        binary = find_tool(name, paths)
        if not binary:
            continue
        env = None
        if family == "iluvatar":
            root = str(Path(binary).parent.parent)
            env = {
                "LD_LIBRARY_PATH": root
                + "/lib:"
                + root
                + "/lib64:"
                + os.environ.get("LD_LIBRARY_PATH", "")
            }
        queries = {
            "nvidia": [
                (
                    "--query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,gpu_bus_id",
                    "--format=csv,noheader,nounits",
                ),
                (
                    "--query-compute-apps=gpu_bus_id,pid,process_name,used_memory",
                    "--format=csv,noheader,nounits",
                ),
            ],
            "ascend": [("info",)],
            "metax": [("--show-memory",), ("--show-usage",), ("--show-process",)],
            "enflame": [(), ("pmon", "-c", "1")],
            "hygon": [(), ("--showproductname",)],
        }.get(family, [()])
        answers = [command([binary, *args], env=env) for args in queries]
        errors = [
            "query {}: {}".format(i, a["error"] or "exit " + str(a["rc"]))
            for i, a in enumerate(answers)
            if a["rc"] != 0 or a["error"]
        ]
        text = "\n".join(a["stdout"] for a in answers)
        # MetaX per-type flags differ by driver. A complete default table is a fallback.
        if family == "metax":
            if not errors and "GPU#" in text:
                text = "##METAX-WIDE\n" + text
            else:
                answer = command([binary], env=env)
                answers.append(answer)
                text = answer["stdout"]
                errors = (
                    [] if answer["rc"] == 0 and not answer["error"] else ["MetaX queries failed"]
                )
        if family == "hygon":
            extra, extra_errors = hygon_extra()
            text = answers[0]["stdout"] + "\n" + extra + "\n##HYGON-MODEL\n" + answers[1]["stdout"]
            errors += extra_errors
        report["vendors"][family] = {
            "tool": binary,
            "text": text,
            "errors": errors,
            "queries": answers,
            "sampled_at": time.time(),
        }
    report["finished_at"] = time.time()
    return report


SECRET = re.compile(
    r"(?i)(?:^|[-_])(password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|authorization|credential)(?:$|[-_])"
)


def safe_argv(args):
    """Redact common secret argument forms before they leave the inspected host."""
    out, hide_next = [], False
    for arg in args:
        if hide_next:
            out.append("[REDACTED]")
            hide_next = False
            continue
        key, sep, _value = arg.partition("=")
        if SECRET.search(key.lstrip("-")):
            out.append(key + "=[REDACTED]" if sep else key)
            hide_next = not sep
            continue
        if re.search(r"(?i)\b(bearer|basic)\s+\S+", arg):
            out.append("[REDACTED AUTH]")
            continue
        if arg.lower() in ("bearer", "basic"):
            out.append(arg)
            hide_next = True
            continue
        arg = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", arg)
        arg = re.sub(
            r"(?i)([?&](?:api[_-]?key|token|secret|password|access_token)=)[^&#\s]+",
            r"\1[REDACTED]",
            arg,
        )
        out.append(arg)
    return out


def process_details(pids, sampled_at):
    containers = {}
    docker = find_tool("docker", [])
    docker_error = None
    if docker:
        response = command([docker, "ps", "--no-trunc", "--format", "{{json .}}"], timeout=6)
        docker_error = response["error"] or (None if response["rc"] == 0 else "docker ps failed")
        for line in response["stdout"].splitlines():
            try:
                row = json.loads(line)
                containers[row["ID"]] = {
                    "id": row["ID"],
                    "name": row["Names"],
                    "image": row["Image"],
                }
            except (ValueError, KeyError, TypeError):
                docker_error = "docker metadata incomplete"
    try:
        boot = int(re.search(r"^btime (\d+)", read("/proc/stat"), re.MULTILINE).group(1))
    except (OSError, AttributeError):
        boot = None
    rows = []
    for pid in pids[:128]:
        if type(pid) is not int or pid <= 0:
            raise ValueError("invalid PID")
        path = Path("/proc", str(pid))
        row = {"pid": pid}
        try:
            stat_before = read(path / "stat").rsplit(")", 1)[1].split()
            start = int(stat_before[19])
            row["start_ticks"] = start
            if boot is not None and boot + start / os.sysconf("SC_CLK_TCK") > sampled_at:
                rows.append(dict(row, state="started_after_sample"))
                continue
            uid = path.stat().st_uid
            try:
                row["user"] = pwd.getpwuid(uid).pw_name
            except KeyError:
                row["user"] = str(uid)
            row["name"] = read(path / "comm").strip()
            raw = read(path / "cmdline", 8192)
            row["command"] = " ".join(safe_argv(raw.rstrip("\0").split("\0")))[:512]
            row["command_truncated"] = (
                len(raw) >= 8192 or len(" ".join(safe_argv(raw.rstrip("\0").split("\0")))) > 512
            )
            if boot is not None:
                row["elapsed_seconds"] = max(
                    0, round(time.time() - boot - start / os.sysconf("SC_CLK_TCK"))
                )
            try:
                group = read(path / "cgroup")
                ids = re.findall(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", group)
                row["container"] = next(
                    (containers[c] for c in ids if c in containers),
                    {"id": ids[0], "name": None} if ids else {"name": "host"},
                )
            except OSError:
                row["container"] = {"name": None}
            stat_after = read(path / "stat").rsplit(")", 1)[1].split()
            if int(stat_after[19]) != start:
                row = {"pid": pid, "state": "pid_reused"}
            else:
                row["state"] = "observed"
        except (OSError, ValueError, IndexError):
            row = {"pid": pid, "state": "exited_or_inaccessible"}
        rows.append(row)
    return {"observed_at": time.time(), "processes": rows, "docker_error": docker_error}


def main(options):
    result = (
        process_details(options["pids"], options["sampled_at"])
        if options.get("mode") == "processes"
        else collect()
    )
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
