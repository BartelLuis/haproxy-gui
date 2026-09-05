import re
import shutil
import time

from . import sshclient

CMD = (
    "grep '^cpu ' /proc/stat; sleep 0.5; grep '^cpu ' /proc/stat; echo --MEM--; "
    "grep -E 'MemTotal|MemAvailable' /proc/meminfo; echo --LOAD--; "
    "cat /proc/loadavg; echo --DISK--; df -P / | tail -1"
)


def _cpu_percent(line1, line2):
    def vals(line):
        return [int(x) for x in line.split()[1:]]

    a, b = vals(line1), vals(line2)
    idle_a, idle_b = a[3] + a[4], b[3] + b[4]
    total_a, total_b = sum(a), sum(b)
    d_total, d_idle = total_b - total_a, idle_b - idle_a
    if d_total <= 0:
        return 0.0
    return round(100.0 * (d_total - d_idle) / d_total, 1)


def _parse_output(text):
    result = {"cpu_percent": None, "load": "", "mem": {}, "disk": {}}
    lines = text.splitlines()
    cpu_lines = [cpu_line for cpu_line in lines if cpu_line.startswith("cpu ")]
    if len(cpu_lines) >= 2:
        result["cpu_percent"] = _cpu_percent(cpu_lines[0], cpu_lines[1])
    mem = {}
    for line in lines:
        m = re.match(r"(MemTotal|MemAvailable):\s+(\d+) kB", line)
        if m:
            mem[m.group(1)] = int(m.group(2)) // 1024
    if mem.get("MemTotal"):
        result["mem"] = {
            "total_mb": mem["MemTotal"],
            "used_mb": mem["MemTotal"] - mem.get("MemAvailable", 0),
            "percent": round(
                100.0 * (mem["MemTotal"] - mem.get("MemAvailable", 0)) / mem["MemTotal"], 1
            ),
        }
    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and re.match(r"^\d+\.\d+", parts[0] or ""):
            result["load"] = " ".join(parts[:3])
        if parts and parts[-1] == "/" and "%" in "".join(parts):
            # df -P / Ausgabezeile
            try:
                result["disk"] = {
                    "total_mb": int(parts[1]) // 1024,
                    "used_mb": int(parts[2]) // 1024,
                    "percent": int(parts[4].rstrip("%")),
                }
            except (ValueError, IndexError):
                pass
    return result


def _local_output():
    with open("/proc/stat") as f:
        cpu1 = f.readline()
    time.sleep(0.5)
    with open("/proc/stat") as f:
        cpu2 = f.readline()
    out = [cpu1, cpu2, "--MEM--"]
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith(("MemTotal", "MemAvailable")):
                out.append(line)
    out.append("--LOAD--")
    with open("/proc/loadavg") as f:
        out.append(f.readline())
    out.append("--DISK--")
    usage = shutil.disk_usage("/")
    out.append(f"overlay {usage.total // 1024} {usage.used // 1024} 0 0% /")
    return "\n".join(out)


def get_metrics(node):
    if node.get("is_local"):
        return _parse_output(_local_output())
    rc, out, err = sshclient.run_ssh(node, CMD, timeout=30)
    if rc != 0 and "--MEM--" not in out:
        raise RuntimeError(err.strip() or "Metriken konnten nicht gelesen werden")
    return _parse_output(out)
