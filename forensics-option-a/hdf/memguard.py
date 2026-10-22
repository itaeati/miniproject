"""Memory guard for the model server process.

The integrated GPU has no memory of its own: weights, KV cache and activations come
out of system RAM. When it runs out the kernel OOM killer chooses its victims by its
own score, and on 2026-10-07 it killed desktop services while the model server kept
running. The guard polls /proc/meminfo and, as soon as available memory falls below
a floor, kills the server's whole process group with SIGKILL (SIGTERM is not used: a
server inside a GPU call may not handle it in time). Swap use is recorded but is not
a kill condition: loading a model on this machine moves ~1 GB to swap within seconds
while 14 GB are still available (measured 2026-10-08). What the guard saw is written
to a record file, and every sample to an optional trace.

Usable from the engine (ServerManager) and standalone:
  python3 -m hdf.memguard --pid PID [--min-available-mb N]
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable

DEFAULT_MIN_AVAILABLE_MB = 6144
DEFAULT_INTERVAL_S = 0.05  # GPU input processing freed up to ~6 GB/s (2026-10-08)
GPU_SAMPLE_EVERY_S = 2.0  # per-process GPU memory is read less often (one file per fd)


def read_meminfo() -> dict[str, int]:
    """/proc/meminfo values in kB."""
    out = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, _, v = line.partition(":")
            parts = v.split()
            if parts and parts[0].isdigit():
                out[k] = int(parts[0])
    return out


_UNITS = {"": 1, "B": 1, "KiB": 1024, "kB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3}


def gpu_resident_mb(pid: int) -> float | None:
    """GPU memory resident for a process, summed over its DRM clients (drm-resident-*
    in /proc/PID/fdinfo; several fds can share one client). None if unreadable."""
    clients: dict[str, int] = {}
    try:
        fds = os.listdir(f"/proc/{pid}/fdinfo")
    except OSError:
        return None
    for fd in fds:
        try:
            text = Path(f"/proc/{pid}/fdinfo/{fd}").read_text()
        except OSError:
            continue
        if "drm-client-id:" not in text:
            continue
        cid, total = "", 0
        for line in text.splitlines():
            k, _, v = line.partition(":")
            parts = v.split()
            if k == "drm-client-id" and parts:
                cid = parts[0]
            elif k.startswith("drm-resident-") and parts and parts[0].isdigit():
                total += int(parts[0]) * _UNITS.get(parts[1] if len(parts) > 1 else "", 1)
        clients[cid] = total
    return round(sum(clients.values()) / 1048576, 1) if clients else None


def _sample(mi: dict[str, int], swap0_kb: int) -> dict:
    return {"t": round(time.time(), 3),
            "available_mb": mi.get("MemAvailable", 0) // 1024,
            "swap_used_mb": (mi.get("SwapTotal", 0) - mi.get("SwapFree", 0)) // 1024,
            "swap_growth_mb": (mi.get("SwapTotal", 0) - mi.get("SwapFree", 0) - swap0_kb) // 1024,
            "gpu_active_mb": mi["GPUActive"] // 1024 if "GPUActive" in mi else None}


class MemoryGuard(threading.Thread):
    """Watches system memory while process `pid` runs and kills its process group
    when a limit is crossed. `tripped` holds the record afterwards (None if not)."""

    def __init__(self, pid: int, min_available_mb: int = DEFAULT_MIN_AVAILABLE_MB, interval_s: float = DEFAULT_INTERVAL_S,
                 record_path: Path | None = None, trace_path: Path | None = None, label: str = "server",
                 meminfo_fn: Callable[[], dict[str, int]] = read_meminfo):
        super().__init__(name=f"memguard-{pid}", daemon=True)
        self.pid, self.label = pid, label
        self.min_available_mb = int(min_available_mb)
        self.interval_s = float(interval_s)
        self.record_path, self.trace_path = record_path, trace_path
        self.meminfo_fn = meminfo_fn
        self.tripped: dict | None = None
        self.fired = threading.Event()  # set before the kill; `tripped` is filled in after it
        self.min_available_seen: int | None = None
        self.max_swap_growth_seen = 0
        self.samples = 0
        self._halt = threading.Event()  # not `_stop`: Thread uses that name internally
        self._recent: deque = deque(maxlen=200)
        self._gpu_mb: float | None = None
        self._gpu_t = 0.0
        mi = meminfo_fn()
        self._swap0_kb = mi.get("SwapTotal", 0) - mi.get("SwapFree", 0)

    def limit_crossed(self, s: dict) -> str | None:
        if s["available_mb"] < self.min_available_mb:
            return f"MemAvailable {s['available_mb']} MB < {self.min_available_mb} MB"
        return None

    def run(self) -> None:
        trace = open(self.trace_path, "a") if self.trace_path else None
        try:
            while not self._halt.is_set():
                if not _alive(self.pid):
                    return
                s = _sample(self.meminfo_fn(), self._swap0_kb)
                if s["t"] - self._gpu_t >= GPU_SAMPLE_EVERY_S:
                    self._gpu_mb, self._gpu_t = gpu_resident_mb(self.pid), s["t"]
                s["server_gpu_mb"] = self._gpu_mb
                self.samples += 1
                self._recent.append(s)
                if self.min_available_seen is None or s["available_mb"] < self.min_available_seen:
                    self.min_available_seen = s["available_mb"]
                self.max_swap_growth_seen = max(self.max_swap_growth_seen, s["swap_growth_mb"])
                if trace:
                    trace.write(json.dumps(s) + "\n")
                    trace.flush()
                reason = self.limit_crossed(s)
                if reason:
                    self._trip(reason, s)
                    return
                self._halt.wait(self.interval_s)
        finally:
            if trace:
                trace.close()

    def _trip(self, reason: str, s: dict) -> None:
        self.fired.set()
        killed = _kill_group(self.pid)
        t_kill = time.time()
        after = []
        for _ in range(20):  # how much memory came back, for the record
            time.sleep(0.5)
            after.append(_sample(self.meminfo_fn(), self._swap0_kb))
            if not _alive(self.pid) and len(after) >= 4:
                break
        self.tripped = {
            "label": self.label, "pid": self.pid, "reason": reason, "action": killed,
            "process_exited": not _alive(self.pid), "detected_at": s["t"],
            "kill_latency_s": round(t_kill - s["t"], 3), "at_trip": s,
            "server_gpu_mb_last": {"mb": self._gpu_mb, "sampled_at": self._gpu_t},
            "limits": {"min_available_mb": self.min_available_mb, "interval_s": self.interval_s},
            "before": list(self._recent), "after_kill": after}
        if self.record_path:
            try:
                Path(self.record_path).write_text(json.dumps(self.tripped, indent=1))
            except OSError:
                pass

    def stop(self) -> None:
        self._halt.set()
        if self.is_alive() and threading.current_thread() is not self:
            self.join(timeout=20)


def _alive(pid: int) -> bool:
    """True while the process exists and is not a zombie."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def _kill_group(pid: int) -> str:
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError:
        return "already exited"
    try:
        if pgid == os.getpgrp():  # never take down the caller's own group
            os.kill(pid, signal.SIGKILL)
            return f"SIGKILL pid {pid}"
        os.killpg(pgid, signal.SIGKILL)
        return f"SIGKILL process group {pgid}"
    except ProcessLookupError:
        return "already exited"


def available_mb() -> int:
    return read_meminfo().get("MemAvailable", 0) // 1024


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m hdf.memguard", description=__doc__.split("\n\n")[0])
    ap.add_argument("--pid", type=int, required=True, help="process to guard (its process group is killed)")
    ap.add_argument("--min-available-mb", type=int, default=DEFAULT_MIN_AVAILABLE_MB)
    ap.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_S)
    ap.add_argument("--record", type=Path, help="JSON record written when the guard trips")
    ap.add_argument("--trace", type=Path, help="JSON lines, one per sample")
    a = ap.parse_args(argv)
    if not _alive(a.pid):
        print(f"process {a.pid} does not exist", file=sys.stderr)
        return 2
    g = MemoryGuard(a.pid, a.min_available_mb, a.interval, a.record, a.trace,
                    label=f"pid {a.pid}")
    print(f"guarding pid {a.pid}: kill if MemAvailable < {a.min_available_mb} MB (every {a.interval}s)",
          flush=True)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: g.stop())
    g.start()
    while g.is_alive():
        g.join(timeout=1)
    if g.tripped:
        print(f"TRIPPED: {g.tripped['reason']}; {g.tripped['action']}; exited={g.tripped['process_exited']}",
              flush=True)
        return 3
    print(f"{'guard stopped' if _alive(a.pid) else f'process {a.pid} ended'}; minimum MemAvailable "
          f"{g.min_available_seen} MB, max swap growth {g.max_swap_growth_seen} MB", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
