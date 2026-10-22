"""Memory guard: limits are enforced on real processes (with /proc/meminfo replaced so no
memory is actually exhausted), the whole process group dies, and the engine stops
instead of restarting the server and repeating the request."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from hdf.config import ConfigError
from hdf.llm import LLMClient, MemoryGuardError, ServerManager
from hdf.memguard import MemoryGuard, _alive, read_meminfo

from .fixtures import FakeFormatter, make_config

GB = 1024 * 1024  # kB


def fake_meminfo(avail_kb, swap_used_kb=0):
    return {"MemTotal": 32 * GB, "MemAvailable": avail_kb, "SwapTotal": 8 * GB,
            "SwapFree": 8 * GB - swap_used_kb, "GPUActive": 1 * GB}


class Script:
    """meminfo values taken from a list, the last one repeating."""

    def __init__(self, *values):
        self.values, self.calls = list(values), 0

    def __call__(self):
        v = self.values[min(self.calls, len(self.values) - 1)]
        self.calls += 1
        return v


def group_members(pgid):
    r = subprocess.run(["pgrep", "-g", str(pgid)], capture_output=True, text=True)
    return [int(x) for x in r.stdout.split()]


class MemoryGuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()

    def spawn(self, cmd, new_session=True):
        p = subprocess.Popen(cmd, start_new_session=new_session)
        self.procs.append(p)
        return p

    def test_trips_on_low_available_and_kills_whole_group(self):
        p = self.spawn(["bash", "-c", "sleep 60 & sleep 60; wait"])
        time.sleep(0.2)
        self.assertGreaterEqual(len(group_members(p.pid)), 2)
        # first value: swap baseline read by the constructor; then three polls
        mi = Script(fake_meminfo(12 * GB), fake_meminfo(12 * GB), fake_meminfo(12 * GB), fake_meminfo(5 * GB))
        rec = self.tmp / "rec.json"
        g = MemoryGuard(p.pid, 6144, 0.02, record_path=rec, trace_path=self.tmp / "trace.jsonl", meminfo_fn=mi)
        g.start()
        self.assertEqual(p.wait(timeout=10), -9)
        g.join(timeout=20)
        self.assertTrue(g.fired.is_set())
        self.assertIn("MemAvailable 5120 MB < 6144 MB", g.tripped["reason"])
        self.assertIn("process group", g.tripped["action"])
        self.assertTrue(g.tripped["process_exited"])
        self.assertEqual(group_members(p.pid), [])  # background child too
        saved = json.loads(rec.read_text())
        self.assertEqual(saved["at_trip"]["available_mb"], 5120)
        self.assertEqual(len(saved["before"]), 3)
        self.assertEqual(len((self.tmp / "trace.jsonl").read_text().splitlines()), 3)

    def test_swap_growth_alone_does_not_trip(self):
        # model loading moved ~1 GB to swap while 14 GB were available (2026-10-08)
        p = self.spawn(["sleep", "0.5"])
        mi = Script(fake_meminfo(14 * GB, 0), fake_meminfo(14 * GB, 300 * 1024), fake_meminfo(14 * GB, 4000 * 1024))
        g = MemoryGuard(p.pid, 6144, 0.02, meminfo_fn=mi)
        g.start()
        self.assertEqual(p.wait(timeout=10), 0)
        g.join(timeout=5)
        self.assertIsNone(g.tripped)
        self.assertEqual(g.max_swap_growth_seen, 4000)

    def test_swap_already_in_use_is_baseline(self):
        p = self.spawn(["sleep", "0.5"])
        mi = Script(fake_meminfo(12 * GB, 3000 * 1024))  # 3 GB swapped before the guard started
        g = MemoryGuard(p.pid, 6144, 0.02, meminfo_fn=mi)
        g.start()
        p.wait(timeout=10)
        g.join(timeout=5)
        self.assertIsNone(g.tripped)
        self.assertEqual(g.max_swap_growth_seen, 0)

    def test_no_trip_ends_with_process(self):
        p = self.spawn(["sleep", "0.5"])
        g = MemoryGuard(p.pid, 6144, 0.02, meminfo_fn=Script(fake_meminfo(12 * GB), fake_meminfo(7 * GB)))
        g.start()
        self.assertEqual(p.wait(timeout=10), 0)
        g.join(timeout=5)
        self.assertFalse(g.is_alive())
        self.assertIsNone(g.tripped)
        self.assertEqual(g.min_available_seen, 7168)
        self.assertGreater(g.samples, 2)

    def test_stop_does_not_kill(self):
        p = self.spawn(["sleep", "60"])
        g = MemoryGuard(p.pid, 6144, 0.02, meminfo_fn=Script(fake_meminfo(12 * GB)))
        g.start()
        time.sleep(0.2)
        g.stop()
        self.assertFalse(g.is_alive())
        self.assertIsNone(p.poll())
        self.assertIsNone(g.tripped)

    def test_never_kills_own_process_group(self):
        p = self.spawn(["sleep", "60"], new_session=False)
        self.assertEqual(os.getpgid(p.pid), os.getpgrp())
        g = MemoryGuard(p.pid, 6144, 0.02, meminfo_fn=Script(fake_meminfo(1 * GB)))
        g.start()
        self.assertEqual(p.wait(timeout=10), -9)
        g.join(timeout=20)
        self.assertEqual(g.tripped["action"], f"SIGKILL pid {p.pid}")

    def test_cli_with_real_meminfo(self):
        p = self.spawn(["sleep", "60"])
        floor = read_meminfo()["MemAvailable"] // 1024 + 10 ** 6  # unreachable: trips on the first sample
        rec = self.tmp / "cli.json"
        r = subprocess.run([sys.executable, "-m", "hdf.memguard", "--pid", str(p.pid), "--min-available-mb",
                            str(floor), "--interval", "0.05", "--record", str(rec)],
                           capture_output=True, text=True, timeout=60, cwd=Path(__file__).resolve().parents[2])
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("TRIPPED", r.stdout)
        self.assertEqual(p.wait(timeout=10), -9)
        self.assertTrue(json.loads(rec.read_text())["process_exited"])
        self.assertFalse(_alive(p.pid))


FAKE_SERVER = textwrap.dedent("""
    import json, sys, time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path
    a = sys.argv
    port = int(a[a.index("--port") + 1])
    marks = Path(sys.argv[0]).parent
    with open(marks / "starts", "a") as f:
        f.write("1\\n")
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def _json(self, obj):
            raw = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def do_GET(self):
            caps = not (marks / "no_caps").exists()
            self._json({"status": "ok", "model": MODEL, "raw_prompt": True, "keep_special_tokens": True,
                        "structured_output": caps, "model_sampling": caps, "stop_on_repetition": caps})
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            with open(marks / "requests", "a") as f:
                f.write(f"{len(body['prompt'])}\\n")
            (marks / "last_body.json").write_text(json.dumps(body))
            (marks / "request_started").touch()
            if (marks / "fail_once").exists():
                (marks / "fail_once").unlink()
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if (marks / "slow").exists():
                time.sleep(60)  # a long generation; the guard kills it
            self._json({"choices": [{"text": "{}", "finish_reason": "stop"}], "usage": {"completion_tokens": 1}})
    MODEL = "fake-triage"
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
""")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerGuardTest(unittest.TestCase):
    fresh_server_per_request = False

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "fake_server.py").write_text(FAKE_SERVER)
        (self.tmp / "slow").touch()
        models = {"triage": {"name": "fake-triage", "path": str(self.tmp),
                             "fresh_server_per_request": self.fresh_server_per_request},
                  "reasoner": {"name": "fake-reasoner", "path": str(self.tmp)}}
        cfg = make_config(self.tmp, models=models, server={"script": str(self.tmp / "fake_server.py"), "python": sys.executable,
                                            "port": free_port(), "startup_timeout_s": 30, "retries": 3,
                                            "guard_poll_interval_s": 0.05})
        self.run_dir = self.tmp / "run"
        self.server = ServerManager(cfg, self.run_dir)
        self.client = LLMClient(cfg, self.server, self.run_dir / "audit")
        self.model = cfg.model("triage")
        self.client.formatters[self.model.role] = FakeFormatter(self.model)

    def tearDown(self):
        self.server.stop()

    def meminfo_low_once_request_runs(self):
        marker = self.tmp / "request_started"
        return fake_meminfo(5 * GB if marker.exists() else 12 * GB)

    def test_guard_kill_stops_engine_without_restart(self):
        self.server.meminfo_fn = self.meminfo_low_once_request_runs
        t0 = time.time()
        with self.assertRaises(MemoryGuardError) as cm:
            self.client.complete(self.model, "sys", "user", "t1")
        self.assertLess(time.time() - t0, 30)  # did not wait for the 60 s generation or retry
        self.assertIn("MemAvailable 5120 MB < 6144 MB", str(cm.exception))
        self.assertEqual((self.tmp / "starts").read_text().count("1"), 1)  # no restart
        rec = json.loads((self.run_dir / "logs" / "memory_guard.json").read_text())
        self.assertTrue(rec["process_exited"])
        self.assertEqual(rec["label"], "fake-triage")
        self.assertTrue((self.run_dir / "logs" / "memory_trace_triage.jsonl").exists())
        audits = [json.loads(p.read_text()) for p in sorted((self.run_dir / "audit").glob("*.json"))]
        self.assertEqual(len(audits), 1)
        self.assertTrue(audits[0]["error"])
        # later requests are refused without starting a server
        with self.assertRaises(MemoryGuardError):
            self.client.complete(self.model, "sys", "user", "t2")
        self.assertEqual((self.tmp / "starts").read_text().count("1"), 1)

    def test_refuses_to_start_below_floor(self):
        self.server.meminfo_fn = lambda: fake_meminfo(5 * GB)
        with self.assertRaises(MemoryGuardError) as cm:
            self.client.complete(self.model, "sys", "user", "t1")
        self.assertIn("not starting", str(cm.exception))
        self.assertFalse((self.tmp / "starts").exists())

    def test_normal_stop_leaves_no_trip(self):
        self.server.meminfo_fn = lambda: fake_meminfo(12 * GB)
        self.server.ensure(self.model)
        guard = self.server.guard
        self.assertTrue(guard.is_alive())
        self.server.stop()
        self.assertFalse(guard.is_alive())
        self.assertIsNone(self.server.guard_trip)
        self.assertFalse((self.run_dir / "logs" / "memory_guard.json").exists())



class FreshServerPerRequestTest(ServerGuardTest):
    """Every request after the first one on a server process gets a fresh server first,
    whatever its length; retries included (2026-10-08: a shorter prompt also took > 6 GB)."""
    fresh_server_per_request = True

    def setUp(self):
        super().setUp()
        (self.tmp / "slow").unlink()
        self.server.meminfo_fn = lambda: fake_meminfo(12 * GB)

    def starts_after(self, lengths):
        out = []
        for n in lengths:
            self.client.complete(self.model, "s", "u" * n, f"t{n}")
            out.append((self.tmp / "starts").read_text().count("1"))
        return out

    def test_restarts_before_every_later_request(self):
        # 300 first; 300 equal; 100 shorter; 600 longer
        self.assertEqual(self.starts_after([300, 300, 100, 600]), [1, 2, 3, 4])
        self.assertEqual(len((self.tmp / "requests").read_text().split()), 4)

    def test_retry_gets_a_fresh_server(self):
        (self.tmp / "fail_once").touch()  # first attempt: HTTP 500, server stays up
        self.client.complete(self.model, "s", "u" * 300, "t")
        self.assertEqual(len((self.tmp / "requests").read_text().split()), 2)
        self.assertEqual((self.tmp / "starts").read_text().count("1"), 2)

    def test_off_means_no_restart(self):
        self.model = type(self.model)(**{**self.model.__dict__, "fresh_server_per_request": False})
        self.client.formatters[self.model.role] = FakeFormatter(self.model)
        self.assertEqual(self.starts_after([100, 300, 600]), [1, 1, 1])

    def test_old_setting_is_refused(self):
        models = {"triage": {"name": "t", "path": str(self.tmp), "restart_on_longer_input": True},
                  "reasoner": {"name": "r", "path": str(self.tmp)}}
        with self.assertRaises(ConfigError) as cm:
            make_config(self.tmp, models=models).model("triage")
        self.assertIn("fresh_server_per_request", str(cm.exception))

    # the guard tests of the parent class do not apply here
    test_guard_kill_stops_engine_without_restart = None
    test_refuses_to_start_below_floor = None
    test_normal_stop_leaves_no_trip = None


if __name__ == "__main__":
    unittest.main()
