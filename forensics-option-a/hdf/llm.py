"""Model server lifecycle, prompt formatting with exact token counts, and the
HTTP client with retry / failure classification."""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .config import Config, ModelConfig
from .memguard import MemoryGuard, available_mb
from .util import atomic_write_json, log


class LLMError(RuntimeError):
    """The request could not be completed after retries."""


class ContextBudgetError(LLMError):
    """The prompt does not fit the budget or the backend ran out of memory for it."""


class MemoryGuardError(LLMError):
    """The memory guard killed the model server. Not retried: the same request would
    put the system under the same memory pressure again."""


# ---------------------------------------------------------------- formatting
class PromptFormatter:
    """Applies the model's own chat template locally so the exact prompt and its
    token count are known before the request is sent."""

    def __init__(self, model: ModelConfig):
        from transformers import AutoTokenizer  # local files only
        self.model = model
        self.tok = AutoTokenizer.from_pretrained(model.path, local_files_only=True)

    def format(self, system: str, user: str) -> str:
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        kwargs = {"tokenize": False, "add_generation_prompt": True}
        try:
            return self.tok.apply_chat_template(msgs, enable_thinking=self.model.enable_thinking, **kwargs)
        except TypeError:
            return self.tok.apply_chat_template(msgs, **kwargs)

    def count(self, text: str) -> int:
        return len(self.tok(text, add_special_tokens=False).input_ids)

    def count_many(self, texts: list[str]) -> list[int]:
        if not texts:
            return []
        enc = self.tok(texts, add_special_tokens=False)
        return [len(x) for x in enc.input_ids]

    def overhead(self, system: str, user_template_without_data: str) -> int:
        return self.count(self.format(system, user_template_without_data))


# ---------------------------------------------------------------- server
def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class ServerManager:
    """Starts, monitors and stops one model server process at a time."""

    def __init__(self, cfg: Config, run_dir: Path):
        s = cfg.section("server")
        self.manage = bool(s.get("manage", True))
        self.python = s.get("python", "python3")
        self.script = s.get("script", "")
        self.device = s.get("device", "GPU")
        self.host = s.get("host", "127.0.0.1")
        self.port = int(s.get("port", 8086))
        self.startup_timeout = int(s.get("startup_timeout_s", 900))
        self.cleanup_cmd = list(s.get("cleanup_command") or [])
        self.kill_port_owner = bool(s.get("kill_port_owner", False))
        self.need_repetition_stop = bool(int(s.get("repetition_window_chars", 0) or 0))
        self.guard_enabled = bool(s.get("memory_guard", True))
        self.guard_min_available_mb = int(s.get("guard_min_available_mb", 6144))
        self.guard_interval_s = float(s.get("guard_poll_interval_s", 0.05))
        self.guard: MemoryGuard | None = None
        self.guard_trip: dict | None = None
        self.meminfo_fn = None  # tests replace /proc/meminfo
        self.requests_sent = 0  # requests sent to the current server process
        self.run_dir = Path(run_dir)
        self.proc: subprocess.Popen | None = None
        self.model: ModelConfig | None = None
        self.pidfile = self.run_dir / "logs" / "server.pid"

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def health(self) -> dict | None:
        try:
            with urllib.request.urlopen(f"{self.base_url}/health", timeout=5) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception:
            return None

    def ensure(self, model: ModelConfig) -> None:
        """Make sure the given model is being served."""
        h = self.health()
        if h and h.get("model") == model.name and h.get("raw_prompt") and h.get("keep_special_tokens"):
            missing = self._missing_caps(h, model)
            if missing:
                raise LLMError(self._caps_message(model, missing))
            if self.proc is None and self.manage:
                log.info("[server] reusing already running server for %s", model.name)
            self.model = model
            return
        if self.guard_trip:
            raise MemoryGuardError(self.guard_message())
        if not self.manage:
            raise LLMError(
                f"server.manage=false but {self.base_url} serves {h.get('model') if h else 'nothing'}"
                f"{'' if not h or h.get('raw_prompt') else ' without raw-prompt support'}; expected {model.name}")
        self.stop()
        if port_open(self.host, self.port):
            if not self.kill_port_owner:
                raise LLMError(f"port {self.port} is in use by another process; stop it or set "
                               f"server.kill_port_owner=true")
            subprocess.run(["fuser", "-k", "-TERM", f"{self.port}/tcp"], capture_output=True, check=False)
            time.sleep(3)
        self._start(model)

    def _start(self, model: ModelConfig) -> None:
        log_path = self.run_dir / "logs" / f"server_{model.role}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [self.python, self.script, "--model-path", model.path, "--device", self.device,
               "--host", self.host, "--port", str(self.port)]
        if self.guard_enabled:
            avail = (self.meminfo_fn()["MemAvailable"] // 1024) if self.meminfo_fn else available_mb()
            if avail < self.guard_min_available_mb:
                raise MemoryGuardError(f"not starting {model.name}: MemAvailable {avail} MB is already below the "
                                       f"memory guard floor of {self.guard_min_available_mb} MB")
        log.info("[server] starting %s", model.name)
        self.requests_sent = 0
        logf = open(log_path, "ab")
        self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
        logf.close()
        self.pidfile.write_text(str(self.proc.pid))
        if self.guard_enabled:
            kw = {"meminfo_fn": self.meminfo_fn} if self.meminfo_fn else {}
            self.guard = MemoryGuard(self.proc.pid, self.guard_min_available_mb, self.guard_interval_s,
                                     record_path=self.run_dir / "logs" / "memory_guard.json",
                                     trace_path=self.run_dir / "logs" / f"memory_trace_{model.role}.jsonl",
                                     label=model.name, **kw)
            self.guard.start()
        t0 = time.time()
        while time.time() - t0 < self.startup_timeout:
            if self.proc.poll() is not None:
                tail = log_path.read_text(errors="replace")[-2000:]
                self._end_guard()
                self.proc = None
                if self.guard_trip:
                    raise MemoryGuardError(self.guard_message())
                raise LLMError(f"model server exited during startup (see {log_path}):\n{tail}")
            h = self.health()
            if h and h.get("status") == "ok":
                if h.get("model") != model.name:
                    raise LLMError(f"server reports model {h.get('model')!r}, expected {model.name!r}")
                if not h.get("raw_prompt"):
                    raise LLMError("model server does not report raw_prompt support; it would re-apply the "
                                   "chat template to already formatted prompts. Update openvino_server.py.")
                if not h.get("keep_special_tokens"):
                    raise LLMError("model server cannot return special tokens; reasoning and answer could not "
                                   "be separated for models that mark them with special tokens. Update "
                                   "openvino_server.py.")
                missing = self._missing_caps(h, model)
                if missing:
                    self.stop()
                    raise LLMError(self._caps_message(model, missing))
                self.model = model
                log.info("[server] %s ready in %.0fs", model.name, time.time() - t0)
                return
            time.sleep(2)
        self.stop()
        raise LLMError(f"model server did not become healthy within {self.startup_timeout}s")

    def _missing_caps(self, h: dict, model: ModelConfig) -> list[str]:
        """Server features the configured decoding needs but /health does not report."""
        need = (("structured_output", model.structured_output), ("model_sampling", model.sampling == "model"),
                ("stop_on_repetition", self.need_repetition_stop))
        return [f for f, n in need if n and not h.get(f)]

    @staticmethod
    def _caps_message(model: ModelConfig, missing: list[str]) -> str:
        return (f"model server for {model.name} does not report {', '.join(missing)}; the configured decoding "
                f"would be silently ignored. Update openvino_server.py (model_sampling also needs the model's "
                f"generation_config.json).")

    def _end_guard(self) -> None:
        if self.guard is not None:
            self.guard.stop()
            if self.guard.tripped:
                self.guard_trip = self.guard.tripped
            self.guard = None

    def check_guard(self) -> None:
        """Raise if the memory guard has killed the server."""
        if self.guard is not None and self.guard.fired.is_set():
            self._end_guard()  # waits until the guard has written its record
        if self.guard_trip:
            raise MemoryGuardError(self.guard_message())

    def guard_message(self) -> str:
        t = self.guard_trip or {}
        return (f"memory guard killed the {t.get('label')} server: {t.get('reason')} ({t.get('action')}); "
                f"details in {self.run_dir / 'logs' / 'memory_guard.json'}")

    def alive(self) -> bool:
        if self.proc is not None and self.proc.poll() is not None:
            return False
        return self.health() is not None

    def restart(self) -> None:
        if self.model is None:
            raise LLMError("no model to restart")
        m = self.model
        log.warning("[server] restarting %s", m.name)
        self.stop()
        self._start(m)

    def stop(self) -> None:
        if self.proc is not None:
            try:
                pgid = os.getpgid(self.proc.pid)
                os.killpg(pgid, signal.SIGTERM)
                try:
                    self.proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(pgid, signal.SIGKILL)
                    self.proc.wait(timeout=10)
            except ProcessLookupError:
                pass
            except Exception as e:
                log.warning("[server] stop: %s", e)
            self._end_guard()  # only after the process is gone: memory is at risk until then
            log.info("[server] stopped %s", self.model.name if self.model else "server")
            self.proc = None
            try:
                self.pidfile.unlink()
            except OSError:
                pass
            if self.cleanup_cmd:
                subprocess.run(self.cleanup_cmd, capture_output=True, check=False, timeout=300)
            for _ in range(30):
                if not port_open(self.host, self.port):
                    break
                time.sleep(1)


# ---------------------------------------------------------------- client
@dataclass
class LLMResult:
    text: str          # answer with reasoning removed
    raw: str           # full generated text
    prompt_tokens: int
    output_tokens: int
    hit_limit: bool    # generation stopped at max_tokens, inside the reasoning, or in a loop
    finish: str = ""   # server finish_reason: stop | length | repetition


def strip_reasoning(raw: str, prompt_opened_think: bool = False) -> tuple[str, bool]:
    """Remove reasoning blocks. Returns (answer, complete). complete=False if the
    reasoning never finished (output ended inside the reasoning block). When the
    chat template itself opens the reasoning block, the output must close it."""
    text = raw
    if "</think>" in text:
        text = text.rsplit("</think>", 1)[1]
    elif "<think>" in text or prompt_opened_think:
        return "", False
    if "<|channel>" in text or "<channel|>" in text:
        if "<channel|>" in text:
            text = text.rsplit("<channel|>", 1)[1]
        else:
            return "", False
    return text.strip(), True


def extract_json(text: str, required_key: str, item_key: str | None = None) -> dict | None:
    """Last JSON object in text that contains required_key. If there is none (the
    answer is malformed or was cut off) and item_key is given, the complete objects
    that contain item_key are returned as {required_key: [...], "_salvaged": True}."""
    dec = json.JSONDecoder()
    found, items = None, []
    i = text.find("{")
    while i != -1:
        try:
            obj, end = dec.raw_decode(text, i)
        except ValueError:
            i = text.find("{", i + 1)
            continue
        if isinstance(obj, dict) and required_key in obj:
            found = obj
        elif isinstance(obj, dict) and item_key and item_key in obj:
            items.append(obj)
        i = text.find("{", end)
    if found is None and items:
        return {required_key: items, "_salvaged": True}
    return found


class LLMClient:
    def __init__(self, cfg: Config, server: ServerManager, audit_dir: Path):
        s = cfg.section("server")
        self.server = server
        self.timeout = int(s.get("request_timeout_s", 3600))
        self.retries = int(s.get("retries", 3))
        self.rep_window = int(s.get("repetition_window_chars", 0) or 0)
        self.rep_ratio = float(s.get("repetition_max_ratio", 0.0) or 0.0)
        self.audit_dir = Path(audit_dir)
        self.formatters: dict[str, PromptFormatter] = {}
        self.calls = 0

    def formatter(self, model: ModelConfig) -> PromptFormatter:
        if model.role not in self.formatters:
            self.formatters[model.role] = PromptFormatter(model)
        return self.formatters[model.role]

    def complete(self, model: ModelConfig, system: str, user: str, tag: str, schema: dict | None = None) -> LLMResult:
        """`schema`: JSON schema of the answer, enforced by the server when the model's
        structured_output is on (after structured_after when thinking is on)."""
        fmt = self.formatter(model)
        prompt = fmt.format(system, user)
        n_in = fmt.count(prompt)
        if n_in > model.max_input_tokens:
            raise ContextBudgetError(f"prompt has {n_in} tokens > {model.max_input_tokens} ({tag})")
        self.server.check_guard()
        self.server.ensure(model)
        req_body = {"prompt": prompt, "max_tokens": model.max_output_tokens, "temperature": 0.0,
                    "model": model.name, "skip_special_tokens": False}
        if model.sampling == "model":
            req_body["sampling"] = "model"
        if schema is not None and model.structured_output:
            req_body["structured"] = {"json_schema": schema}
            if model.enable_thinking and model.structured_after:
                req_body["structured"]["after"] = model.structured_after
        if self.rep_window and self.rep_ratio:
            req_body["stop_on_repetition"] = {"window_chars": self.rep_window, "max_ratio": self.rep_ratio}
        body = json.dumps(req_body).encode("utf-8")
        last_err = None
        for attempt in range(1, self.retries + 1):
            sent = self.server.requests_sent
            if model.fresh_server_per_request and sent:
                if self.server.manage:
                    log.info("[server] %s: %d request(s) already sent to this process; restarting the "
                             "server before this %d-token prompt", model.name, sent, n_in)
                    self.server.restart()
                else:
                    log.warning("[server] %s: %d request(s) already sent to a server hdf does not manage; "
                                "it cannot be restarted and may exhaust memory", model.name, sent)
            elif sent and self.server.manage and self.server.guard_enabled:
                avail_now = (self.server.meminfo_fn()["MemAvailable"] // 1024) if self.server.meminfo_fn else available_mb()
                safe_floor = int(self.server.guard_min_available_mb) + 6144
                if avail_now < safe_floor:
                    log.info("[server] %s: available memory %d MB < safe prefill floor %d MB after %d request(s); "
                             "restarting server proactively", model.name, avail_now, safe_floor, sent)
                    self.server.restart()
            t0 = time.time()
            self.server.requests_sent += 1
            try:
                req = urllib.request.Request(f"{self.server.base_url}/v1/completions", data=body,
                                             headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    res = json.loads(r.read().decode("utf-8"))
                ch = (res.get("choices") or [{}])[0]
                raw = ch.get("text") if isinstance(ch.get("text"), str) else (ch.get("message") or {}).get("content", "")
                raw = raw or ""
                usage = res.get("usage") or {}
                n_out = int(usage.get("completion_tokens") or 0) or fmt.count(raw)
                answer, complete = strip_reasoning(raw, prompt.rstrip().endswith("<think>"))
                finish = str(ch.get("finish_reason") or "")
                hit = (finish in ("length", "repetition") or n_out >= model.max_output_tokens - 8
                       or not complete)
                self.calls += 1
                self._audit(tag, prompt, raw, n_in, n_out, time.time() - t0, None,
                            {"finish": finish, "sampling_used": res.get("sampling_used"),
                             "structured": "structured" in req_body})
                try:
                    req_clear = urllib.request.Request(f"{self.server.base_url}/v1/clear_cache")
                    with urllib.request.urlopen(req_clear, timeout=2):
                        pass
                except Exception:
                    pass
                return LLMResult(answer, raw, n_in, n_out, hit, finish)
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode("utf-8", "replace")
                except Exception:
                    pass
                last_err = f"HTTP {e.code}: {detail[:500]}"
                self._audit(tag, prompt, "", n_in, 0, time.time() - t0, last_err)
                self.server.check_guard()
                low = detail.lower()
                if any(k in low for k in ("memory", "exceeded max size", "allocat", "out of", "context")):
                    raise ContextBudgetError(f"backend could not process {n_in}-token prompt: {detail[:300]}")
            except (urllib.error.URLError, ConnectionError, TimeoutError, socket.timeout, OSError) as e:
                last_err = f"{type(e).__name__}: {e}"
                self._audit(tag, prompt, "", n_in, 0, time.time() - t0, last_err)
                self.server.check_guard()  # killed by the guard: no restart, no retry
                if not self.server.alive():
                    if self.server.manage:
                        self.server.restart()
                    else:
                        raise LLMError(f"model server is not reachable: {last_err}")
            except ValueError as e:
                last_err = f"bad response: {e}"
            log.warning("[llm] %s attempt %d/%d failed: %s", tag, attempt, self.retries, last_err)
            time.sleep(min(60, 5 * attempt))
        raise LLMError(f"{tag}: request failed after {self.retries} attempts: {last_err}")

    def _audit(self, tag, prompt, raw, n_in, n_out, secs, error, extra=None) -> None:
        try:
            atomic_write_json(self.audit_dir / f"{int(time.time() * 1000)}_{tag}.json",
                              {"tag": tag, "prompt_tokens": n_in, "output_tokens": n_out,
                               "seconds": round(secs, 1), "error": error, **(extra or {}),
                               "prompt": prompt, "output": raw})
        except OSError:
            pass
