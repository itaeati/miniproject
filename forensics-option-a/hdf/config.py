"""Configuration loading: package defaults <- machine config file <- CLI overrides."""
from __future__ import annotations

import copy
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = PACKAGE_DIR / "default_config.toml"

# Settings that hold filesystem paths; relative values are resolved against the
# directory of the config file that set them.
_PATH_KEYS = {
    ("paths", "work_dir"), ("paths", "attack_stix"), ("server", "script"),
    ("models", "triage", "path"), ("models", "reasoner", "path"),
}


class ConfigError(ValueError):
    pass


def _merge(base: dict, override: dict, base_dir: Path, prefix: tuple = ()) -> None:
    for key, value in override.items():
        path = prefix + (key,)
        if isinstance(value, dict):
            if not isinstance(base.get(key), dict):
                base[key] = {}
            _merge(base[key], value, base_dir, path)
            continue
        if path in _PATH_KEYS and isinstance(value, str) and value:
            value = str((base_dir / os.path.expanduser(value)).resolve()) if not os.path.isabs(
                os.path.expanduser(value)) else os.path.expanduser(value)
        base[key] = value


@dataclass
class ModelConfig:
    role: str
    name: str
    path: str
    enable_thinking: bool
    max_input_tokens: int
    max_output_tokens: int
    fresh_server_per_request: bool = False
    sampling: str = "greedy"          # "greedy" | "model" (the model's generation_config.json)
    structured_output: bool = True    # server enforces the answer's JSON schema
    structured_after: str = ""        # with thinking on: the schema applies after this marker


class Config:
    def __init__(self, data: dict):
        self.data = data

    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self.data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def section(self, name: str) -> dict:
        return dict(self.data.get(name, {}))

    def model(self, role: str) -> ModelConfig:
        m = self.get("models", role, default={}) or {}
        budget = self.section("budget")
        mi = int(m.get("max_input_tokens") or 0) or int(budget["max_input_tokens"])
        mo = int(m.get("max_output_tokens") or 0) or int(budget["max_output_tokens"])
        if "restart_on_longer_input" in m:
            raise ConfigError(f"models.{role}.restart_on_longer_input was replaced by "
                              f"fresh_server_per_request (a shorter prompt also took > 6 GB, 2026-10-08)")
        if mi + mo > int(budget["context_tokens"]):
            raise ConfigError(
                f"models.{role}: max_input_tokens ({mi}) + max_output_tokens ({mo}) exceeds "
                f"budget.context_tokens ({budget['context_tokens']})")
        return ModelConfig(role=role, name=str(m.get("name") or ""), path=str(m.get("path") or ""),
                           enable_thinking=bool(m.get("enable_thinking", True)),
                           max_input_tokens=mi, max_output_tokens=mo,
                           fresh_server_per_request=bool(m.get("fresh_server_per_request", False)),
                           sampling=str(m.get("sampling") or "greedy"),
                           structured_output=bool(m.get("structured_output", True)),
                           structured_after=str(m.get("structured_after") or ""))

    def validate_for_run(self, need_server: bool) -> None:
        problems = []
        for role in ("triage", "reasoner"):
            mc = self.model(role)
            if not mc.name:
                problems.append(f"models.{role}.name is empty")
            if not mc.path or not Path(mc.path).is_dir():
                problems.append(f"models.{role}.path does not exist: {mc.path!r} (needed for the tokenizer)")
            if mc.sampling not in ("greedy", "model"):
                problems.append(f"models.{role}.sampling must be 'greedy' or 'model', got {mc.sampling!r}")
        if need_server and self.get("server", "manage"):
            script = self.get("server", "script")
            if not script or not Path(script).is_file():
                problems.append(f"server.script does not exist: {script!r}")
        cov = self.get("coverage", "mode")
        if cov not in ("full", "budget"):
            problems.append(f"coverage.mode must be 'full' or 'budget', got {cov!r}")
        if cov == "budget" and int(self.get("coverage", "llm_token_budget") or 0) <= 0:
            problems.append("coverage.mode = 'budget' requires coverage.llm_token_budget > 0")
        if problems:
            raise ConfigError("Invalid configuration:\n  - " + "\n  - ".join(problems))


def load_config(path: str | None = None, overrides: dict | None = None) -> Config:
    with open(DEFAULT_CONFIG, "rb") as f:
        data = tomllib.load(f)
    # Defaults resolve relative paths against the directory that contains the package.
    resolved: dict = {}
    _merge(resolved, data, PACKAGE_DIR.parent)
    if path:
        p = Path(os.path.expanduser(path)).resolve()
        if not p.is_file():
            raise ConfigError(f"config file not found: {p}")
        with open(p, "rb") as f:
            _merge(resolved, tomllib.load(f), p.parent)
    if overrides:
        _merge(resolved, copy.deepcopy(overrides), Path.cwd())
    return Config(resolved)
