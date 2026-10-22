"""Command line entry point.

  run     ingest evidence, triage, investigate, report, verify (resumable)
  ingest  build the evidence store only
  verify  re-run the independent verification of an existing run
"""
from __future__ import annotations

import argparse
import fcntl
import json
import signal
import sys
from datetime import datetime
from pathlib import Path

from .attack import Attack
from .config import ConfigError, load_config
from .grounding import Grounder
from .ingest import Ingestor
from .investigate import Investigation
from .llm import LLMClient, LLMError, MemoryGuardError, ServerManager
from .report import Reporter
from .store import EvidenceStore
from .triage import Triage
from .util import atomic_write_json, log, read_json, setup_logging
from .verify import verify_run


def _signal_to_exit(signum, _frame):
    raise SystemExit(128 + signum)


def _run_dir(cfg, args) -> Path:
    if args.out:
        return Path(args.out).expanduser().resolve()
    name = args.name or Path(args.evidence[0]).name
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(cfg.get("paths", "work_dir")).expanduser().resolve() / f"{stamp}_{name}"


def _overrides(args) -> dict:
    o: dict = {}
    if getattr(args, "coverage", None):
        o.setdefault("coverage", {})["mode"] = args.coverage
    if getattr(args, "budget_tokens", None):
        o.setdefault("coverage", {})["llm_token_budget"] = args.budget_tokens
    if getattr(args, "allow_partial", False):
        o.setdefault("triage", {})["allow_partial"] = True
    if getattr(args, "no_narrative", False):
        o.setdefault("report", {})["narrative"] = False
    if getattr(args, "no_manage_server", False):
        o.setdefault("server", {})["manage"] = False
    return o


def _ingest(cfg, evidence: list[str], run_dir: Path) -> EvidenceStore:
    db = run_dir / "evidence.db"
    store = EvidenceStore(db) if db.exists() else None
    inputs = sorted(str(Path(e).expanduser().resolve()) for e in evidence)
    if store is not None and store.get_meta("ingest_done"):
        if store.get_meta("inputs") != inputs:
            raise SystemExit(f"{run_dir} was built from different evidence {store.get_meta('inputs')}; "
                             f"use a new --out directory")
        log.info("[ingest] reusing evidence store %s", db)
        return store
    if store is not None:
        store.close()
        db.unlink()
        for suffix in ("-wal", "-shm"):
            Path(str(db) + suffix).unlink(missing_ok=True)
    for e in inputs:
        if not Path(e).exists():
            raise SystemExit(f"evidence path not found: {e}")
    store = EvidenceStore(db, create=True)
    store.set_meta("inputs", inputs)
    summary = Ingestor(cfg, store, run_dir).ingest([Path(e) for e in inputs])
    store.set_meta("ingest_done", True)
    log.info("[ingest] %d events, %d patterns, %d hosts, %s .. %s", summary["events"], summary["patterns"],
             summary["hosts"], summary["first_ts"], summary["last_ts"])
    return store


def cmd_run(args) -> int:
    cfg = load_config(args.config, _overrides(args))
    cfg.validate_for_run(need_server=True)
    run_dir = _run_dir(cfg, args)
    run_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(run_dir / "logs" / "run.log", args.verbose)
    lock = open(run_dir / ".lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.error("another hdf process is using %s", run_dir)
        return 2
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _signal_to_exit)
    atomic_write_json(run_dir / "config.used.json", cfg.data)
    log.info("run directory: %s", run_dir)
    attack = Attack.load(cfg.get("paths", "attack_stix"), cfg.get("paths", "attack_stix_url"))
    grounder = Grounder(attack)
    store = _ingest(cfg, args.evidence, run_dir)
    server = ServerManager(cfg, run_dir)
    client = LLMClient(cfg, server, run_dir / "audit" / "llm")
    triage_m, reason_m = cfg.model("triage"), cfg.model("reasoner")
    try:
        coverage = Triage(cfg, store, client, triage_m, grounder, attack, run_dir).run()
        findings = read_json(run_dir / "findings.json", [])
        state = Investigation(cfg, store, client, reason_m, grounder, attack, run_dir).run(findings)
        Reporter(cfg, store, client, reason_m, grounder, attack, run_dir).build(coverage, state, findings)
    except MemoryGuardError as e:
        log.error("run stopped: %s", e)
        log.error("nothing after this point was analysed; see %s before re-running", run_dir / "logs")
        return 5
    except (LLMError, RuntimeError) as e:
        log.error("run stopped: %s", e)
        log.error("fix the cause and re-run the same command with --out %s to resume", run_dir)
        return 1
    finally:
        server.stop()
        store.close()
    result = verify_run(run_dir, attack)
    log.info("verification: %s (%d violations)", "PASS" if result["ok"] else "FAIL", len(result["violations"]))
    for v in result["violations"][:20]:
        log.error("  %s", v)
    rep = read_json(run_dir / "report.json", {})
    if rep.get("status") == "incomplete":
        log.error("run INCOMPLETE: %s", "; ".join(rep.get("problems", []))[:1000])
    log.info("report: %s", run_dir / "report.md")
    if not result["ok"]:
        return 3
    return 4 if rep.get("status") == "incomplete" else 0


def cmd_ingest(args) -> int:
    cfg = load_config(args.config)
    run_dir = _run_dir(cfg, args)
    run_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(run_dir / "logs" / "ingest.log", args.verbose)
    store = _ingest(cfg, args.evidence, run_dir)
    print(json.dumps(store.stats(), indent=1))
    store.close()
    return 0


def cmd_verify(args) -> int:
    cfg = load_config(args.config)
    setup_logging(None, False)
    attack = Attack.load(cfg.get("paths", "attack_stix"), cfg.get("paths", "attack_stix_url"))
    res = verify_run(Path(args.run_dir), attack)
    print(json.dumps(res, indent=1, ensure_ascii=False))
    return 0 if res["ok"] else 3


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hdf", description="Local LLM hypothesis drill-down forensic engine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="full investigation")
    r.add_argument("evidence", nargs="+", help="evidence files or directories")
    r.add_argument("--config", help="machine configuration (TOML)")
    r.add_argument("--out", help="run directory (re-use it to resume)")
    r.add_argument("--name", help="name used for a new run directory")
    r.add_argument("--coverage", choices=["full", "budget"])
    r.add_argument("--budget-tokens", type=int, help="phase-1 token budget for --coverage budget")
    r.add_argument("--allow-partial", action="store_true", help="continue if some chunks fail")
    r.add_argument("--no-narrative", action="store_true")
    r.add_argument("--no-manage-server", action="store_true", help="use an already running server")
    r.add_argument("-v", "--verbose", action="store_true")
    r.set_defaults(fn=cmd_run)
    i = sub.add_parser("ingest", help="build the evidence store only")
    i.add_argument("evidence", nargs="+")
    i.add_argument("--config")
    i.add_argument("--out")
    i.add_argument("--name")
    i.add_argument("-v", "--verbose", action="store_true")
    i.set_defaults(fn=cmd_ingest)
    v = sub.add_parser("verify", help="re-verify a finished run")
    v.add_argument("run_dir")
    v.add_argument("--config")
    v.set_defaults(fn=cmd_verify)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except ConfigError as e:
        print(str(e), file=sys.stderr)
        return 2
