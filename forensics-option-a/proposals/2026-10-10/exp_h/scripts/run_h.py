"""Experiment H runner = experiment F runner (exp_f/scripts/run_f.py, same prompts, binding, re-ask,
pass 2, limits) restricted to the lines listed in a sample file (--judge). Only the judged lines
are grouped into requests; context lines (how the acting process and its parent started) are
still looked up in the whole dataset, as in experiment F. Labels are never read here.

usage: run_h.py CONFIG BASE_EVIDENCE_DB RUN_DIR --judge SAMPLE_JSON [--dry-run]
writes RUN_DIR/pass1.json (verdicts after pass 1) and RUN_DIR/verdicts.json (final: "attack" if
either pass said attack). exit: 0 ok, 4 some lines without a verdict, 1 LLM error, 5 memory guard
"""
import argparse
import json
import shutil
import signal
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, "/home/ubuntu/forensics-option-a")
sys.path.insert(0, "/home/ubuntu/forensics-option-a/proposals/2026-10-09/exp_f/scripts")
from hdf.config import load_config  # noqa: E402
from hdf.llm import (ContextBudgetError, LLMClient, LLMError, MemoryGuardError,  # noqa: E402
                     ServerManager, extract_json)
from hdf.store import EvidenceStore  # noqa: E402
from hdf.util import atomic_write_json, log, read_json, setup_logging  # noqa: E402
import f_lib as F  # noqa: E402

V = F.V
REASK_ROUNDS = 2
MAX_LINES = 20
EVIDENCE_TOKENS = 4000          # pass 1, same as experiments D and E
RECHECK_LINE_TOKENS = 3000      # pass 2: lines to judge ...
RECHECK_ATTACK_TOKENS = 2000    # ... plus reference attack lines (prompt stays under ~7K)
RECHECK_ATTACK_LINES = 15


def _signal_to_exit(signum, _frame):
    raise SystemExit(128 + signum)


class Asker:
    def __init__(self, client, model, byid, src_info, res_dir):
        self.client, self.model, self.byid, self.src_info, self.res_dir = client, model, byid, src_info, res_dir

    def once(self, req, tag, attack_ids=None):
        """One request; returns {event_id: verdict} for lines whose quote binds them."""
        src = self.src_info[self.byid[req.events[0]].src]
        user = F.render(req, self.byid, *src, attack_ids=attack_ids)
        h = V.request_hash(self.model.name, f"exp-f|{tag}|{user}")
        cached = read_json(self.res_dir / f"{h}.json")
        if cached and cached.get("status") == "ok":
            return {int(k): v for k, v in cached["verdicts"].items()}
        bodies = [F.body(self.byid[i]) for i in req.events]
        t0 = time.time()
        res = self.client.complete(self.model, F.SYSTEM, user, tag, schema=F.schema(len(req.events)))
        obj = extract_json(res.text, "verdicts", item_key="line")
        got, rejected = F.parse_verdicts(obj, bodies)
        out = {req.events[k - 1]: v for k, v in got.items()}
        for r in rejected:
            r["event"] = req.events[r["line"] - 1]
        atomic_write_json(self.res_dir / f"{h}.json", {
            "status": "ok", "tag": tag, "key": req.key, "events": req.events, "context": req.context,
            "attack_refs": attack_ids, "verdicts": {str(k): v for k, v in out.items()}, "rejected": rejected,
            "missing": [i for i in req.events if i not in out], "salvaged": bool(obj and obj.get("_salvaged")),
            "hit_limit": res.hit_limit, "finish": res.finish, "prompt_tokens": res.prompt_tokens,
            "output_tokens": res.output_tokens, "seconds": round(time.time() - t0, 1)})
        return out

    def full(self, req, tag, attack_ids=None):
        """Ask, then re-ask only the lines without a bound verdict (up to REASK_ROUNDS)."""
        out = {k: {**v, "round": 0} for k, v in self.once(req, f"{tag}_a0", attack_ids).items()}
        missing = [i for i in req.events if i not in out]
        for rnd in range(1, REASK_ROUNDS + 1):
            if not missing:
                break
            # round 1: the missing lines together; last round: each line alone (nothing to confuse it with)
            groups = [missing] if rnd < REASK_ROUNDS else [[i] for i in missing]
            log.warning("[exp-f] %s: %d line(s) without a bound verdict -> asking again (round %d, %d request(s))",
                        tag, len(missing), rnd, len(groups))
            for g_n, ids in enumerate(groups):
                sub = V.Request(req.key, req.part, req.title, ids, req.context)
                suffix = f"_a{rnd}" if len(groups) == 1 else f"_a{rnd}_{g_n:02d}"
                got = self.once(sub, f"{tag}{suffix}", attack_ids)
                out.update({k: {**v, "round": rnd} for k, v in got.items()})
            missing = [i for i in missing if i not in out]
        for i in missing:
            out[i] = {"verdict": "no_verdict", "reason": "", "quote": "", "round": REASK_ROUNDS}
        return out


def recheck_requests(reqs, verdicts, byid, count):
    """Pass-2 requests: per process group with >= 1 attack line, its normal lines (time order)
    with the closest attack lines of the same group as reference."""
    groups = defaultdict(list)
    first_req = {}
    for r in reqs:
        groups[r.key] += r.events
        first_req.setdefault(r.key, r)
    out = []
    for key, ids in groups.items():
        att = [i for i in ids if verdicts[i]["verdict"] == "attack"]
        nor = [i for i in ids if verdicts[i]["verdict"] == "normal"]
        if not att or not nor:
            continue
        r0 = first_req[key]
        for part, chunk in enumerate(F.split(nor, byid, count, MAX_LINES, RECHECK_LINE_TOKENS), 1):
            refs = F.pick_attack_refs(att, chunk, byid, count, RECHECK_ATTACK_TOKENS, RECHECK_ATTACK_LINES)
            out.append((V.Request(key, part, r0.title, chunk, r0.context), refs))
    return out


def build_requests_subset(full, sub, count):
    """verdict_lib.build_requests over the judged lines only, with context looked up in `full`."""
    orig_c, orig_p = V.creation_records, V.parent_of
    V.creation_records = lambda _evs, host, pid: orig_c(full, host, pid)
    V.parent_of = lambda _evs, host, pid: orig_p(full, host, pid)
    try:
        return V.build_requests(sub, MAX_LINES, count, EVIDENCE_TOKENS)
    finally:
        V.creation_records, V.parent_of = orig_c, orig_p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("config"), ap.add_argument("base_db"), ap.add_argument("run_dir")
    ap.add_argument("--judge", required=True, help="sample JSON with the event ids to judge")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    cfg = load_config(a.config)
    cfg.validate_for_run(need_server=not a.dry_run)
    model = cfg.model("triage")
    run_dir = Path(a.run_dir).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(run_dir / "logs" / ("dry_run.log" if a.dry_run else "run.log"), False)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _signal_to_exit)
    db = run_dir / "evidence.db"
    if not db.exists():
        shutil.copy2(a.base_db, db)
    store = EvidenceStore(db)
    evs = V.load_events(store)
    byid = {e.id: e for e in evs}
    src_info = {s: V.source_constants(store, s) for s in {e.src for e in evs}}
    server = ServerManager(cfg, run_dir)
    client = LLMClient(cfg, server, run_dir / "audit" / "llm")
    fmt = client.formatter(model)
    judged = set(json.load(open(a.judge))["judged"])
    reqs = build_requests_subset(evs, [e for e in evs if e.id in judged], fmt.count)
    res_dir = run_dir / "results"
    res_dir.mkdir(exist_ok=True)
    log.info("experiment H: %d events, %d judged, %d pass-1 requests, model %s", len(evs), len(judged), len(reqs), model.name)
    if a.dry_run:
        rows = []
        for n, r in enumerate(reqs, 1):
            user = F.render(r, byid, *src_info[byid[r.events[0]].src])
            rows.append({"n": n, "key": r.key, "lines": len(r.events), "prompt_tokens": fmt.count(fmt.format(F.SYSTEM, user))})
            if n in (1, 20):
                (run_dir / f"prompt_example_{n}.txt").write_text(fmt.format(F.SYSTEM, user))
        # pass-2 sizes under the worst case: every line of every group judged "attack" except one
        # normal line per group would give tiny requests; the largest case is every line normal but one.
        worst = {e.id: {"verdict": "normal"} for e in evs if e.id in judged}
        for r in reqs:
            if r.part == 1:
                worst[r.events[0]] = {"verdict": "attack"}
        rc = recheck_requests(reqs, worst, byid, fmt.count)
        rows2 = []
        for n, (r, refs) in enumerate(rc, 1):
            user = F.render(r, byid, *src_info[byid[r.events[0]].src], attack_ids=refs)
            rows2.append({"n": n, "key": r.key, "lines": len(r.events), "refs": len(refs),
                          "prompt_tokens": fmt.count(fmt.format(F.SYSTEM, user))})
            if n == 1:
                (run_dir / "prompt_example_recheck.txt").write_text(fmt.format(F.SYSTEM, user))
        atomic_write_json(run_dir / "dry_run.json", {"model": model.name, "max_input_tokens": model.max_input_tokens,
                                                     "pass1": rows, "pass2_worst": rows2})
        log.info("dry run: pass 1 max prompt %d tokens; pass 2 (worst case) %d requests, max %d tokens (limit %d)",
                 max(r["prompt_tokens"] for r in rows), len(rows2),
                 max((r["prompt_tokens"] for r in rows2), default=0), model.max_input_tokens)
        store.close()
        return 0
    asker = Asker(client, model, byid, src_info, res_dir)
    verdicts: dict[int, dict] = {}
    final: dict[int, dict] = {}
    try:
        for n, r in enumerate(reqs, 1):
            got = asker.full(r, f"f_{n:02d}")
            verdicts.update(got)
            c = {x: sum(got[i]["verdict"] == x for i in r.events) for x in ("attack", "normal", "no_verdict")}
            log.info("[exp-f] pass1 %d/%d %s part %d (%d lines): %s", n, len(reqs), r.key, r.part, len(r.events), c)
        atomic_write_json(run_dir / "pass1.json", {str(k): v for k, v in sorted(verdicts.items())})
        final = {k: {**v, "pass": 1} for k, v in verdicts.items()}
        rc = recheck_requests(reqs, verdicts, byid, fmt.count)
        log.info("[exp-f] pass 2: %d request(s) re-check %d normal line(s)", len(rc), sum(len(r.events) for r, _ in rc))
        for n, (r, refs) in enumerate(rc, 1):
            got = asker.full(r, f"r_{n:02d}", attack_ids=refs)
            for k, v in got.items():
                final[k]["recheck"] = v
                if v["verdict"] == "attack":
                    final[k] = {**v, "pass": 2, "pass1": verdicts[k]}
            c = {x: sum(got[i]["verdict"] == x for i in r.events) for x in ("attack", "normal", "no_verdict")}
            log.info("[exp-f] pass2 %d/%d %s part %d (%d lines, %d attack refs): %s", n, len(rc), r.key, r.part,
                     len(r.events), len(refs), c)
    except MemoryGuardError as e:
        log.error("run stopped by memory guard: %s", e)
        return 5
    except (LLMError, ContextBudgetError) as e:
        log.error("run stopped: %s", e)
        return 1
    finally:
        server.stop()
        atomic_write_json(run_dir / "verdicts.json", {str(k): v for k, v in sorted(final.items())})
        store.close()
    left = [k for k, v in final.items() if v["verdict"] == "no_verdict"]
    log.info("experiment H done: %d verdicts, %d lines without a verdict", len(final), len(left))
    return 4 if left else 0


if __name__ == "__main__":
    sys.exit(main())
