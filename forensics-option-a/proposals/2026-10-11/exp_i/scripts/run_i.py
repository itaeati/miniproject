"""Experiment I runner (copy of exp_h/scripts/run_h.py).
Experiment H runner = experiment F runner (exp_f/scripts/run_f.py, same prompts, binding, re-ask,
pass 2, limits) restricted to the lines listed in a sample file (--judge). Only the judged lines
are grouped into requests; context lines (how the acting process and its parent started) are
still looked up in the whole dataset, as in experiment F. Labels are never read here.

usage: run_i.py CONFIG BASE_EVIDENCE_DB RUN_DIR --judge SAMPLE_JSON [--dry-run]
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
sys.path.insert(0, str(Path(__file__).resolve().parent))   # i_lib (python -I does not add it)
from hdf.config import load_config  # noqa: E402
from hdf.llm import (ContextBudgetError, LLMClient, LLMError, MemoryGuardError,  # noqa: E402
                     ServerManager, extract_json)
from hdf.store import EvidenceStore  # noqa: E402
from hdf.util import atomic_write_json, log, read_json, setup_logging  # noqa: E402
import f_lib as F  # noqa: E402
import i_lib as I  # noqa: E402

V = F.V
REASK_ROUNDS = 2
SYSTEM_PROMPT = F.SYSTEM        # common part: the same system text for every profile
PROMPT_MARGIN = 64              # tokens kept free below max_input_tokens (label width differences)
# Line/token limits and the context position come from the profile's [harness] table (i_lib.Harness;
# defaults = experiment H: 20 lines, 4000 evidence tokens, re-check 3000 + 2000 tokens / 15 attack lines).


def _signal_to_exit(signum, _frame):
    raise SystemExit(128 + signum)


class Asker:
    def __init__(self, client, model, byid, src_info, res_dir, hz, fingerprint):
        self.client, self.model, self.byid, self.src_info, self.res_dir = client, model, byid, src_info, res_dir
        self.hz, self.fingerprint = hz, fingerprint
        self.context_tokens = 0   # set by main (budget.context_tokens): output limit = context - prompt
        self.fit = None           # set by main: fit(req, attack_ids) shortens reference lines when needed

    def once(self, req, tag, attack_ids=None):
        """One request; returns ({event_id: verdict} for lines whose quote binds them,
        {event_id: [rejected answers]} for answers whose quote did not)."""
        src = self.src_info[self.byid[req.events[0]].src]
        if self.fit:
            self.fit(req, attack_ids)    # shorten reference lines only if the prompt would not fit
        user = I.render(req, self.byid, *src, attack_ids=attack_ids, context_position=self.hz.context_position)
        # the profile fingerprint keeps profiles of the same model (e.g. other sampling) from sharing answers
        h = V.request_hash(self.model.name, f"exp-i|{self.fingerprint}|{tag}|{user}")
        cached = read_json(self.res_dir / f"{h}.json")
        if cached and cached.get("status") == "ok":
            return {int(k): v for k, v in cached["verdicts"].items()}, _by_event(cached.get("rejected", []))
        bodies = [F.body(self.byid[i]) for i in req.events]
        t0 = time.time()
        res = I.complete(self.client, self.model, self.context_tokens, SYSTEM_PROMPT, user, tag,
                         schema=F.schema(len(req.events)))
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
            "max_output_tokens": max(self.model.max_output_tokens, self.context_tokens - res.prompt_tokens),
            "output_tokens": res.output_tokens, "seconds": round(time.time() - t0, 1)})
        return out, _by_event(rejected)

    def full(self, req, tag, attack_ids=None):
        """Ask, then re-ask only the lines without a bound verdict (up to REASK_ROUNDS); every answer,
        bound or not, is merged per line by i_lib.merge_answers (any attack -> attack)."""
        bound, rejected = {}, defaultdict(list)

        def take(got, rej, rnd):
            bound.update({k: {**v, "round": rnd} for k, v in got.items() if k not in bound})
            for k, rs in rej.items():
                rejected[k] += [{**r, "round": rnd} for r in rs]

        take(*self.once(req, f"{tag}_a0", attack_ids), 0)
        missing = [i for i in req.events if i not in bound]
        for rnd in range(1, REASK_ROUNDS + 1):
            if not missing:
                break
            # round 1: the missing lines together; last round: each line alone (nothing to confuse it with)
            groups = [missing] if rnd < REASK_ROUNDS else [[i] for i in missing]
            log.warning("[exp-f] %s: %d line(s) without a bound verdict -> asking again (round %d, %d request(s))",
                        tag, len(missing), rnd, len(groups))
            for g_n, ids in enumerate(groups):
                sub = I.sub_request(req, ids)
                suffix = f"_a{rnd}" if len(groups) == 1 else f"_a{rnd}_{g_n:02d}"
                take(*self.once(sub, f"{tag}{suffix}", attack_ids), rnd)
            missing = [i for i in missing if i not in bound]
        out = I.merge_answers(bound, dict(rejected), req.events)
        for i in missing:
            out[i].setdefault("round", REASK_ROUNDS)
        return out


def _by_event(rejected: list[dict]) -> dict[int, list[dict]]:
    out = defaultdict(list)
    for r in rejected:
        out[int(r["event"])].append({k: v for k, v in r.items() if k not in ("event", "line")})
    return dict(out)


def recheck_requests(reqs, verdicts, byid, count, hz, **limits):
    """Re-check requests for the current verdicts (first round: nothing seen yet); used by the dry run."""
    return I.recheck_targets(reqs, verdicts, byid, {}, count, hz, **limits)


def recursive_recheck(reqs, final, byid, count, hz, ask, **limits) -> list[dict]:
    """Rounds 1..hz.max_rounds: re-ask normal lines whose own or linked process has attack lines
    (i_lib.recheck_targets), with those attack lines as reference. A line flips to attack when the re-check
    says attack (final[k]["pass"] = 1 + round). Stops when a round flips nothing or nothing is left to ask.
    ask(req, tag, refs) -> {event_id: verdict dict}. Updates `final` in place; returns the per-round log."""
    seen: dict[int, frozenset[int]] = {}
    rounds = []
    for rnd in range(1, hz.max_rounds + 1):
        ev = I.evidence_sets(final, byid)
        targets = I.recheck_targets(reqs, final, byid, seen, count, hz, **limits)
        if not targets:
            break
        log.info("[exp-i] re-check round %d: %d request(s), %d normal line(s)", rnd, len(targets),
                 sum(len(r.events) for r, _ in targets))
        flipped = 0
        for n, (r, refs) in enumerate(targets, 1):
            got = ask(r, f"r{rnd}_{n:02d}", refs)
            for k, v in got.items():
                seen[k] = ev[k]
                final[k].setdefault("rechecks", []).append({**v, "round": rnd, "refs": refs})
                if v["verdict"] == "attack" and final[k]["verdict"] != "attack":
                    prev = {x: y for x, y in final[k].items() if x != "rechecks"}
                    final[k] = {**v, "pass": 1 + rnd, "pass1": prev.get("pass1", prev),
                                "rechecks": final[k]["rechecks"]}
                    flipped += 1
            c = {x: sum(got[i]["verdict"] == x for i in r.events) for x in ("attack", "normal", "no_verdict")}
            log.info("[exp-i] round %d %d/%d %s part %d (%d lines, %d attack refs): %s", rnd, n, len(targets), r.key,
                     r.part, len(r.events), len(refs), c)
        rounds.append({"round": rnd, "requests": len(targets), "lines": sum(len(r.events) for r, _ in targets),
                       "flipped": flipped})
        if not flipped:
            break
    return rounds


def build_requests_subset(full, sub, count, hz, overhead_of=None, max_input=0, context=0, byid_view=None):
    """One request per process group (verdict_lib.build_requests over the judged lines only, context looked up in
    `full`), each group split variably by i_lib.pack: whole lines, prompt <= max_input and prompt + expected answer
    <= context. overhead_of(request) = prompt tokens of the group's request without lines."""
    orig_c, orig_p = V.creation_records, V.parent_of
    V.creation_records = lambda _evs, host, pid: orig_c(full, host, pid)
    V.parent_of = lambda _evs, host, pid: orig_p(full, host, pid)
    try:
        groups = V.build_requests(sub, 10 ** 9)
    finally:
        V.creation_records, V.parent_of = orig_c, orig_p
    byid = {e.id: e for e in full}
    count_of = (lambda i: count(V.line_text(byid[i], 1)) + 1) if count else None
    out = []
    for g in groups:
        if overhead_of and count and g.context:
            # the group's context lines must leave room for its longest line and one answer; only they may be
            # shortened (marked), the lines to judge never are
            longest = max(count_of(i) for i in g.events)
            budget = min(max_input, context - hz.output_base - hz.output_per_line) - longest
            if overhead_of(g) > budget:
                I.shorten_to_fit(g, g.context, byid_view or byid, overhead_of, budget)
        oh = overhead_of(g) if (overhead_of and count) else 0
        for part, ids in enumerate(I.pack(g.events, count_of, oh, hz, max_input, context), 1):
            r = I.sub_request(g, ids)
            r.part = part
            out.append(r)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("config"), ap.add_argument("base_db"), ap.add_argument("run_dir")
    ap.add_argument("--judge", required=True, help="sample JSON with the event ids to judge")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    cfg = load_config(a.config)
    cfg.validate_for_run(need_server=not a.dry_run)
    model = cfg.model("triage")
    hz = I.harness_from(cfg)
    fingerprint = I.profile_fingerprint(cfg)
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
    restored = I.restore_views(store, evs)      # long values the ingest cut are shown whole again
    byid = {e.id: e for e in evs}
    src_info = {s: V.source_constants(store, s) for s in {e.src for e in evs}}
    server = ServerManager(cfg, run_dir)
    client = LLMClient(cfg, server, run_dir / "audit" / "llm")
    fmt = client.formatter(model)
    judged = set(json.load(open(a.judge))["judged"])
    context = int(cfg.get("budget", "context_tokens"))
    limits = {"max_input": model.max_input_tokens - PROMPT_MARGIN, "context": context}

    def overhead_of(req, recheck=False):
        """Prompt tokens of this group's request without any line to judge (template, scope, context lines)."""
        empty = I.sub_request(req, [])
        user = I.render(empty, byid, *src_info[byid[req.events[0]].src], attack_ids=[] if recheck else None,
                        context_position=hz.context_position)
        return fmt.count(fmt.format(SYSTEM_PROMPT, user))

    reqs = build_requests_subset(evs, [e for e in evs if e.id in judged], fmt.count, hz, overhead_of, **limits)

    def fit(req, attack_ids):
        """Before a request is sent: if prompt + expected answer would not fit, shorten its reference lines
        (attack references first, then context; lines to judge never). Returns the prompt tokens."""
        src = src_info[byid[req.events[0]].src]
        budget = min(limits["max_input"], context - hz.output_base - hz.output_per_line * len(req.events))
        tok = lambda r: fmt.count(fmt.format(SYSTEM_PROMPT, I.render(r, byid, *src, attack_ids=attack_ids,
                                                                      context_position=hz.context_position)))
        return I.shorten_to_fit(req, list(attack_ids or []) + list(req.context), byid, tok, budget)
    rc_limits = {**limits, "overhead_of": lambda r: overhead_of(r, recheck=True)}
    res_dir = run_dir / "results"
    res_dir.mkdir(exist_ok=True)
    log.info("experiment I: %d events, %d judged, %d pass-1 requests, model %s, profile %s (%s), harness %s; "
             "%d cut line(s) restored, %d not restorable", len(evs), len(judged), len(reqs), model.name,
             Path(a.config).stem, fingerprint, hz, restored["restored"], restored["failed"])
    atomic_write_json(run_dir / "profile.json", {"config": str(Path(a.config).resolve()), "fingerprint": fingerprint,
                                                 "model": model.name, "enable_thinking": model.enable_thinking,
                                                 "sampling": model.sampling, "structured_after": model.structured_after,
                                                 "max_output_tokens": model.max_output_tokens,
                                                 "harness": I.dataclasses.asdict(hz), "views_restored": restored})
    if a.dry_run:
        rows = []
        for n, r in enumerate(reqs, 1):
            fit(r, None)
            user = I.render(r, byid, *src_info[byid[r.events[0]].src], context_position=hz.context_position)
            rows.append({"n": n, "key": r.key, "lines": len(r.events), "prompt_tokens": fmt.count(fmt.format(SYSTEM_PROMPT, user))})
            if n in (1, 20):
                (run_dir / f"prompt_example_{n}.txt").write_text(fmt.format(SYSTEM_PROMPT, user))
        # pass-2 sizes under the worst case: every line of every group judged "attack" except one
        # normal line per group would give tiny requests; the largest case is every line normal but one.
        worst = {e.id: {"verdict": "normal"} for e in evs if e.id in judged}
        for r in reqs:
            if r.part == 1:
                worst[r.events[0]] = {"verdict": "attack"}
        rc = recheck_requests(reqs, worst, byid, fmt.count, hz, **rc_limits)
        rows2 = []
        for n, (r, refs) in enumerate(rc, 1):
            fit(r, refs)
            user = I.render(r, byid, *src_info[byid[r.events[0]].src], attack_ids=refs, context_position=hz.context_position)
            rows2.append({"n": n, "key": r.key, "lines": len(r.events), "refs": len(refs),
                          "prompt_tokens": fmt.count(fmt.format(SYSTEM_PROMPT, user))})
            if n == 1:
                (run_dir / "prompt_example_recheck.txt").write_text(fmt.format(SYSTEM_PROMPT, user))
        allr = reqs + [r for r, _ in rc]
        short = {i for r in allr for i in (getattr(r, "shortened", None) or {})}
        atomic_write_json(run_dir / "dry_run.json", {"model": model.name, "max_input_tokens": model.max_input_tokens,
                                                     "pass1": rows, "pass2_worst": rows2,
                                                     "reference_lines_shortened": len(short),
                                                     "judged_lines_shortened": sum(len(set(getattr(r, "shortened", None) or {}) & set(r.events)) for r in allr),
                                                     "views_restored": restored})
        log.info("dry run: pass 1 max prompt %d tokens; pass 2 (worst case) %d requests, max %d tokens (limit %d)",
                 max(r["prompt_tokens"] for r in rows), len(rows2),
                 max((r["prompt_tokens"] for r in rows2), default=0), model.max_input_tokens)
        store.close()
        return 0
    asker = Asker(client, model, byid, src_info, res_dir, hz, fingerprint)
    asker.context_tokens = int(cfg.get("budget", "context_tokens"))
    asker.fit = fit
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
        rounds = recursive_recheck(reqs, final, byid, fmt.count, hz,
                                   lambda r, tag, refs: asker.full(r, tag, attack_ids=refs), **rc_limits)
        atomic_write_json(run_dir / "rounds.json", rounds)
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
    log.info("experiment I done: %d verdicts, %d lines without a verdict", len(final), len(left))
    return 4 if left else 0


if __name__ == "__main__":
    sys.exit(main())
