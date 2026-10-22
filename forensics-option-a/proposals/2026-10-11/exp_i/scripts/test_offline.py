"""Offline checks for experiment I (experiment H checks 1-4 on the copied runner, plus new tests).
Offline checks for experiment H (no model server, fake LLM):
1. only the sampled lines are judged, every one of them gets a verdict;
2. context lines are looked up in the whole dataset (also outside the sample);
3. an oracle fake model (answers from the labels) scores recall 1.0 / FP 0.0, and an all-attack
   fake scores recall 1.0 / FP 1.0 -> scorer and runner agree on line identity;
4. the runner never opens the label files, and the prompt templates carry no dataset values.
"""
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
H = HERE.parent
HD = Path("/home/ubuntu/forensics-option-a/proposals/2026-10-10/exp_h")   # = score_i.H_DATA (read-only)
sys.path.insert(0, "/home/ubuntu/forensics-option-a")
sys.path.insert(0, str(HERE))
import hdf.llm as L  # noqa: E402
import run_i  # noqa: E402
import score_i  # noqa: E402
from run_i import F, I, V  # noqa: E402
from hdf.store import EvidenceStore  # noqa: E402

OUT = H / "test_runs"
CFG = str(HD / "configs" / "gemma_p1.toml")
DATASETS = ["win_bitsadmin_download", "win_auditpol_disable"]


def bodies_of(user):
    part = user.split("=== LINES TO JUDGE ===\n", 1)[1].split("\n=== END ===", 1)[0]
    return [re.sub(r"^\[L\d+\] ", "", l) for l in part.split("\n")]


def context_of(user):
    part = user.split("for reference only, do not judge them):\n", 1)[1].split("\n=== LINES TO JUDGE", 1)[0]
    # only the [Cn] lines: a re-check prompt also holds a reference block of [An] lines before the lines to judge
    return [l for l in part.split("\n") if l.startswith("[C")]


def run(ds, policy, seen):
    d = OUT / policy.__name__ / ds

    def complete(self, model, system, user, tag, schema=None):
        b = bodies_of(user)
        seen.append((ds, b, context_of(user), user))
        items = [{"line": f"L{k}", "quote": b[k - 1], "verdict": policy(ds, b[k - 1]), "reason": "test"}
                 for k in range(1, len(b) + 1)]
        return L.LLMResult(json.dumps({"verdicts": items}), "", 100, 50, False, "stop")

    shutil.rmtree(d, ignore_errors=True)
    L.LLMClient.complete = complete
    sys.argv = ["run_i.py", CFG, str(HD / "data" / ds / "evidence.db"), str(d), "--judge", str(score_i.sample_path(ds))]
    return run_i.main(), d


def h_checks(check):
    """Experiment H checks 1-4 (unchanged)."""
    body_class = {}
    full_bodies = {}
    for ds in DATASETS:
        tmp = OUT / "db_copy" / ds
        tmp.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HD / "data" / ds / "evidence.db", tmp / "evidence.db")   # never open the frozen file
        st = EvidenceStore(tmp / "evidence.db")
        evs = V.load_events(st)
        st.close()
        cls = score_i.classes(ds)
        full_bodies[ds] = {F.body(e) for e in evs}
        body_class[ds] = {}
        for e in evs:
            if e.id in cls:
                body_class[ds].setdefault(F.body(e), set()).add(cls[e.id])

    def oracle(ds, body):
        line = body.split(" :: ", 1)[1] if " :: " in body else body
        c = next((v for k, v in body_class[ds].items() if k.endswith(line) or line.endswith(k)), {"benign_bw"})
        return "attack" if "attack" in c else "normal"

    def all_attack(ds, body):
        return "attack"

    for pol in (oracle, all_attack):
        for ds in DATASETS:
            seen = []
            rc, d = run(ds, pol, seen)
            S = json.load(open(score_i.sample_path(ds)))
            fin = json.load(open(d / "verdicts.json"))
            check(rc == 0 and sorted(int(k) for k in fin) == sorted(S["judged"]),
                  f"{pol.__name__} {ds}: rc={rc}, judged {len(fin)} == sample {S['n']}")
            r = score_i.score_run(d, ds)
            want = (1.0, 0.0) if pol is oracle else (1.0, 1.0)
            got = (r["final"]["recall"], r["final"]["fp_rate"])
            check(got == want, f"{pol.__name__} {ds}: recall/FP = {got}, expected {want}")
            if pol is oracle:
                judged_bodies = {b for _, bs, _, _ in seen for b in bs}
                ctx = [c for _, _, cs, _ in seen for c in cs]
                outside = [c for c in ctx if c.split("] ", 1)[1] not in judged_bodies]
                check(len(outside) > 0, f"{ds}: {len(outside)} context line(s) come from outside the sample")
    src = (HERE / "run_i.py").read_text()
    check("labels" not in src.replace("Labels are never read here", ""), "run_i.py never references label files")
    tpl = F.USER + F.RECHECK + F.SYSTEM + I.SAME_REFS + I.LINKED_REFS
    words = ("bitsadmin", "auditpol", "ntdsutil", "schtasks", "fodhelper", "wsmprovhost", "mshta", "powershell",
             "lsass", "comsvcs", "rundll32", "WORKSTATION", "pedro", "wardog", "T1", ".exe", ".dll")
    bad = [w for w in words if w.lower() in tpl.lower()]
    check(not bad, f"templates free of dataset values: {bad}")


# ---------------------------------------------------------------- experiment I tests
def test_lsass_dev_classes(check):
    """Development sample = every lsass event; attack lines = the 87 labelled events, the rest benign_bw/excluded."""
    ds = "win_lsass_comsvcs"
    check(score_i.sample_path(ds) == H / "samples" / f"{ds}.json", "lsass sample comes from exp_i/samples")
    cls = score_i.classes(ds)
    L = json.load(open(HD / "labels" / f"{ds}.json"))
    n_att = sum(1 for v in cls.values() if v == "attack")
    check(n_att == len(L["labels"]) == 87, f"lsass attack lines {n_att} == labels {len(L['labels'])} == 87")
    other = {v for v in cls.values() if v != "attack"}
    check(other <= {"benign_bw", "excluded"}, f"lsass non-attack classes {sorted(other)}")


def run_answers(ds, answer, name, seen=None, cfg=None):
    """Run the runner on dataset ds with a fake model: answer(body, k, user) -> one verdict item for line k."""
    d = OUT / name / ds

    def complete(self, model, system, user, tag, schema=None):
        b = bodies_of(user)
        if seen is not None:
            seen.append((tag, b, user))
        items = [answer(b[k - 1], k, user) for k in range(1, len(b) + 1)]
        return L.LLMResult(json.dumps({"verdicts": items}), "", 100, 50, False, "stop")

    shutil.rmtree(d, ignore_errors=True)
    L.LLMClient.complete = complete
    sys.argv = ["run_i.py", cfg or CFG, str(HD / "data" / ds / "evidence.db"), str(d), "--judge", str(score_i.sample_path(ds))]
    return run_i.main(), d


BAD_QUOTE = "zz-text-that-is-in-no-line-zz"


def test_unbound_attack_kept(check):
    """attack + a quote that is not in the line: kept as attack, marked unbound / evidence insufficient."""
    ds = "win_bitsadmin_download"
    rc, d = run_answers(ds, lambda b, k, u: {"line": f"L{k}", "quote": BAD_QUOTE, "verdict": "attack", "reason": "t"},
                        "unbound_attack")
    fin = json.load(open(d / "verdicts.json"))
    vs = list(fin.values())
    check(rc == 0, f"unbound attack: rc={rc} (expected 0)")
    check(len(vs) == json.load(open(score_i.sample_path(ds)))["n"], f"unbound attack: {len(vs)} lines judged")
    check(all(v["verdict"] == "attack" and v.get("bound") is False and v.get("evidence") == "insufficient" for v in vs),
          "unbound attack: every line attack, bound False, evidence insufficient")


def test_unbound_normal_still_missing(check):
    """normal + a quote that is not in the line: still no verdict (exit 4)."""
    ds = "win_bitsadmin_download"
    rc, d = run_answers(ds, lambda b, k, u: {"line": f"L{k}", "quote": BAD_QUOTE, "verdict": "normal", "reason": "t"},
                        "unbound_normal")
    fin = json.load(open(d / "verdicts.json"))
    check(rc == 4, f"unbound normal: rc={rc} (expected 4)")
    check(all(v["verdict"] == "no_verdict" for v in fin.values()), "unbound normal: every line no_verdict")


def test_any_attack_wins(check):
    """A bound normal plus an unbound attack for the same line -> attack, bound False."""
    import i_lib
    bound = {7: {"verdict": "normal", "reason": "n", "quote": "q", "round": 0}}
    rejected = {7: [{"verdict": "attack", "reason": "a", "quote": "x", "why": "not_in_line", "round": 1}],
                8: [{"verdict": "normal", "reason": "n", "quote": "x", "why": "not_in_line", "round": 0}]}
    m = i_lib.merge_answers(bound, rejected, [7, 8, 9])
    check(m[7]["verdict"] == "attack" and m[7]["bound"] is False and m[7]["evidence"] == "insufficient",
          f"any attack wins: line 7 -> {m[7]['verdict']}, bound {m[7]['bound']}")
    check(len(m[7]["answers"]) == 2, f"any attack wins: line 7 keeps both answers ({len(m[7]['answers'])})")
    check(m[8]["verdict"] == "no_verdict" and m[9]["verdict"] == "no_verdict", "unbound normal / no answer -> no_verdict")
    b2 = i_lib.merge_answers({5: {"verdict": "attack", "reason": "a", "quote": "q", "round": 0}}, {}, [5])
    check(b2[5]["verdict"] == "attack" and b2[5]["bound"] is True and "evidence" not in b2[5], "bound attack -> bound True")


def test_unbound_counted_separately(check):
    """Two benign lines with an unbound attack: fp_unbound == 2 and they count in fp_rate."""
    ds = "win_bitsadmin_download"
    cls = score_i.classes(ds)
    ben = [i for i, c in sorted(cls.items()) if c.startswith("benign")]
    d = OUT / "unbound_count" / ds
    d.mkdir(parents=True, exist_ok=True)
    fin = {str(i): {"verdict": "attack" if c == "attack" else "normal", "bound": True} for i, c in cls.items()}
    for i in ben[:2]:
        fin[str(i)] = {"verdict": "attack", "bound": False, "evidence": "insufficient"}
    (d / "verdicts.json").write_text(json.dumps(fin))
    r = score_i.score_run(d, ds)
    check(r["final"].get("fp_unbound") == 2, f"fp_unbound = {r['final'].get('fp_unbound')} (expected 2)")
    check(r["final"].get("attack_unbound") == 2, f"attack_unbound = {r['final'].get('attack_unbound')} (expected 2)")
    check(r["final"]["fp_rate"] == round(2 / len(ben), 3), f"fp_rate {r['final']['fp_rate']} includes them")


PROFILES = H / "profiles"
PROFILE_NAMES = ["gemma", "gemma_sampled", "qwen", "qwen_think", "fsec", "fsec_after"]


def _first_requests(ds="win_bitsadmin_download"):
    """Pass-1 requests of ds (exp H limits), the events by id and the source constants, from a DB copy."""
    tmp = OUT / "db_copy_r" / ds
    tmp.mkdir(parents=True, exist_ok=True)
    shutil.copy2(HD / "data" / ds / "evidence.db", tmp / "evidence.db")
    st = EvidenceStore(tmp / "evidence.db")
    evs = V.load_events(st)
    src_info = {x: V.source_constants(st, x) for x in {e.src for e in evs}}
    st.close()
    byid = {e.id: e for e in evs}
    judged = set(json.load(open(score_i.sample_path(ds)))["judged"])
    reqs = run_i.build_requests_subset(evs, [e for e in evs if e.id in judged], None, I.Harness())
    return reqs, byid, src_info


def test_profiles_share_common_part(check):
    """Every profile renders the same rules, task and system text; only the context block may move."""
    from hdf.config import load_config
    reqs, byid, src_info = _first_requests()
    r = next(x for x in reqs if x.context)
    texts = {}
    for p in PROFILE_NAMES:
        hz = I.harness_from(load_config(str(PROFILES / f"{p}.toml")))
        texts[p] = I.render(r, byid, *src_info[byid[r.events[0]].src], attack_ids=None,
                            context_position=hz.context_position)
    check(all(F._RULES in t for t in texts.values()), "every profile prompt holds _RULES verbatim")
    task = F.USER.split("Task:", 1)[1].format(n=len(r.events))
    check(all(task in t for t in texts.values()), "every profile prompt holds the same Task/rules/format text")
    check(len({tuple(sorted(t.split("\n"))) for t in texts.values()}) == 1,
          "profile prompts hold the same lines (only their order may differ)")
    check(run_i.SYSTEM_PROMPT is F.SYSTEM and F.SYSTEM == V.SYSTEM, "runner sends V.SYSTEM for every profile")


def test_context_after(check):
    """context_position = after: the lines to judge come before the context block."""
    reqs, byid, src_info = _first_requests()
    r = next(x for x in reqs if x.context)
    a = I.render(r, byid, *src_info[byid[r.events[0]].src], attack_ids=None, context_position="after")
    b = I.render(r, byid, *src_info[byid[r.events[0]].src], attack_ids=None, context_position="before")
    hdr = "Context lines (how this process"
    check(a.index("=== LINES TO JUDGE ===") < a.index(hdr) and a.index("=== END ===") < a.index(hdr),
          "after: context block follows === END ===")
    check(b.index(hdr) < b.index("=== LINES TO JUDGE ==="), "before: unchanged (context first)")
    check(b == F.render(r, byid, *src_info[byid[r.events[0]].src]), "before == f_lib.render (experiment H prompt)")
    refs = r.events[:1]
    ra = I.render(V.Request(r.key, r.part, r.title, r.events[1:] or r.events, r.context), byid,
                  *src_info[byid[r.events[0]].src], attack_ids=refs, context_position="after")
    check(ra.index("=== END ===") < ra.index(hdr) < ra.index("Task:"), "after (re-check prompt): context after END, before Task")
    try:
        I.render(r, byid, *src_info[byid[r.events[0]].src], attack_ids=None, context_position="middle")
        check(False, "bad context_position accepted")
    except ValueError:
        check(True, "bad context_position -> ValueError")


def test_cache_key_includes_profile(check):
    """Same model, only sampling differs: the second profile must not reuse the first one's cached answers."""
    from hdf.config import load_config
    ds = "win_bitsadmin_download"
    fa = I.profile_fingerprint(load_config(str(PROFILES / "gemma.toml")))
    fb = I.profile_fingerprint(load_config(str(PROFILES / "gemma_sampled.toml")))
    check(fa != fb and len(fa) == 12, f"fingerprints differ: {fa} vs {fb}")
    ans = lambda b, k, u: {"line": f"L{k}", "quote": b, "verdict": "normal", "reason": "t"}
    seen_a, seen_b = [], []
    rc1, d = run_answers(ds, ans, "cache_key", seen_a, cfg=str(PROFILES / "gemma.toml"))
    n1 = len(list((d / "results").glob("*.json")))
    # second profile, SAME run dir (no rmtree): every request must be asked again
    def complete(self, model, system, user, tag, schema=None):
        b = bodies_of(user)
        seen_b.append(tag)
        return L.LLMResult(json.dumps({"verdicts": [ans(b[k - 1], k, user) for k in range(1, len(b) + 1)]}),
                           "", 100, 50, False, "stop")
    L.LLMClient.complete = complete
    sys.argv = ["run_i.py", str(PROFILES / "gemma_sampled.toml"), str(HD / "data" / ds / "evidence.db"), str(d),
                "--judge", str(score_i.sample_path(ds))]
    rc2 = run_i.main()
    n2 = len(list((d / "results").glob("*.json")))
    check(rc1 == 0 and rc2 == 0 and len(seen_b) == len(seen_a) > 0, f"second profile asked {len(seen_b)}/{len(seen_a)} requests again")
    check(n2 == 2 * n1, f"cache files {n1} -> {n2} (separate per profile)")


def test_harness_unknown_key(check):
    from hdf.config import load_config
    for bad in ({"foo": 1}, {"context_position": "middle"}, {"max_lines": "20"}):
        try:
            I.harness_from(load_config(None, overrides={"harness": bad}))
            check(False, f"[harness] {bad} accepted")
        except ValueError:
            check(True, f"[harness] {bad} -> ValueError")
    hz = I.harness_from(load_config(None))
    check(hz == I.Harness() and (hz.max_lines, hz.evidence_tokens, hz.recheck_attack_tokens, hz.recheck_attack_lines,
                                 hz.context_position, hz.max_rounds) == (0, 0, 2000, 15, "before", 3),
          "no [harness] -> variable packing defaults (no line cap, no fixed evidence budget)")


def test_hit_limit_reported(check):
    """A fake model that stops at the output limit shows up in score_run's finish and hit_limit counts."""
    ds = "win_bitsadmin_download"
    d = OUT / "hit_limit" / ds
    shutil.rmtree(d, ignore_errors=True)

    def complete(self, model, system, user, tag, schema=None):
        b = bodies_of(user)
        items = [{"line": f"L{k}", "quote": b[k - 1], "verdict": "attack", "reason": "t"} for k in range(1, len(b) + 1)]
        return L.LLMResult(json.dumps({"verdicts": items}), "", 100, 4096, True, "length")
    L.LLMClient.complete = complete
    sys.argv = ["run_i.py", str(PROFILES / "fsec.toml"), str(HD / "data" / ds / "evidence.db"), str(d),
                "--judge", str(score_i.sample_path(ds))]
    rc = run_i.main()
    r = score_i.score_run(d, ds)
    check(rc == 0 and r.get("hit_limit") == r["requests"] > 0, f"hit_limit {r.get('hit_limit')} of {r['requests']} requests")
    check(r["finish"] == {"length": r["requests"]}, f"finish {r['finish']}")


def _ev(i, pid, fields=None, host="H1"):
    """Synthetic event: process pid on host, time = id."""
    f = {"ProcessId": str(pid), "Image": f"img{pid}", **(fields or {})}
    return V.Ev(i, 1, f"t{i:04d}", float(i), host, " | ".join(f"{k}={v}" for k, v in f.items()), f,
                V.norm_pid(f.get("SourceProcessId") or f.get("ProcessId")), V.norm_pid(f.get("NewProcessId")),
                V.norm_pid(f.get("ParentProcessId")))


def _loop(evs, attack, flip, max_rounds=3):
    """Run run_i.recursive_recheck on synthetic events; pass 1 = `attack` ids attack, rest normal.
    flip(line_id, refs) -> bool decides the fake model's re-check answer. Returns (final, rounds, asked)."""
    byid = {e.id: e for e in evs}
    reqs = V.build_requests(evs, 20)
    final = {e.id: {"verdict": "attack" if e.id in attack else "normal", "bound": True, "pass": 1} for e in evs}
    asked = []

    def ask(req, tag, refs):
        asked.append((tag, list(req.events), list(refs)))
        return {i: {"verdict": "attack" if flip(i, refs) else "normal", "bound": True, "reason": "", "quote": ""}
                for i in req.events}
    rounds = run_i.recursive_recheck(reqs, final, byid, None, I.Harness(max_rounds=max_rounds), ask)
    return final, rounds, asked


def test_recursive_flip(check):
    """Y (pid 800, linked to attack pid 700) flips in round 1; X (pid 900, linked to 800) only in round 2."""
    evs = [_ev(1, 700), _ev(2, 800, {"TargetProcessId": "700"}), _ev(3, 900, {"TargetProcessId": "800"})]
    final, rounds, asked = _loop(evs, {1}, lambda i, refs: (i == 2 and 1 in refs) or (i == 3 and 2 in refs))
    check(final[2]["verdict"] == "attack" and final[2]["pass"] == 2, f"Y flipped in round 1 (pass {final[2].get('pass')})")
    check(final[3]["verdict"] == "attack" and final[3]["pass"] == 3, f"X flipped in round 2 (pass {final[3].get('pass')})")
    check([r["round"] for r in rounds] == [1, 2] and [r["flipped"] for r in rounds] == [1, 1], f"rounds {rounds}")


def test_linked_process_rechecked(check):
    """A line of another process (pid 900) that names attack pid 700 in TargetProcessId is re-checked with 700's attack line."""
    evs = [_ev(1, 700), _ev(2, 700), _ev(3, 900, {"TargetProcessId": "700"}), _ev(4, 900), _ev(5, 901)]
    byid = {e.id: e for e in evs}
    reqs = V.build_requests(evs, 20)
    verdicts = {1: {"verdict": "attack"}, 2: {"verdict": "normal"}, 3: {"verdict": "normal"}, 4: {"verdict": "normal"},
                5: {"verdict": "normal"}}
    t = I.recheck_targets(reqs, verdicts, byid, {})
    lines = {i: refs for r, refs in t for i in r.events}
    check(set(lines) == {2, 3}, f"targets {sorted(lines)} == [2, 3] (same process + linked; 4 and 5 not linked)")
    check(lines.get(3) == [1], f"linked line 3 gets attack line 1 as reference ({lines.get(3)})")
    check(I.linked_pids(byid[3]) == {("H1", 900), ("H1", 700)}, f"linked_pids {I.linked_pids(byid[3])}")
    r3 = next(r for r, _ in t if 3 in r.events)
    check(r3.key == V.group_key(byid[3]), "linked line is asked within its own process group (title/context)")


def test_recursion_stops(check):
    evs = [_ev(1, 700), _ev(2, 700), _ev(3, 800, {"TargetProcessId": "700"})]
    final, rounds, asked = _loop(evs, {1}, lambda i, refs: False)
    check(len(rounds) == 1 and rounds[0]["flipped"] == 0, f"normal-only model: stops after round 1 ({rounds})")
    chain = [_ev(1, 700)] + [_ev(k, 700 + 100 * (k - 1), {"TargetProcessId": str(700 + 100 * (k - 2))}) for k in range(2, 7)]
    final, rounds, asked = _loop(chain, {1}, lambda i, refs: bool(refs))
    check(len(rounds) == 3, f"always-flipping model on a 6-process chain: {len(rounds)} rounds (max_rounds 3)")
    check(sum(1 for v in final.values() if v["verdict"] == "attack") == 4, "3 rounds flipped 3 chained lines")
    ds = "win_bitsadmin_download"
    ans = lambda b, k, u: {"line": f"L{k}", "quote": b, "verdict": "attack" if k == 1 and "=== LINES TO JUDGE" in u
                           and "judged to be part of an attack" not in u else "normal", "reason": "t"}
    rc, d = run_answers(ds, ans, "rounds_json", cfg=str(PROFILES / "gemma.toml"))
    rj = json.load(open(d / "rounds.json"))
    check(rc == 0 and len(rj) == 1 and rj[0]["flipped"] == 0 and rj[0]["requests"] > 0,
          f"runner writes rounds.json ({rj})")


def test_only_new_evidence_rechecked(check):
    """Round 2 asks only the line whose evidence grew (3), not the one whose evidence is unchanged (5)."""
    evs = [_ev(1, 700), _ev(2, 700), _ev(3, 700), _ev(4, 800), _ev(5, 800)]
    final, rounds, asked = _loop(evs, {1, 4}, lambda i, refs: i == 2)
    r2 = [lines for tag, lines, _ in asked if tag.startswith("r2_")]
    check(len(rounds) == 2, f"two rounds ({rounds})")
    check(r2 == [[3]], f"round-2 requests {r2} == [[3]]")


def _attack():
    from hdf.attack import Attack
    return Attack.load("/home/ubuntu/forensics-option-a/data/attack/enterprise-attack.json")


def test_conclusion_grounded(check):
    """End to end on a fake run: a conclusion citing a line that is not in the request is rejected."""
    import conclude
    ds = "win_bitsadmin_download"
    cls = score_i.classes(ds)
    rc, d = run_answers(ds, lambda b, k, u: {"line": f"L{k}", "quote": b, "verdict": "normal", "reason": "t"},
                        "conclude", cfg=str(PROFILES / "gemma.toml"))
    fin = json.load(open(d / "verdicts.json"))
    for i, c in cls.items():   # make the attack lines "attack" (one of them unbound) to feed the conclusion step
        if c == "attack":
            fin[str(i)] = {"verdict": "attack", "bound": True}
    first_att = min(i for i, c in cls.items() if c == "attack")
    fin[str(first_att)] = {"verdict": "attack", "bound": False, "evidence": "insufficient"}
    (d / "verdicts.json").write_text(json.dumps(fin))
    users = []

    def complete(self, model, system, user, tag, schema=None):
        users.append(user)
        n = user.count("\n[L")
        out = {"conclusions": [{"technique": "t1197", "lines": ["L1"], "reason": "r"},
                               {"technique": "T1197", "lines": [f"L{n + 5}"], "reason": "r"},
                               {"technique": "T9999", "lines": ["L1"], "reason": "r"}]}
        return L.LLMResult(json.dumps(out), "", 100, 50, False, "stop")
    L.LLMClient.complete = complete
    rc2 = conclude.main([str(PROFILES / "gemma.toml"), str(d)])
    c = json.load(open(d / "conclusions.json"))
    n_req = len(users)
    check(rc2 == 0 and n_req > 0, f"conclude rc={rc2}, {n_req} request(s)")
    check(len(c["conclusions"]) == n_req and all(x["technique"] == "T1197" for x in c["conclusions"]),
          f"{len(c['conclusions'])} grounded conclusions, technique normalised to T1197")
    why = sorted({r["why"] for r in c["rejected"]})
    check(why == ["bad_line", "unknown_technique"] and len(c["rejected"]) == 2 * n_req, f"rejected {why}")
    att = {int(k) for k, v in fin.items() if v["verdict"] == "attack"}
    shown = {int(i) for x in c["conclusions"] for i in x["events"]}
    check(shown <= att and first_att in {i for x in c.get("asked", []) for i in x["events"]},
          "cited events are attack lines; unbound attack lines are asked too")
    check(all(x["name"] for x in c["conclusions"]), "conclusions carry the ATT&CK name")


def test_technique_normalised(check):
    import conclude
    A = _attack()
    check(conclude.normalise_technique("t1003/001", A) == ("T1003.001", ""), "t1003/001 -> T1003.001")
    check(conclude.normalise_technique(" T1003.001 ", A) == ("T1003.001", ""), "spaces stripped")
    check(conclude.normalise_technique("T9999", A)[0] is None, "T9999 rejected")
    check(conclude.normalise_technique("credential dumping", A)[0] is None, "free text rejected")
    check(conclude.normalise_technique("T1003.001 - OS Credential Dumping: LSASS Memory", A) == ("T1003.001", ""),
          "ID followed by its name -> the ID")
    check(conclude.normalise_technique("T1003 or T1055", A) == (None, "several_ids"), "two different IDs rejected")
    check(conclude.normalise_technique("T1003.001 (T1003.001)", A) == ("T1003.001", ""), "same ID twice -> the ID")
    check(conclude.normalise_technique("T10030", A)[0] is None, "five digits rejected")
    check(conclude.normalise_technique("t1066", A) == (A.canonical("T1066"), "") and A.canonical("T1066") == "T1027.005",
          "revoked T1066 -> its replacement T1027.005")
    check(conclude.normalise_technique("T1153", A) == (None, "unknown_technique"), "deprecated T1153 rejected")


def test_truth_from_metadata(check):
    check(score_i.technique_truth("win_ntds_ntdsutil") == {"T1003.003"}, "ntdsutil truth T1003.003")
    check(score_i.technique_truth("win_bitsadmin_download") == {"T1197"}, "bitsadmin truth T1197")
    check(score_i.technique_truth("win_lsass_comsvcs") == {"T1003.001"}, "lsass truth T1003.001")


def test_technique_scoring(check):
    ds = "win_lsass_comsvcs"
    cls = score_i.classes(ds)
    att = sorted(i for i, c in cls.items() if c == "attack")
    ben = sorted(i for i, c in cls.items() if c.startswith("benign"))
    d = OUT / "tech_score" / ds
    d.mkdir(parents=True, exist_ok=True)
    (d / "verdicts.json").write_text(json.dumps({str(i): {"verdict": "attack"} for i in cls}))
    (d / "conclusions.json").write_text(json.dumps({"conclusions": [
        {"technique": "T1003", "events": att[:2], "reason": "", "group": "g"},
        {"technique": "T1059.001", "events": att[:1], "reason": "", "group": "g"}], "rejected": []}))
    t = score_i.score_run(d, ds)["techniques"]
    check(t["exact"] is False and t["parent"] is True and t["extra"] == 2, f"parent-only match: {t}")
    (d / "conclusions.json").write_text(json.dumps({"conclusions": [
        {"technique": "T1003.001", "events": att[:3] + ben[:1], "reason": "", "group": "g"}], "rejected": []}))
    t = score_i.score_run(d, ds)["techniques"]
    check(t["exact"] is True and t["extra"] == 0 and t["evidence_recall"] == 0.75, f"exact match: {t}")


def test_prompt_has_no_technique_hints(check):
    import conclude
    tpl = conclude.CONCLUDE + conclude.SYSTEM_PROMPT
    check(not re.search(r"T\d{4}", tpl), "no technique IDs in the conclusion template")
    names = [p.name for p in (HD / "data").iterdir()] + ["bitsadmin", "auditpol", "ntdsutil", "schtasks", "fodhelper",
                                                           "lsass", "comsvcs", "mshta", "psremoting", ".exe", ".dll"]
    bad = [w for w in names if w.lower() in tpl.lower()]
    check(not bad, f"no dataset names in the conclusion template: {bad}")


# ---------------------------------------------------------------- conclusion v2 (ATT&CK catalog in the prompt)
def _fake_attack_run(name, ds="win_bitsadmin_download"):
    """A run dir whose verdicts mark the labelled attack lines attack (one unbound), the rest normal."""
    cls = score_i.classes(ds)
    rc, d = run_answers(ds, lambda b, k, u: {"line": f"L{k}", "quote": b, "verdict": "normal", "reason": "t"},
                        name, cfg=str(PROFILES / "gemma.toml"))
    fin = json.load(open(d / "verdicts.json"))
    att = sorted(i for i, c in cls.items() if c == "attack")
    for i in att:
        fin[str(i)] = {"verdict": "attack", "bound": True}
    fin[str(att[0])] = {"verdict": "attack", "bound": False, "evidence": "insufficient"}
    (d / "verdicts.json").write_text(json.dumps(fin))
    return d, att


def test_catalog_from_stix(check):
    import conclude_v2 as C2
    cat = C2.load_catalog("/home/ubuntu/forensics-option-a/data/attack/enterprise-attack.json")
    A = _attack()
    current = {k for k in A.techniques if A.canonical(k) == k}
    check(set(cat["techniques"]) == current and len(current) == 697, f"catalog {len(cat['techniques'])} == current IDs {len(current)}")
    t = cat["techniques"]["T1003.001"]
    check(t["name"] == "OS Credential Dumping: LSASS Memory" and t["tactics"] == ["credential-access"],
          f"T1003.001 -> {t['name']} {t['tactics']}")
    descs = [x["description"] for x in cat["techniques"].values()]
    check(all("](" not in x and "(Citation:" not in x and len(x) <= C2.DESC_CHARS for x in descs) and all(descs),
          "descriptions cleaned (no links/citations), non-empty, <= DESC_CHARS")
    check(cat["version"] == A.version, f"catalog version {cat['version']} == ATT&CK {A.version}")


def test_catalog_same_for_every_run(check):
    """The select prompt's catalog block (the 222 parent techniques) does not depend on the evidence; the
    templates themselves hold no IDs or dataset names."""
    import conclude_v2 as C2
    cat = C2.load_catalog("/home/ubuntu/forensics-option-a/data/attack/enterprise-attack.json")
    blocks = set()
    for ds in ("win_bitsadmin_download", "win_auditpol_disable"):
        tmp = OUT / "db_copy_c" / ds
        tmp.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HD / "data" / ds / "evidence.db", tmp / "evidence.db")
        st = EvidenceStore(tmp / "evidence.db")
        evs = V.load_events(st)
        src_info = {x: V.source_constants(st, x) for x in {e.src for e in evs}}
        st.close()
        byid = {e.id: e for e in evs}
        u = C2.render_select([evs[0].id, evs[1].id], byid, src_info, cat)
        blocks.add(u.split("=== ATT&CK TECHNIQUES ===\n", 1)[1].split("\n=== END TECHNIQUES ===", 1)[0])
    blk = next(iter(blocks)).split("\n")
    check(len(blocks) == 1 and len(blk) == 222 and not any("." in l.split(" ", 1)[0] for l in blk),
          f"same {len(blk)}-line parent catalog block for every dataset")
    tpl = C2.SELECT + C2.VERIFY + C2.SYSTEM_PROMPT
    check(not re.search(r"T\d{4}", tpl), "no technique IDs in the v2 templates")
    names = [p.name for p in (HD / "data").iterdir()] + ["bitsadmin", "auditpol", "ntdsutil", "schtasks", "fodhelper",
                                                           "lsass", "comsvcs", "mshta", "psremoting", ".exe", ".dll"]
    bad = [w for w in names if w.lower() in tpl.lower()]
    check(not bad, f"no dataset names in the v2 templates: {bad}")


def test_select_prompt_fits(check):
    """Dry run with every profile's tokenizer: catalog + rules + the full evidence budget fit max_input_tokens."""
    import conclude_v2 as C2
    from hdf.config import load_config
    d, att = _fake_attack_run("c2_dry")
    for p in ("gemma", "qwen_think", "fsec"):
        rc = C2.main([str(PROFILES / f"{p}.toml"), str(d), "--dry-run"])
        dr = json.load(open(d / "conclude_v2_dry.json"))
        ev = I.harness_from(load_config(str(PROFILES / f"{p}.toml"))).evidence_tokens
        want = dr["max_input_tokens"] - dr["catalog_tokens"] - C2.PROMPT_MARGIN
        want = min(want, ev) if ev else want
        check(rc == 0 and 0 < dr["max_select_tokens"] <= dr["max_input_tokens"] and dr["evidence_budget"] == want,
              f"{p}: select max {dr['max_select_tokens']} / limit {dr['max_input_tokens']}, "
              f"catalog {dr['catalog_tokens']}, evidence budget {dr['evidence_budget']} (== {want}, variable)")
        check(dr["max_verify_tokens"] <= dr["max_input_tokens"],
              f"{p}: worst verify prompt (largest parent) {dr['max_verify_tokens']} tokens")


def _fake_conclude(d, select_out, verify_fn):
    import conclude_v2 as C2
    calls = {"select": 0, "verify": 0, "verify_users": []}

    def complete(self, model, system, user, tag, schema=None):
        if "=== ATT&CK TECHNIQUES ===" in user:
            calls["select"] += 1
            n = user.split("=== ATTACK LINES ===", 1)[1].count("\n[L")
            out = {"conclusions": select_out(n)}
        else:
            calls["verify"] += 1
            calls["verify_users"].append(user)
            out = {"checks": verify_fn(user)}
        return L.LLMResult(json.dumps(out), "", 100, 50, False, "stop")
    L.LLMClient.complete = complete
    rc = C2.main([str(PROFILES / "gemma.toml"), str(d)])
    return rc, json.load(open(d / "conclusions_v2.json")), calls


def test_verify_rejects_not_shown(check):
    """select names T1197 and the sub-technique t1003/001 directly; verify: T1197 shown, T1003 not_shown -> final T1197."""
    d, att = _fake_attack_run("c2_verify")
    rc, c, calls = _fake_conclude(d, lambda n: [{"technique": "T1197", "lines": ["L1"], "reason": "r"},
                                                {"technique": "t1003/001", "lines": ["L1"], "reason": "r"},
                                                {"technique": "T1197", "lines": [f"L{n + 3}"], "reason": "bad line"},
                                                {"technique": "T9999", "lines": ["L1"], "reason": "unknown"}],
                                  lambda u: [{"technique": "T1197", "verdict": "shown", "sub_technique": "none", "reason": "r"},
                                             {"technique": "T1003", "verdict": "not_shown", "sub_technique": "none", "reason": "r"}])
    u = calls["verify_users"][0] if calls["verify_users"] else ""
    check("Adversaries may" in u and "(Citation:" not in u and "T1003.001 OS Credential Dumping: LSASS Memory" in u,
          "verify prompt: cleaned description + the parent's sub-technique list")
    check(rc == 0 and calls["select"] > 0 and calls["verify"] == calls["select"], f"rc={rc}, calls select {calls['select']} verify {calls['verify']}")
    check({x["technique"] for x in c["selected"]} == {"T1197", "T1003"}, f"selected parents {sorted({x['technique'] for x in c['selected']})}")
    check({x["technique"] for x in c["conclusions"]} == {"T1197"} and all(x["verified"] == "shown" for x in c["conclusions"]),
          "final keeps only the shown one")
    why = sorted({r["why"] for r in c["rejected"]})
    check(why == ["bad_line", "not_shown", "unknown_technique"], f"rejected reasons {why}")


def test_sub_technique_refined(check):
    """verify picks a sub-technique of the parent -> final is the sub-technique; a sub of another parent is ignored."""
    d, att = _fake_attack_run("c2_sub")
    rc, c, calls = _fake_conclude(d, lambda n: [{"technique": "T1003", "lines": ["L1"], "reason": "r"},
                                                {"technique": "T1197", "lines": ["L1"], "reason": "r"}],
                                  lambda u: [{"technique": "T1003", "verdict": "shown", "sub_technique": "T1003.001", "reason": "r"},
                                             {"technique": "T1197", "verdict": "shown", "sub_technique": "T1055.001", "reason": "r"}])
    fin = sorted({x["technique"] for x in c["conclusions"]})
    check(rc == 0 and fin == ["T1003.001", "T1197"], f"final {fin} == ['T1003.001', 'T1197']")


def test_verify_unanswered_kept(check):
    """A selected technique the verify answer does not mention is kept (unsure -> keep), marked unverified."""
    d, att = _fake_attack_run("c2_unanswered")
    rc, c, calls = _fake_conclude(d, lambda n: [{"technique": "T1197", "lines": ["L1"], "reason": "r"}], lambda u: [])
    check(rc == 0 and c["conclusions"] and all(x["verified"] == "unverified" for x in c["conclusions"]),
          f"unanswered -> kept as unverified ({sorted({x['verified'] for x in c['conclusions']})})")
    r = score_i.score_run(d, "win_bitsadmin_download", conclusions_file="conclusions_v2.json")
    check(r["techniques"]["exact"] is True and r["techniques_selected"]["exact"] is True,
          f"scored from conclusions_v2.json: final {r['techniques']['concluded']}, selected {r['techniques_selected']['concluded']}")


# ---------------------------------------------------------------- dynamic output budget
class _StubFmt:
    def format(self, system, user):
        return system + "\n" + user

    def count(self, text):
        return len(text.split())


class _StubClient:
    def __init__(self):
        self.models = []

    def formatter(self, model):
        return _StubFmt()

    def complete(self, model, system, user, tag, schema=None):
        self.models.append(model)
        return "ok"


def test_dynamic_output_budget(check):
    """Output limit = context - prompt tokens, never below the configured output tokens; input limit unchanged."""
    from hdf.config import load_config
    cfg = load_config(str(PROFILES / "gemma.toml"))
    m = cfg.model("triage")
    ctx = int(cfg.get("budget", "context_tokens"))
    c = _StubClient()
    for n in (100, 6000, ctx - m.max_output_tokens):
        I.complete(c, m, ctx, "sys", " ".join(["w"] * (n - 1)), "t")
        got = c.models[-1]
        check(got.max_output_tokens == ctx - n and got.max_input_tokens == m.max_input_tokens and got.name == m.name,
              f"prompt {n}: output {got.max_output_tokens} == {ctx} - {n}, input limit {got.max_input_tokens}")
    I.complete(c, m, ctx, "sys", " ".join(["w"] * (ctx - 100)), "t")
    check(c.models[-1].max_output_tokens == m.max_output_tokens, "over-long prompt: output stays at the minimum (client then refuses the prompt)")
    check(m.max_output_tokens == 4096 and m.max_input_tokens + m.max_output_tokens == ctx == 16384,
          f"profile budget {m.max_input_tokens}+{m.max_output_tokens} == {ctx}")


def test_runner_uses_dynamic_output(check):
    """Every runner and conclusion request is sent with output = context - prompt tokens (real tokenizer)."""
    import conclude_v2 as C2
    from hdf.config import load_config
    ctx = int(load_config(str(PROFILES / "gemma.toml")).get("budget", "context_tokens"))
    seen = []

    def complete(self, model, system, user, tag, schema=None):
        fmt = self.formatter(model)
        n_in = fmt.count(fmt.format(system, user))
        seen.append((tag, model.max_output_tokens, ctx - n_in))
        if "=== ATT&CK TECHNIQUES ===" in user:
            out = {"conclusions": [{"technique": "T1197", "lines": ["L1"], "reason": "r"}]}
        elif "Sub-techniques:" in user:
            out = {"checks": [{"technique": "T1197", "verdict": "shown", "sub_technique": "none", "reason": "r"}]}
        else:
            b = bodies_of(user)
            out = {"verdicts": [{"line": f"L{k}", "quote": b[k - 1], "verdict": "attack" if k == 1 else "normal",
                                 "reason": "t"} for k in range(1, len(b) + 1)]}
        return L.LLMResult(json.dumps(out), "", n_in, 50, False, "stop")
    ds = "win_bitsadmin_download"
    d = OUT / "dyn_out" / ds
    shutil.rmtree(d, ignore_errors=True)
    L.LLMClient.complete = complete
    sys.argv = ["run_i.py", str(PROFILES / "gemma.toml"), str(HD / "data" / ds / "evidence.db"), str(d),
                "--judge", str(score_i.sample_path(ds))]
    rc = run_i.main()
    rc2 = C2.main([str(PROFILES / "gemma.toml"), str(d)])
    kinds = {t[0][0] for t in seen}
    bad = [t for t in seen if t[1] != max(4096, t[2])]
    check(rc == 0 and rc2 == 0 and {"f", "r", "s", "v"} <= kinds and not bad,
          f"{len(seen)} requests (kinds {sorted(kinds)}), output == context - prompt for all; mismatches {bad[:3]}")
    check(min(t[1] for t in seen) > 4096, f"smallest output budget {min(t[1] for t in seen)} > 4096 (prompts < 12,288)")


# ---------------------------------------------------------------- no cut log lines
ALL_DS = ["win_lsass_comsvcs", "win_bitsadmin_download", "win_auditpol_disable", "win_remote_schtask",
          "win_ntds_ntdsutil", "win_psremoting", "win_uac_fodhelper"]


def test_views_restored(check):
    """Values the ingest cut at max_value_chars ("…[+N chars]") are restored from the event's own fields:
    no marker is left, and each restored line grows by exactly the N characters the marker announced."""
    total = 0
    for ds in ALL_DS:
        tmp = OUT / "db_copy_v" / ds
        tmp.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HD / "data" / ds / "evidence.db", tmp / "evidence.db")
        st = EvidenceStore(tmp / "evidence.db")
        evs = V.load_events(st)
        before = {e.id: e.view for e in evs}
        stats = I.restore_views(st, evs)
        st.close()
        left = [e.id for e in evs if I.CUT_MARK.search(e.view)]
        grew = all(len(e.view) - len(before[e.id]) == sum(int(n) - len(m) for m, n in
                                                           ((mm.group(0), mm.group(1)) for mm in I.CUT_MARK.finditer(before[e.id])))
                   for e in evs if e.view != before[e.id])
        n_cut = sum(1 for v in before.values() if I.CUT_MARK.search(v))
        total += stats["restored"]
        check(not left and stats["failed"] == 0 and stats["restored"] == n_cut and grew,
              f"{ds}: {stats['restored']}/{n_cut} cut lines restored, {len(left)} markers left, lengths exact {grew}")
    check(total > 0, f"{total} cut lines restored over the datasets")


def test_variable_packing(check):
    """Whole lines only; a group that fits stays in one request (no fixed line cap); a larger group is split at
    line boundaries; every request keeps prompt <= input limit and prompt + expected answer <= context."""
    hz = I.Harness(output_base=600, output_per_line=100)
    lines = {i: 150 for i in range(1, 201)}           # 200 lines of 150 tokens
    lines[150] = 5000                                  # one long (restored) line
    count_of = lambda i: lines[i]
    one = I.pack(list(range(1, 41)), count_of, 800, hz, max_input=12288, context=16384)
    check(len(one) == 1 and len(one[0]) == 40, f"40 lines (prompt 6,800) stay in one request: {[len(c) for c in one]}")
    many = I.pack(list(range(1, 201)), count_of, 800, hz, max_input=12288, context=16384)
    flat = [i for c in many for i in c]
    check(flat == list(range(1, 201)), "every line exactly once, in order, never split")
    ok = all(800 + sum(lines[i] for i in c) <= 12288 and 800 + sum(lines[i] for i in c) + 600 + 100 * len(c) <= 16384
             for c in many)
    check(ok, f"every request within both limits: sizes {[len(c) for c in many]}")
    check(all(800 + sum(lines[i] for i in a) + lines[b[0]] + 600 + 100 * (len(a) + 1) > 16384
              or 800 + sum(lines[i] for i in a) + lines[b[0]] > 12288 for a, b in zip(many, many[1:])),
          "greedy: the next line would not have fitted in the previous request")
    big = {1: 100, 2: 13000, 3: 100}
    r = I.pack([1, 2, 3], big.get, 800, hz, max_input=12288, context=16384)
    check(r == [[1], [2], [3]], f"a line larger than the budget is asked alone (never cut): {r}")
    capped = I.pack(list(range(1, 41)), count_of, 800, I.Harness(max_lines=20), max_input=12288, context=16384)
    check([len(c) for c in capped] == [20, 20], "profile max_lines still caps when set")
    nocount = I.pack(list(range(1, 41)), None, 0, I.Harness(), max_input=12288, context=16384)
    check(nocount == [list(range(1, 41))], "no tokenizer (offline synthetic tests): one request per group")


def test_all_datasets_fit(check):
    """Dry run, Gemma tokenizer, all 7 datasets: every pass-1 and worst-case re-check prompt within the input limit,
    every cut value restored, and no judged line shortened."""
    for ds in ALL_DS:
        d = OUT / "fit" / ds
        sys.argv = ["run_i.py", str(PROFILES / "gemma.toml"), str(HD / "data" / ds / "evidence.db"), str(d),
                    "--judge", str(score_i.sample_path(ds)), "--dry-run"]
        rc = run_i.main()
        dr = json.load(open(d / "dry_run.json"))
        rows = dr["pass1"] + dr["pass2_worst"]
        over = [r for r in rows if r["prompt_tokens"] > dr["max_input_tokens"]]
        check(rc == 0 and not over and dr.get("judged_lines_shortened") == 0,
              f"{ds}: {len(rows)} prompts, max {max(r['prompt_tokens'] for r in rows)}, over limit {len(over)}, "
              f"reference lines shortened {dr.get('reference_lines_shortened')}, judged shortened {dr.get('judged_lines_shortened')}")


def test_conclude_fits_long_lines(check):
    """uac_fodhelper attack lines include ~9K-token lines: every select and verify prompt stays within the limit."""
    import conclude_v2 as C2
    d, att = _fake_attack_run("c2_long", ds="win_uac_fodhelper")
    sizes = []

    def complete(self, model, system, user, tag, schema=None):
        fmt = self.formatter(model)
        n_in = fmt.count(fmt.format(system, user))
        sizes.append((tag[0], n_in, model.max_input_tokens))
        if n_in > model.max_input_tokens:
            raise L.ContextBudgetError(f"{n_in} > {model.max_input_tokens}")
        if "=== ATT&CK TECHNIQUES ===" in user:
            n = user.split("=== ATTACK LINES ===", 1)[1].count("\n[L")
            out = {"conclusions": [{"technique": "T1548", "lines": [f"L{k}" for k in range(1, n + 1)], "reason": "r"}]}
        else:
            out = {"checks": [{"technique": "T1548", "verdict": "shown", "sub_technique": "T1548.002", "reason": "r"}]}
        return L.LLMResult(json.dumps(out), "", n_in, 50, False, "stop")
    L.LLMClient.complete = complete
    rc = C2.main([str(PROFILES / "gemma.toml"), str(d)])
    v = [x for x in sizes if x[0] == "v"]
    check(rc == 0 and v and all(n <= lim for _, n, lim in sizes),
          f"rc={rc}: {len(sizes)} prompts (verify {len(v)}), max {max(n for _, n, _ in sizes)} <= limit")


def test_conclude_retries_failed_request(check):
    """A select answer that is cut off (repetition, no JSON) is asked again in two halves; nothing is lost.
    No tokenizer: a stub formatter, and the run dir is written directly (can run beside a GPU job)."""
    ds = "win_bitsadmin_download"
    d = OUT / "c2_retry" / ds
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    shutil.copy2(HD / "data" / ds / "evidence.db", d / "evidence.db")
    cls = score_i.classes(ds)
    (d / "verdicts.json").write_text(json.dumps({str(i): {"verdict": "attack" if c == "attack" else "normal"}
                                                 for i, c in cls.items()}))
    orig_fmt = L.LLMClient.formatter
    L.LLMClient.formatter = lambda self, model: _StubFmt()
    asked = []

    def complete(self, model, system, user, tag, schema=None):
        n = user.split("=== ATTACK LINES ===", 1)[1].count("\n[L") if "=== ATTACK LINES ===" in user else 0
        asked.append((tag, n))
        if "=== ATT&CK TECHNIQUES ===" in user:
            if not tag.endswith(("_h0", "_h1")):
                return L.LLMResult('{"conclusions": [{"technique": "' + " " * 50, "", 100, 2600, True, "repetition")
            return L.LLMResult(json.dumps({"conclusions": [{"technique": "T1197", "lines": ["L1"], "reason": "r"}]}),
                               "", 100, 50, False, "stop")
        return L.LLMResult(json.dumps({"checks": [{"technique": "T1197", "verdict": "shown", "sub_technique": "none",
                                                   "reason": "r"}]}), "", 100, 50, False, "stop")
    import conclude_v2 as C2
    L.LLMClient.complete = complete
    try:
        rc = C2.main([str(PROFILES / "gemma.toml"), str(d)])
    finally:
        L.LLMClient.formatter = orig_fmt
    c = json.load(open(d / "conclusions_v2.json"))
    first = [t for t, n in asked if t.startswith("s_") and not t.endswith(("_h0", "_h1"))]
    halves = [t for t, n in asked if t.endswith(("_h0", "_h1"))]
    big = [t for t, n in asked if t.startswith("s_") and not t.endswith(("_h0", "_h1")) and n > 1]
    check(rc == 0 and len(halves) == 2 * len(big) and halves, f"{len(first)} failed selects, {len(halves)} half requests")
    check({x["technique"] for x in c["conclusions"]} == {"T1197"}, "the halves' answers are used")
    check(any(r["why"] == "cut_off" for r in c.get("failed", [])), "the cut-off answer is recorded")


def test_conclude_groups_by_process_tree(check):
    """Conclusion groups follow the process tree (actor, parent, created process), not access targets."""
    import conclude_v2 as C2
    evs = [_ev(1, 700, {"ParentProcessId": "600"}), _ev(2, 600), _ev(3, 800, {"TargetProcessId": "500"}),
           _ev(4, 900, {"TargetProcessId": "500"}), _ev(5, 650, {"NewProcessId": "600"})]
    byid = {e.id: e for e in evs}
    g = C2.lineage_groups([1, 2, 3, 4, 5], byid)
    check(sorted(map(sorted, g)) == [[1, 2, 5], [3], [4]], f"groups {sorted(map(sorted, g))}: 800 and 900 share only a target")


def test_reference_lines_shortened_to_fit(check):
    """A context/reference line may be shortened (marked) to make room; a judged line is never shortened."""
    ctx = _ev(1, 600, {"CommandLine": "x" * 6000})
    judged = _ev(2, 700, {"ParentProcessId": "600", "Payload": "y" * 5000})
    byid = {1: ctx, 2: judged}
    req = V.Request("H1|pid=700", 1, "title", [2], [1])
    tokens = lambda r: len(I.render(r, byid, "src", "fmt", "", context_position="before")) // 4   # stub: 4 chars/token
    before = tokens(req)
    I.shorten_to_fit(req, [1], byid, tokens, budget=before - 1000)
    after = I.render(req, byid, "src", "fmt", "", context_position="before")
    check(tokens(req) <= before - 1000, f"prompt {before} -> {tokens(req)} <= {before - 1000}")
    check(judged.view in after and "y" * 5000 in after, "judged line shown whole")
    check(I.SHORT_MARK.search(after) is not None and "x" * 6000 not in after and "x" * 300 in after,
          "context line shortened, head kept, marked")
    sub = I.sub_request(req, [2])
    check(getattr(sub, "shortened", None) == req.shortened, "re-ask sub-request keeps the shortened context")
    req2 = V.Request("H1|pid=700", 1, "title", [2], [1])
    I.shorten_to_fit(req2, [1], byid, tokens, budget=10)
    check(len(req2.shortened[1]) >= I.SHORT_MIN_CHARS, "never below SHORT_MIN_CHARS (prompt may stay over: the client refuses it)")


def test_select_schema_constrains_ids(check):
    """The select answer's technique must look like an ATT&CK ID (same pattern as hdf.output_schemas): a free string
    let Gemma write '": "' and loop on whitespace (run 1, 12 of 37 conclusion requests). The cache key carries the
    schema, so an answer given under another schema is never reused."""
    import re as _re
    import conclude_v2 as C2
    s = C2.select_schema()
    pat = s["properties"]["conclusions"]["items"]["properties"]["technique"].get("pattern", "")
    check(bool(pat) and _re.fullmatch(pat.strip("^$"), "T1003.001") and _re.fullmatch(pat.strip("^$"), "T1059")
          and not _re.fullmatch(pat.strip("^$"), '": "'), f"technique pattern {pat!r}")
    check(C2.cache_key("m", "fp", "s_01", "u", s) != C2.cache_key("m", "fp", "s_01", "u", C1_schema()),
          "cache key depends on the schema")


def C1_schema():
    import conclude
    return conclude.schema()


TESTS = [test_lsass_dev_classes, test_unbound_attack_kept, test_unbound_normal_still_missing, test_any_attack_wins,
         test_unbound_counted_separately, test_profiles_share_common_part, test_context_after,
         test_cache_key_includes_profile, test_harness_unknown_key, test_hit_limit_reported,
         test_recursive_flip, test_linked_process_rechecked, test_recursion_stops, test_only_new_evidence_rechecked,
         test_conclusion_grounded, test_technique_normalised, test_truth_from_metadata, test_technique_scoring,
         test_prompt_has_no_technique_hints, test_catalog_from_stix, test_catalog_same_for_every_run,
         test_select_prompt_fits, test_verify_rejects_not_shown, test_sub_technique_refined, test_verify_unanswered_kept,
         test_dynamic_output_budget, test_runner_uses_dynamic_output, test_views_restored,
         test_variable_packing, test_reference_lines_shortened_to_fit, test_all_datasets_fit,
         test_conclude_fits_long_lines, test_conclude_retries_failed_request, test_conclude_groups_by_process_tree,
         test_select_schema_constrains_ids]


def main():
    ok = True
    names = sys.argv[1:]

    def check(cond, msg):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + msg)
        ok &= bool(cond)

    argv0 = list(sys.argv)
    try:
        if not names or "h_checks" in names:
            h_checks(check)
        for t in TESTS:
            if names and t.__name__ not in names:
                continue
            try:
                t(check)
            except Exception as e:  # a crashing test is a failing test
                check(False, f"{t.__name__}: {type(e).__name__}: {e}")
            sys.argv = list(argv0)
    finally:
        shutil.rmtree(OUT, ignore_errors=True)
    print("ALL PASS" if ok else "SOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
