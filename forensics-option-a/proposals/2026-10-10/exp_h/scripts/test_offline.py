"""Offline checks for experiment H (no model server, fake LLM):
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
sys.path.insert(0, "/home/ubuntu/forensics-option-a")
sys.path.insert(0, str(HERE))
import hdf.llm as L  # noqa: E402
import run_h  # noqa: E402
import score_h  # noqa: E402
from run_h import F, V  # noqa: E402
from hdf.store import EvidenceStore  # noqa: E402

OUT = H / "test_runs"
CFG = str(H / "configs" / "gemma_p1.toml")
DATASETS = ["win_bitsadmin_download", "win_auditpol_disable"]


def bodies_of(user):
    part = user.split("=== LINES TO JUDGE ===\n", 1)[1].split("\n=== END ===", 1)[0]
    return [re.sub(r"^\[L\d+\] ", "", l) for l in part.split("\n")]


def context_of(user):
    part = user.split("for reference only, do not judge them):\n", 1)[1].split("\n=== LINES TO JUDGE", 1)[0]
    return [] if part.startswith("(none") else part.split("\n")


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
    sys.argv = ["run_h.py", CFG, str(H / "data" / ds / "evidence.db"), str(d), "--judge", str(H / "samples" / f"{ds}.json")]
    return run_h.main(), d


def main():
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + msg)
        ok &= bool(cond)

    body_class = {}
    full_bodies = {}
    for ds in DATASETS:
        tmp = OUT / "db_copy" / ds
        tmp.mkdir(parents=True, exist_ok=True)
        shutil.copy2(H / "data" / ds / "evidence.db", tmp / "evidence.db")   # never open the frozen file
        st = EvidenceStore(tmp / "evidence.db")
        evs = V.load_events(st)
        st.close()
        cls = score_h.classes(ds)
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
            S = json.load(open(H / "samples" / f"{ds}.json"))
            fin = json.load(open(d / "verdicts.json"))
            check(rc == 0 and sorted(int(k) for k in fin) == sorted(S["judged"]),
                  f"{pol.__name__} {ds}: rc={rc}, judged {len(fin)} == sample {S['n']}")
            r = score_h.score_run(d, ds)
            want = (1.0, 0.0) if pol is oracle else (1.0, 1.0)
            got = (r["final"]["recall"], r["final"]["fp_rate"])
            check(got == want, f"{pol.__name__} {ds}: recall/FP = {got}, expected {want}")
            if pol is oracle:
                judged_bodies = {b for _, bs, _, _ in seen for b in bs}
                ctx = [c for _, _, cs, _ in seen for c in cs]
                outside = [c for c in ctx if c.split("] ", 1)[1] not in judged_bodies]
                check(len(outside) > 0, f"{ds}: {len(outside)} context line(s) come from outside the sample")
    src = (HERE / "run_h.py").read_text()
    check("labels" not in src.replace("Labels are never read here", ""), "run_h.py never references label files")
    tpl = F.USER + F.RECHECK + F.SYSTEM
    words = ("bitsadmin", "auditpol", "ntdsutil", "schtasks", "fodhelper", "wsmprovhost", "mshta", "powershell",
             "lsass", "comsvcs", "rundll32", "WORKSTATION", "pedro", "wardog", "T1", ".exe", ".dll")
    bad = [w for w in words if w.lower() in tpl.lower()]
    check(not bad, f"templates free of dataset values: {bad}")
    shutil.rmtree(OUT, ignore_errors=True)
    print("ALL PASS" if ok else "SOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
