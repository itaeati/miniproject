"""Experiment I scoring (copy of exp_h/scripts/score_h.py; data, labels and samples are read from
experiment H, read-only, via H_DATA; a sample in exp_i/samples overrides H_DATA/samples).
Experiment H scoring (evaluation only, offline). Labels come from labels/<dataset>.json
(scripts/label.py); the judged lines from samples/<dataset>.json.

Classes of a judged line:
  attack        acting process is an attack process, or the line holds a metadata artifact
  benign_aw     unlabelled, inside a window drawn around an attack line
  benign_bw     unlabelled, inside a window drawn around a benign line (or a fully judged dataset)
  excluded      ambiguous_target_only or near_unattributed (reported, not scored)
Primary: recall = attack lines judged "attack" / attack lines (no_verdict counts as a miss);
FP rate = benign lines (aw + bw) judged "attack" / benign lines. Secondary: FP rate per window kind.
Unlabelled lines next to an attack may be its indirect effects (e.g. a service doing work for it),
so every benign line judged "attack" is listed for manual review.
usage: score_i.py RUNS_DIR   (runs/<model>/<dataset>; writes scores/summary.json and prints a table)
"""
import glob
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path

H = Path(__file__).resolve().parent.parent            # exp_i: runs/, scores/
H_DATA = Path("/home/ubuntu/forensics-option-a/proposals/2026-10-10/exp_h")   # data/, labels/, samples/ (read-only)


def sample_path(dataset: str) -> Path:
    own = H / "samples" / f"{dataset}.json"
    return own if own.exists() else H_DATA / "samples" / f"{dataset}.json"


def classes(dataset: str) -> dict[int, str]:
    L = json.load(open(H_DATA / "labels" / f"{dataset}.json"))
    S = json.load(open(sample_path(dataset)))
    att = {int(k) for k in L["labels"]}
    excl = {int(k) for k in L["near_unattributed"]} | set(L["ambiguous_target_only"])
    db = sqlite3.connect(f"file:{H_DATA / 'data' / dataset / 'evidence.db'}?mode=ro", uri=True)
    order = [r[0] for r in db.execute("select id from events order by ts_epoch, id")]
    in_aw = {order[i] for w in S["windows"] if w["kind"] == "attack-centre" for i in range(w["start"], w["end"])}
    out = {}
    for i in S["judged"]:
        out[i] = ("attack" if i in att else "excluded" if i in excl else "benign_aw" if i in in_aw else "benign_bw")
    return out


EVAL = Path("/home/ubuntu/forensics-option-a/data/eval")   # dataset metadata (raw/*.yaml attack_mappings)


def technique_truth(dataset: str) -> set[str]:
    """ATT&CK IDs from the dataset metadata: technique (+ "." + sub-technique when given)."""
    import yaml
    out = set()
    for p in sorted((EVAL / dataset / "raw").glob("*.yaml")):
        for m in (yaml.safe_load(open(p)) or {}).get("attack_mappings") or []:
            t = str(m.get("technique") or "").strip().upper()
            sub = str(m.get("sub-technique") or "").strip()
            if re.fullmatch(r"T\d{4}", t):
                out.add(f"{t}.{int(sub):03d}" if sub.isdigit() else t)
    return out


def technique_score(conclusions: list[dict], truth: set[str], cls: dict[int, str]) -> dict:
    """exact: a true ID was concluded; parent: only the parent technique matched (no exact match);
    extra: concluded IDs that are not true; evidence_recall: share of attack-labelled events among the
    events cited by the conclusions that name a true ID."""
    got = {c["technique"] for c in conclusions}
    exact = bool(got & truth)
    parent = not exact and bool({g.split(".")[0] for g in got} & {t.split(".")[0] for t in truth})
    cited = {int(i) for c in conclusions if c["technique"] in truth for i in c["events"]}
    return {"truth": sorted(truth), "concluded": sorted(got), "exact": exact, "parent": parent,
            "extra": len(got - truth),
            "evidence_recall": rate(sum(1 for i in cited if cls.get(i) == "attack"), len(cited)) if cited else None}


def rate(num, den):
    return round(num / den, 3) if den else None


def score_run(run: Path, dataset: str, conclusions_file: str | None = None) -> dict:
    """conclusions_file: default conclusions_v2.json (catalog + verify) when present, else conclusions.json (v1)."""
    cls = classes(dataset)
    res = {"dataset": dataset, "run": str(run), "classes": dict(Counter(cls.values()))}
    if not (run / "verdicts.json").exists():
        return {**res, "status": "missing"}
    for name, f in (("pass1", "pass1.json"), ("final", "verdicts.json")):
        if not (run / f).exists():
            continue
        raw = {int(k): x for k, x in json.load(open(run / f)).items()}
        v = {k: x["verdict"] for k, x in raw.items()}
        unbound = {k for k, x in raw.items() if x["verdict"] == "attack" and x.get("bound", True) is False}
        c = {k: Counter(v.get(i, "absent") for i, ck in cls.items() if ck == k)
             for k in ("attack", "benign_aw", "benign_bw", "excluded")}
        ben = c["benign_aw"] + c["benign_bw"]
        res[name] = {"counts": {k: dict(x) for k, x in c.items()},
                     "recall": rate(c["attack"]["attack"], sum(c["attack"].values())),
                     "fp_rate": rate(ben["attack"], sum(ben.values())),
                     "fp_rate_attack_windows": rate(c["benign_aw"]["attack"], sum(c["benign_aw"].values())),
                     "fp_rate_benign_windows": rate(c["benign_bw"]["attack"], sum(c["benign_bw"].values())),
                     "no_verdict": sum(1 for x in v.values() if x == "no_verdict"),
                     # attack verdicts whose quote never bound them to the line (counted in recall and FP above)
                     "attack_unbound": sum(1 for i in cls if i in unbound),
                     "recall_unbound": sum(1 for i, ck in cls.items() if ck == "attack" and i in unbound),
                     "fp_unbound": sum(1 for i, ck in cls.items() if ck.startswith("benign") and i in unbound)}
    reqs = [json.load(open(p)) for p in glob.glob(str(run / "results" / "*.json"))]
    res["requests"] = len(reqs)
    res["gen_seconds"] = round(sum(q.get("seconds", 0) for q in reqs))
    res["finish"] = dict(Counter(q.get("finish") for q in reqs))
    res["hit_limit"] = sum(1 for q in reqs if q.get("hit_limit") is True)
    res["rejected_quotes"] = sum(len(q.get("rejected", [])) for q in reqs)
    res["max_prompt_tokens"] = max((q.get("prompt_tokens", 0) for q in reqs), default=0)
    cf = conclusions_file or next((f for f in ("conclusions_v2.json", "conclusions.json") if (run / f).exists()), None)
    if cf and (run / cf).exists():
        con = json.load(open(run / cf))
        res["techniques"] = technique_score(con["conclusions"], technique_truth(dataset), cls)
        res["techniques"]["rejected"] = len(con.get("rejected", []))
        res["techniques"]["file"] = cf
        if "selected" in con:   # v2: before the description check
            res["techniques_selected"] = technique_score(con["selected"], technique_truth(dataset), cls)
    fin = json.load(open(run / "verdicts.json"))
    res["missed_attack"] = [{"event": i, "verdict": fin.get(str(i), {}).get("verdict", "absent"),
                             "reason": fin.get(str(i), {}).get("reason", "")[:160]}
                            for i, k in sorted(cls.items()) if k == "attack" and fin.get(str(i), {}).get("verdict") != "attack"]
    res["false_positives"] = [{"event": i, "window": k, "reason": fin.get(str(i), {}).get("reason", "")[:160]}
                              for i, k in sorted(cls.items()) if k.startswith("benign") and fin.get(str(i), {}).get("verdict") == "attack"]
    return {**res, "status": "ok"}


def main():
    runs = Path(sys.argv[1]) if len(sys.argv) > 1 else H / "runs"
    rows = []
    for model_dir in sorted(p for p in runs.iterdir() if p.is_dir()):
        for ds_dir in sorted(p for p in model_dir.iterdir() if p.is_dir()):
            rows.append({"model": model_dir.name, **score_run(ds_dir, ds_dir.name)})
    summary = {}
    for m in sorted({r["model"] for r in rows}):
        ok = [r for r in rows if r["model"] == m and r["status"] == "ok"]
        tot = lambda cls, v: sum(r["final"]["counts"][c].get(v, 0) for r in ok for c in cls)
        alls = lambda cls: sum(sum(r["final"]["counts"][c].values()) for r in ok for c in cls)
        summary[m] = {"datasets": len(ok),
                      "macro_recall": rate(sum(r["final"]["recall"] or 0 for r in ok), len(ok)),
                      "macro_fp_rate": rate(sum(r["final"]["fp_rate"] or 0 for r in ok), len(ok)),
                      "pooled_recall": rate(tot(["attack"], "attack"), alls(["attack"])),
                      "pooled_fp_rate": rate(tot(["benign_aw", "benign_bw"], "attack"), alls(["benign_aw", "benign_bw"])),
                      "no_verdict": sum(r["final"]["no_verdict"] for r in ok),
                      "attack_unbound": sum(r["final"]["attack_unbound"] for r in ok),
                      "recall_unbound": sum(r["final"]["recall_unbound"] for r in ok),
                      "fp_unbound": sum(r["final"]["fp_unbound"] for r in ok),
                      "gen_seconds": sum(r["gen_seconds"] for r in ok),
                      "technique_exact": sum(1 for r in ok if r.get("techniques", {}).get("exact")),
                      "technique_parent_only": sum(1 for r in ok if r.get("techniques", {}).get("parent")),
                      "technique_extra": sum(r.get("techniques", {}).get("extra", 0) for r in ok)}
    out = H / "scores"
    out.mkdir(exist_ok=True)
    (out / "summary.json").write_text(json.dumps({"per_run": rows, "per_model": summary}, indent=1, ensure_ascii=False))
    print(f"{'model':14s} {'dataset':24s} {'recall p1/final':>16s} {'FP p1/final':>16s} {'FP aw/bw':>12s} {'nov':>4s} "
          f"{'unb(att/fp)':>11s} {'hitlim':>6s} {'req':>4s} {'gen_s':>6s}  techniques")
    for r in rows:
        if r["status"] != "ok":
            print(f"{r['model']:14s} {r['dataset']:24s} {r['status']}")
            continue
        p1, fi = r.get("pass1", {}), r["final"]
        tq = r.get("techniques")
        tech = (f"exact={tq['exact']} parent={tq['parent']} extra={tq['extra']} {tq['concluded']}" if tq else "-")
        print(f"{r['model']:14s} {r['dataset']:24s} {str(p1.get('recall')):>7s}/{str(fi['recall']):<8s} "
              f"{str(p1.get('fp_rate')):>7s}/{str(fi['fp_rate']):<8s} {str(fi['fp_rate_attack_windows']):>5s}/{str(fi['fp_rate_benign_windows']):<6s} "
              f"{fi['no_verdict']:4d} {fi['recall_unbound']:5d}/{fi['fp_unbound']:<5d} {r['hit_limit']:6d} {r['requests']:4d} {r['gen_seconds']:6d}  {tech}")
    for m, s in summary.items():
        print(m, json.dumps(s))


if __name__ == "__main__":
    main()
