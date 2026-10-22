"""Pick the lines to judge for one dataset (evaluation design; labels are never shown to a model).

Windows of WIN consecutive events (time order) around randomly chosen centres: K_ATT centres drawn
uniformly from attack-labelled events and K_BEN centres from unlabelled events (fixed seed, centres
whose window would overlap an earlier window are redrawn). Every event inside a window is judged,
so attack and benign lines keep their natural density; context lines still come from the whole
dataset. Datasets smaller than the total budget are judged in full.
usage: sample.py EVIDENCE_DB LABELS_JSON OUT_JSON [--win 25 --k-att 4 --k-ben 2 --seed 20261010]
"""
import argparse
import json
import random
import sqlite3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db"), ap.add_argument("labels"), ap.add_argument("out")
    ap.add_argument("--win", type=int, default=25)
    ap.add_argument("--k-att", type=int, default=4)
    ap.add_argument("--k-ben", type=int, default=2)
    ap.add_argument("--seed", type=int, default=20261010)
    a = ap.parse_args()
    L = json.load(open(a.labels))
    att = {int(k) for k in L["labels"]}
    near = {int(k) for k in L["near_unattributed"]} | set(L["ambiguous_target_only"])
    db = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    order = [r[0] for r in db.execute("select id from events order by ts_epoch, id")]
    pos = {e: i for i, e in enumerate(order)}
    budget = a.win * (a.k_att + a.k_ben)
    rng = random.Random(f"{a.seed}|{L['dataset']}")
    windows = []
    if len(order) <= budget:
        judged = list(order)
        windows.append({"kind": "all", "start": 0, "end": len(order)})
    else:
        taken = set()

        def pick(pool, kind, k):
            pool = sorted(pool)
            tries = 0
            while k and tries < 1000:
                tries += 1
                c = rng.choice(pool)
                s = max(0, min(pos[c] - a.win // 2, len(order) - a.win))
                rng_ids = set(range(s, s + a.win))
                if rng_ids & taken:
                    continue
                taken.update(rng_ids)
                windows.append({"kind": kind, "centre": c, "start": s, "end": s + a.win})
                k -= 1

        pick(att, "attack-centre", a.k_att)
        pick(set(order) - att - near, "benign-centre", a.k_ben)
        judged = sorted({order[i] for w in windows for i in range(w["start"], w["end"])}, key=pos.get)
    out = {"dataset": L["dataset"], "seed": a.seed, "win": a.win, "windows": windows, "judged": judged,
           "n": len(judged), "attack": sum(1 for e in judged if e in att),
           "excluded": sum(1 for e in judged if e in near),
           "benign": sum(1 for e in judged if e not in att and e not in near)}
    json.dump(out, open(a.out, "w"), indent=1)
    print(f"{L['dataset']:26s} judged={out['n']:4d} attack={out['attack']:4d} benign={out['benign']:4d} excluded={out['excluded']:3d} windows={len(windows)}")


if __name__ == "__main__":
    main()
