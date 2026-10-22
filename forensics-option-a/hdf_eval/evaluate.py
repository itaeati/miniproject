"""Validation harness: fetch datasets, build ground truth from official sources,
run the engine, and score technique-level detection.

  python3 -m hdf_eval list
  python3 -m hdf_eval fetch all|<name> ...
  python3 -m hdf_eval run <name> [--config hdf.toml] [--coverage budget --budget-tokens N]
  python3 -m hdf_eval score <run_dir> <name>
  python3 -m hdf_eval summary
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from hdf.attack import TECH_RE, Attack  # noqa: E402
from hdf.config import load_config  # noqa: E402

REGISTRY = Path(__file__).resolve().parent / "datasets.yaml"
DATA_DIR = ROOT / "data" / "eval"
UNOBSERVABLE_TACTICS = {"TA0042", "TA0043"}  # resource development, reconnaissance: not in victim logs


def registry() -> dict:
    with open(REGISTRY) as f:
        return yaml.safe_load(f)


def download(url: str, dest: Path) -> dict:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "hdf-eval"})
    with urllib.request.urlopen(req, timeout=600) as r, open(dest, "wb") as f:
        h = hashlib.sha256()
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            h.update(b)
            f.write(b)
    return {"url": url, "file": dest.name, "bytes": dest.stat().st_size, "sha256": h.hexdigest()}


def safe_unzip(zpath: Path, dest: Path) -> list[str]:
    out = []
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zpath) as z:
        for m in z.infolist():
            target = (dest / m.filename).resolve()
            if dest.resolve() not in target.parents:
                continue
            if m.is_dir():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(m) as src, open(target, "wb") as f:
                f.write(src.read())
            out.append(str(target.relative_to(dest)))
    return out


def fetch(name: str, attack: Attack) -> dict:
    reg = registry()
    spec = reg["datasets"][name]
    base = reg["base_url"]
    ddir = DATA_DIR / name
    raw, evidence = ddir / "raw", ddir / "evidence"
    manifest = {"name": name, "description": spec.get("description", ""), "fetched_at": datetime.now().isoformat(),
                "files": [], "ground_truth": None}
    links, gt = [], None
    if "otrf_metadata" in spec:
        meta_url = f"{base}/{spec['otrf_metadata']}"
        info = download(meta_url, raw / Path(spec["otrf_metadata"]).name)
        manifest["metadata"] = info
        meta = yaml.safe_load((raw / info["file"]).read_text())
        manifest["description"] = manifest["description"] or meta.get("title", "")
        types = {t.lower() for t in spec.get("file_types", ["host"])}
        links = [f["link"] for f in meta.get("files") or [] if str(f.get("type", "")).lower() in types]
        gt = gt_from_otrf(meta, attack, meta_url)
    else:
        links = [f"{base}/{p}" for p in spec["files"]]
        gtspec = spec["ground_truth"]
        plan = download(f"{base}/{gtspec['emulation_plan']}", raw / Path(gtspec["emulation_plan"]).name)
        gt = gt_from_plan(raw / plan["file"], int(gtspec["sheet"]), attack, plan["url"])
    good_dirs = []
    for url in links:
        dest = raw / url.rsplit("/", 1)[1]
        try:
            info = download(url, dest)
            good_dirs.append(url.rsplit("/", 1)[0])
        except urllib.error.HTTPError as e:
            # metadata sometimes differs in folder-name case from the repository; retry with a sibling folder
            info = None
            for d in good_dirs + [l.rsplit("/", 1)[0] for l in links if l != url]:
                alt = f"{d}/{url.rsplit('/', 1)[1]}"
                if alt == url:
                    continue
                try:
                    info = download(alt, dest)
                    info["note"] = f"metadata link {url} returned HTTP {e.code}; used {alt}"
                    break
                except urllib.error.HTTPError:
                    continue
            if info is None:
                manifest["files"].append({"url": url, "error": f"HTTP {e.code}"})
                print(f"  ! {url}: HTTP {e.code}")
                continue
        if zipfile.is_zipfile(dest):
            info["extracted"] = safe_unzip(dest, evidence / dest.stem)
        else:
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / dest.name).write_bytes(dest.read_bytes())
            info["extracted"] = [dest.name]
        manifest["files"].append(info)
    manifest["ground_truth"] = gt
    (ddir / "manifest.json").write_text(json.dumps(manifest, indent=1))
    ok = [f for f in manifest["files"] if "error" not in f]
    print(f"{name}: {len(ok)}/{len(manifest['files'])} files, GT {gt['techniques']}")
    return manifest


def gt_from_otrf(meta: dict, attack: Attack, source: str) -> dict:
    techs, dropped, unobservable = [], [], []
    for m in meta.get("attack_mappings") or []:
        t = str(m.get("technique") or "").strip()
        st = str(m.get("sub-technique") or "").strip()
        if not t:
            continue
        tid = f"{t}.{st.zfill(3)}" if st else t
        c = attack.canonical(tid)
        if not c:
            dropped.append(tid)
            continue
        if c not in techs:
            techs.append(c)
        if set(m.get("tactics") or []) and set(m.get("tactics") or []) <= UNOBSERVABLE_TACTICS:
            unobservable.append(c)
    return {"source": source, "techniques": techs, "dropped_ids": dropped, "unobservable": unobservable}


def gt_from_plan(xlsx: Path, sheet: int, attack: Attack, source: str) -> dict:
    import openpyxl
    wb = openpyxl.load_workbook(xlsx, read_only=True, data_only=True)
    ws = wb.worksheets[sheet - 1]
    rows = list(ws.iter_rows(values_only=True))
    head = [str(c or "").strip().lower() for c in rows[0]]
    i_step, i_desc = head.index("step"), head.index("description")
    raw_ids, steps = [], {}
    for r in rows[1:]:
        step = str(r[i_step] or "").strip()
        if not step or step == "0":
            continue
        ids = TECH_RE.findall(str(r[i_desc] or ""))
        steps[step] = ids
        raw_ids += ids
    techs, dropped, mapping = [], [], {}
    for t in dict.fromkeys(raw_ids):
        c = attack.canonical(t)
        mapping[t] = c
        if c is None:
            dropped.append(t)
        elif c not in techs:
            techs.append(c)
    return {"source": f"{source} (sheet {sheet})", "techniques": techs, "dropped_ids": dropped,
            "legacy_mapping": mapping, "steps": steps, "unobservable": []}


def parent(t: str) -> str:
    return t.split(".")[0]


def prf(pred: set, gt: set) -> dict:
    tp = len(pred & gt)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(gt) if gt else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": len(pred - gt), "fn": len(gt - pred), "precision": round(p, 3), "recall": round(r, 3),
            "f1": round(f, 3), "missed": sorted(gt - pred), "extra": sorted(pred - gt)}


def score(run_dir: Path, name: str) -> dict:
    manifest = json.loads((DATA_DIR / name / "manifest.json").read_text())
    gt = manifest["ground_truth"]
    rep = json.loads((run_dir / "report.json").read_text())
    ver = json.loads((run_dir / "verification.json").read_text()) if (run_dir / "verification.json").exists() else {}
    pred = {t["id"] for t in rep.get("techniques", [])}
    gt_all = set(gt["techniques"])
    gt_obs = gt_all - set(gt.get("unobservable", []))
    res = {
        "dataset": name, "run_dir": str(run_dir), "scored_at": datetime.now().isoformat(),
        "run_status": rep.get("status", "unknown"), "run_problems": rep.get("problems", []),
        "predicted": sorted(pred), "ground_truth": sorted(gt_all),
        "exact": prf(pred, gt_all), "parent_level": prf({parent(t) for t in pred}, {parent(t) for t in gt_all}),
        "exact_observable_gt": prf(pred, gt_obs),
        "conclusions": len(rep.get("conclusions", [])), "hypotheses": rep.get("hypotheses", {}),
        "findings": rep.get("findings"), "coverage": rep.get("coverage", {}),
        "rejected_claims": rep.get("audit", {}).get("rejected_claims", {}),
        "verification_ok": ver.get("ok"), "verification_violations": len(ver.get("violations", [])),
        "llm_calls": len(list((run_dir / "audit" / "llm").glob("*.json"))) if (run_dir / "audit" / "llm").exists() else 0,
    }
    (run_dir / "score.json").write_text(json.dumps(res, indent=1))
    return res


def cmd_run(args) -> int:
    name = args.name
    ev = DATA_DIR / name / "evidence"
    if not ev.exists():
        print(f"dataset {name} not fetched; run: python3 -m hdf_eval fetch {name}")
        return 2
    cfg = load_config(args.config)
    out = Path(cfg.get("paths", "work_dir")) / f"eval_{name}_{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    if args.out:
        out = Path(args.out)
    cmd = [sys.executable, str(ROOT / "hypothesis_drilldown_forensics.py"), "run", str(ev), "--out", str(out)]
    if args.config:
        cmd += ["--config", args.config]
    if args.coverage:
        cmd += ["--coverage", args.coverage]
    if args.budget_tokens:
        cmd += ["--budget-tokens", str(args.budget_tokens)]
    if args.allow_partial:
        cmd.append("--allow-partial")
    print(" ".join(cmd))
    rc = subprocess.call(cmd)
    if (out / "report.json").exists():
        res = score(out, name)
        print(json.dumps({k: res[k] for k in ("run_status", "run_problems", "predicted", "ground_truth", "exact",
                                               "parent_level", "verification_ok")}, indent=1))
    return rc


def cmd_summary(args) -> int:
    cfg = load_config(args.config)
    work = Path(cfg.get("paths", "work_dir"))
    latest = {}
    for s in sorted(work.glob("eval_*/score.json")):
        d = json.loads(s.read_text())
        latest[d["dataset"]] = d
    print(f"{'dataset':28s} {'GT':>3s} {'pred':>4s} {'P':>6s} {'R':>6s} {'F1':>6s} {'R(parent)':>9s} verify  run         coverage")
    for n, d in sorted(latest.items()):
        e, p, c = d["exact"], d["parent_level"], d["coverage"]
        cov = f"{c.get('patterns_read')}/{c.get('patterns_total')} patterns"
        print(f"{n:28s} {len(d['ground_truth']):3d} {len(d['predicted']):4d} {e['precision']:6.2f} {e['recall']:6.2f} "
              f"{e['f1']:6.2f} {p['recall']:9.2f} {'PASS' if d['verification_ok'] else 'FAIL':6s}  "
              f"{d.get('run_status', 'unknown'):10s}  {cov}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hdf_eval")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    f = sub.add_parser("fetch")
    f.add_argument("names", nargs="+")
    f.add_argument("--config")
    r = sub.add_parser("run")
    r.add_argument("name")
    r.add_argument("--config")
    r.add_argument("--out")
    r.add_argument("--coverage", choices=["full", "budget"])
    r.add_argument("--budget-tokens", type=int)
    r.add_argument("--allow-partial", action="store_true")
    s = sub.add_parser("score")
    s.add_argument("run_dir")
    s.add_argument("name")
    m = sub.add_parser("summary")
    m.add_argument("--config")
    args = ap.parse_args(argv)
    if args.cmd == "list":
        for n, d in registry()["datasets"].items():
            fetched = (DATA_DIR / n / "manifest.json").exists()
            print(f"{'*' if fetched else ' '} {n:28s} {d.get('description', d.get('otrf_metadata', ''))}")
        return 0
    if args.cmd == "fetch":
        cfg = load_config(args.config)
        attack = Attack.load(cfg.get("paths", "attack_stix"), cfg.get("paths", "attack_stix_url"))
        names = list(registry()["datasets"]) if args.names == ["all"] else args.names
        for n in names:
            try:
                fetch(n, attack)
            except Exception as e:
                print(f"{n}: FAILED {type(e).__name__}: {e}")
        return 0
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "score":
        print(json.dumps(score(Path(args.run_dir), args.name), indent=1))
        return 0
    if args.cmd == "summary":
        return cmd_summary(args)
    return 1
