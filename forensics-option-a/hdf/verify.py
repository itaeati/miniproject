"""Independent post-run verification of report.json / report.md.

Re-checks, from the evidence store alone, that every cited event exists, every
technique ID is a current ATT&CK ID, every conclusion statement and summary
sentence only contains values present in its cited events, and that no
threat-actor or software name appears in the report without evidence.
"""
from __future__ import annotations

import re
from pathlib import Path

from .attack import TECH_RE, Attack
from .grounding import Grounder, extract_artifacts
from .store import EvidenceStore
from .util import atomic_write_json, read_json

EV_RE = re.compile(r"\bE(\d+)\b")


def verify_run(run_dir: Path, attack: Attack) -> dict:
    run_dir = Path(run_dir)
    rep = read_json(run_dir / "report.json")
    md_path = run_dir / "report.md"
    if not rep or not md_path.exists():
        return {"ok": False, "violations": ["report.json or report.md missing"]}
    store = EvidenceStore(run_dir / "evidence.db")
    g = Grounder(attack)
    v: list[str] = []

    def hay(ids):
        return " ".join(store.norm_full(int(e)) for e in dict.fromkeys(ids))

    def exists(e) -> bool:
        return store.event(int(e)) is not None

    all_cited = set()
    for c in rep.get("conclusions", []):
        ids = c.get("evidence_events", [])
        if not ids:
            v.append(f"{c['id']}: conclusion without evidence events")
        for e in ids + c.get("motivating_events", []):
            if not exists(e):
                v.append(f"{c['id']}: cites missing event E{e}")
        all_cited.update(ids)
        h = hay(ids + c.get("motivating_events", []))
        ts = [ev.ts for ev in store.events(ids + c.get("motivating_events", [])) if ev.ts]
        gr = g.check_text(c.get("statement", ""), h, ts)
        if not gr.ok:
            v.append(f"{c['id']}: statement values not in cited events: {gr.missing}")
        for t in c.get("techniques", []):
            if attack.canonical(t["id"]) != t["id"]:
                v.append(f"{c['id']}: invalid or outdated technique {t['id']}")
        for k, vals in c.get("entities", {}).items():
            for val in vals:
                if not g.value_in(val, h):
                    v.append(f"{c['id']}: entity {val!r} not in cited events")
    for t in rep.get("techniques", []):
        if attack.canonical(t["id"]) != t["id"]:
            v.append(f"technique list: invalid {t['id']}")
    for s in rep.get("narrative", []):
        ids = s.get("events", [])
        if not ids or not all(exists(e) and e in all_cited for e in ids):
            v.append(f"summary sentence cites events outside the conclusions: {s.get('text', '')[:120]}")
            continue
        ts = [ev.ts for ev in store.events(ids) if ev.ts]
        gr = g.check_text(s.get("text", ""), hay(ids), ts)
        if not gr.ok:
            v.append(f"summary sentence values not in cited events {gr.missing}: {s.get('text', '')[:120]}")
    for k, vals in rep.get("entities", {}).items():
        h = hay(all_cited)
        for val in vals:
            if not g.value_in(val, h):
                v.append(f"entity {k}={val!r} not in any cited event")
    for t in rep.get("timeline", []):
        if t["event"] not in all_cited or not exists(t["event"]):
            v.append(f"timeline event E{t['event']} is not cited by a conclusion")

    # report.md: sections 2-5 may only contain values from cited events
    md = md_path.read_text(encoding="utf-8")
    body = md.split("## 2.", 1)[1].split("## 6.", 1)[0] if "## 2." in md else ""
    for m in EV_RE.finditer(body):
        if not exists(m.group(1)):
            v.append(f"report.md references missing event E{m.group(1)}")
    h_all = hay(all_cited | {e for c in rep.get("conclusions", []) for e in c.get("motivating_events", [])})
    ts_all = [ev.ts for ev in store.events(all_cited) if ev.ts]
    allowed_techs = {t["id"] for t in rep.get("techniques", [])}
    allowed_names = {t["name"].lower() for t in rep.get("techniques", [])}
    for line in body.splitlines():
        # undo markdown escaping and display truncation before extracting values
        text = re.sub(r"\bE\d+\b", "", line).replace("\\|", "|").replace("…", " ")
        for name in attack.named_actors(text) + attack.named_software(text):
            if not g.value_in(name, h_all) and name.lower() not in allowed_names:
                v.append(f"report.md names {name!r} without evidence")
        for kind, val in extract_artifacts(text):
            if kind in ("datetime", "time"):
                if not any(val.replace(" ", "T") in t or val in t for t in ts_all) and not g.value_in(val, h_all):
                    v.append(f"report.md time {val!r} not in cited events")
            elif not g.value_in(val, h_all):
                v.append(f"report.md value {val!r} not in cited events")
        for t in TECH_RE.findall(text):
            if t not in allowed_techs:
                v.append(f"report.md technique {t} not in the verified technique list")
    store.close()
    v = list(dict.fromkeys(v))
    result = {"ok": not v, "violations": v, "conclusions": len(rep.get("conclusions", [])),
              "cited_events": len(all_cited)}
    atomic_write_json(run_dir / "verification.json", result)
    with open(md_path, "a", encoding="utf-8") as f:
        f.write("## 7. Independent verification\n\n")
        if result["ok"]:
            f.write(f"PASS: {len(all_cited)} cited events exist; every value, time, technique ID and name in "
                    "sections 2-5 was found in the cited evidence.\n")
        else:
            f.write(f"FAIL: {len(v)} violation(s); see verification.json.\n")
    return result
