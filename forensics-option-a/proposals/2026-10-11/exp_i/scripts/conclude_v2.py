"""Experiment I final step, version 2: the model picks techniques from the ATT&CK catalog, then checks each
pick against its official description and picks the sub-technique.

v1 (conclude.py) let the model name IDs from memory and only checked that the ID exists, so a real but wrong
ID passed. v2 (user decision 2026-10-10):
  1. select (recall first: unsure -> name it): the prompt holds every current ATT&CK Enterprise PARENT technique ("<ID> <name>", 222 lines, from
     the local STIX bundle; the same block for every dataset) and the attack lines of one lineage group; the
     model names the techniques the cited lines show (same checks as v1: current ID, cited L labels exist).
     All 697 techniques with sub-techniques took 10.6K Gemma tokens (2,109 for the parents), leaving ~1K for
     the evidence, so sub-techniques are shown only in step 2. A sub-technique ID named here is accepted and
     checked under its parent.
  2. verify: for every selected parent, its tactics, its official description (links and citations removed,
     shortened) and its sub-techniques (ID, name, short description) are shown with the attack lines; the
     model answers "not_shown" only when the cited lines clearly do not show it (unsure -> "shown", as in the
     line verdicts) and names the sub-technique the lines show, or "none".
A select answer that is cut off (output limit, repetition, no JSON) is asked again in two halves (RETRY_DEPTH).
Groups follow the process tree only (acting process, parent, created process).
Final technique = the sub-technique from step 2 if it belongs to the parent, else the one named in step 1, else
the parent. Picks verified "shown", or not mentioned by the answer ("unverified"), are kept. Grouping and
splitting as v1. Labels are never read.

usage: conclude_v2.py PROFILE RUN_DIR [--dry-run]
writes RUN_DIR/conclusions_v2.json ({selected, conclusions, rejected, asked}); --dry-run writes
RUN_DIR/conclude_v2_dry.json (prompt sizes) without a server. exit: 0 ok, 1 LLM error, 5 memory guard, 2 input
"""
import argparse
import json
import re
import signal
import sys
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conclude as C1  # noqa: E402  (v1: lineage_groups, normalise_technique; sys.path set up there)
from hdf.attack import Attack  # noqa: E402
from hdf.config import load_config  # noqa: E402
from hdf.llm import (ContextBudgetError, LLMClient, LLMError, MemoryGuardError,  # noqa: E402
                     ServerManager, extract_json)
from hdf.store import EvidenceStore  # noqa: E402
from hdf.util import atomic_write_json, log, read_json, setup_logging  # noqa: E402

F, I, V = C1.F, C1.I, C1.V
SYSTEM_PROMPT = V.SYSTEM
DESC_CHARS = 900                 # official description shown in the verify step (cut at a sentence end)
SUB_DESC_CHARS = 240             # per sub-technique in the verify step
PROMPT_MARGIN = 200              # tokens kept free below max_input_tokens
CATALOG_CACHE = Path(__file__).resolve().parent.parent / "cache" / "attack_catalog.json"

SELECT = """MITRE ATT&CK Enterprise techniques (version {version}; sub-techniques are not listed), one per line as "<ID> <name>":
=== ATT&CK TECHNIQUES ===
{catalog}
=== END TECHNIQUES ===

{sources}
The lines below were judged to be part of an attack. They are events of processes that are linked to each other by process id, in time order.
=== ATTACK LINES ===
{lines}
=== END ===

Task: name every technique from the list above that these attack lines may show.
Rules:
1. Use only IDs from the list.
2. If you are unsure whether the lines show a technique, name it: every named technique is checked afterwards against its official definition.
3. "lines": the L labels of every line that shows it.
4. "reason": one short sentence naming the field values of the cited lines you relied on.
5. Answer with an empty list only when no line can be part of any technique in the list.

Respond with one JSON object only:
{{"conclusions": [{{"technique": "<ID from the list>", "lines": ["L<n>"], "reason": "<short reason>"}}]}}"""

VERIFY = """{sources}
The lines below were judged to be part of an attack, in time order.
=== ATTACK LINES ===
{lines}
=== END ===

Techniques named for these lines, each with the lines cited for it, its official ATT&CK description and its sub-techniques:
{items}

Task: for EVERY technique from K1 to K{n}, decide whether the cited lines show that technique as its description defines it, and which of its sub-techniques they show.
Rules:
1. "verdict": answer "not_shown" only when the cited lines clearly do not show what the description defines. If you are unsure, answer "shown".
2. "sub_technique": the ID of the sub-technique listed under that technique that the cited lines show, or "none" when the technique has no sub-techniques or the lines do not show which one.
3. Give exactly one answer for each technique.
4. "reason": one short sentence naming the field values of the cited lines you relied on.

Respond with one JSON object only:
{{"checks": [{{"technique": "<ID>", "verdict": "shown|not_shown", "sub_technique": "<sub-technique ID or none>", "reason": "<short reason>"}}]}}"""


# ---------------------------------------------------------------- catalog from the STIX bundle
def _clean(text: str, limit: int = DESC_CHARS) -> str:
    t = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"</?code>", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) <= limit:
        return t
    cut = t[:limit]
    end = max(cut.rfind(". "), cut.rfind(".) "))
    return (cut[:end + 1] if end > limit // 3 else cut[:limit - 1].rstrip() + "…")


def load_catalog(stix_path) -> dict:
    """{"version", "techniques": {ID: {name, tactics, description}}} for the current (not revoked, not
    deprecated) techniques; sub-technique names are "<parent name>: <name>". Cached next to the scripts."""
    stix_path = Path(stix_path)
    st = stix_path.stat()
    cached = read_json(CATALOG_CACHE)
    if cached and cached.get("v") == 2 and cached.get("stix_mtime") == st.st_mtime and cached.get("stix_size") == st.st_size:
        return cached
    attack = Attack.load(stix_path)
    bundle = json.load(open(stix_path, encoding="utf-8"))
    raw = {}
    for o in bundle["objects"]:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r["external_id"] for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
        if not ext or attack.canonical(ext) != ext:
            continue
        raw[ext] = {"name": o["name"], "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                                     if p.get("kill_chain_name") == "mitre-attack"],
                    "description": _clean(o.get("description", "")),
                    "short": _clean(o.get("description", ""), SUB_DESC_CHARS)}
    for k, v in raw.items():
        if "." in k and k.split(".")[0] in raw:
            v["name"] = f"{raw[k.split('.')[0]]['name']}: {v['name']}"
            raw[k.split(".")[0]].setdefault("subs", []).append(k)
    for v in raw.values():
        v["subs"] = sorted(v.get("subs", []))
    cat = {"v": 2, "version": attack.version, "stix_mtime": st.st_mtime, "stix_size": st.st_size,
           "techniques": dict(sorted(raw.items()))}
    CATALOG_CACHE.parent.mkdir(exist_ok=True)
    atomic_write_json(CATALOG_CACHE, cat)
    return cat


def catalog_block(cat: dict) -> str:
    """The parent techniques only (sub-techniques are shown in the verify step)."""
    return "\n".join(f"{k} {v['name']}" for k, v in cat["techniques"].items() if "." not in k)


# ---------------------------------------------------------------- prompts and checks
def _sources(chunk, byid, src_info) -> str:
    out = []
    for s in sorted({byid[i].src for i in chunk}):
        label, fmt, constants = src_info[s]
        out.append(f"Evidence source {label} (format: {fmt}).{(' ' + constants) if constants else ''}")
    return "\n".join(out)


def _lines(chunk, byid, only=None) -> str:
    """The chunk's lines with their L labels; `only` = the subset of event ids to show (labels unchanged)."""
    out = []
    for n, i in enumerate(chunk, 1):
        if only is not None and i not in only:
            continue
        ev = byid[i]
        if hasattr(ev, "compact_view") and ev.compact_view:
            out.append(f"[L{n}] {ev.ts or 'no-timestamp'} host={ev.host or '-'} :: {ev.compact_view}")
        else:
            out.append(V.line_text(ev, n))
    return "\n".join(out)


def export_intermediate_tracker(run_dir: Path, attack_ids: list[int], byid: dict) -> None:
    """Persist distilled forensic attributes to intermediate_reports/tracker_state.json."""
    inter_dir = run_dir / "intermediate_reports"
    inter_dir.mkdir(exist_ok=True)
    tracker_events = []
    for aid in attack_ids:
        e = byid[aid]
        pairs = [p.split("=", 1) for p in e.view.split(" | ") if "=" in p]
        fmap = {k.strip(): v.strip() for k, v in pairs}
        core_parts = []
        for k in ("EventID", "ProcessName", "NewProcessName", "ParentProcessName", "CommandLine", "SubjectUserName"):
            if k in fmap and fmap[k]:
                core_parts.append(f"{k}={fmap[k]}")
        msg = fmap.get("Message", "")
        if msg and "Token Elevation Type indicates" not in msg:
            core_parts.append(f"Message={msg[:160]}")
        compact_str = " | ".join(core_parts) if core_parts else e.view[:200]
        e.compact_view = compact_str
        tracker_events.append({"event_id": aid, "ts": e.ts, "host": e.host, "compact": compact_str})
    atomic_write_json(inter_dir / "tracker_state.json", {"count": len(tracker_events), "events": tracker_events})


# Process-tree links only (acting process, its parent, the process it created): processes that merely access the
# same target (TargetProcessId / SourceProcessId) are not the same activity and are kept apart here.
def lineage_groups(ids: list[int], byid) -> list[list[int]]:
    parent: dict = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in ids:
        e = byid[i]
        node = ("ev", i)
        find(node)
        for p in (e.actor, e.new, e.parent):
            if p is not None:
                parent[find(("p", e.host, p))] = find(node)
    comps: dict = {}
    for i in ids:
        comps.setdefault(find(("ev", i)), []).append(i)
    groups = [sorted(c, key=lambda i: (byid[i].epoch, i)) for c in comps.values()]
    return sorted(groups, key=lambda g: (byid[g[0]].epoch, g[0]))


RETRY_DEPTH = 2   # a cut-off select answer is asked again in halves, at most this many times


def render_select(chunk, byid, src_info, cat) -> str:
    return SELECT.format(version=cat["version"], catalog=catalog_block(cat), sources=_sources(chunk, byid, src_info),
                         lines=_lines(chunk, byid))


def render_verify(chunk, byid, src_info, cat, picks: list[dict], only=None) -> str:
    items = []
    for n, p in enumerate(picks, 1):
        t = cat["techniques"][p["technique"]]
        subs = [f"  {sid} {cat['techniques'][sid]['name']}: {cat['techniques'][sid]['short']}" for sid in t["subs"]]
        items.append(f"[K{n}] {p['technique']} {t['name']} (tactics: {', '.join(t['tactics']) or '-'})\n"
                     f"Cited lines: {', '.join(p['lines'])}\nDescription: {t['description']}\n"
                     f"Sub-techniques: " + ("\n" + "\n".join(subs) if subs else "(none)"))
    return VERIFY.format(sources=_sources(chunk, byid, src_info), lines=_lines(chunk, byid, only), items="\n\n".join(items),
                         n=len(picks))


TECHNIQUE_ID = "^T[0-9]{4}(\\.[0-9]{3})?$"   # same as hdf.output_schemas: a free string looped on whitespace (run 1)


def select_schema() -> dict:
    """v1's answer shape with the technique held to the ATT&CK ID form (the ID is still checked against the catalog)."""
    s = C1.schema()
    s["properties"]["conclusions"]["items"]["properties"]["technique"] = {"type": "string", "pattern": TECHNIQUE_ID}
    return s


def cache_key(model_name: str, fingerprint: str, tag: str, user: str, schema: dict) -> str:
    return V.request_hash(model_name, f"exp-i-conclude2|{fingerprint}|{tag}|{json.dumps(schema, sort_keys=True)}|{user}")


def verify_schema(ids: list[str], cat: dict) -> dict:
    subs = sorted({s for i in ids for s in cat["techniques"][i]["subs"]}) + ["none"]
    item = {"type": "object", "additionalProperties": False, "required": ["technique", "verdict", "sub_technique", "reason"],
            "properties": {"technique": {"enum": ids}, "verdict": {"enum": ["shown", "not_shown"]},
                           "sub_technique": {"enum": subs}, "reason": {"type": "string"}}}
    return {"type": "object", "additionalProperties": False, "required": ["checks"],
            "properties": {"checks": {"type": "array", "minItems": len(ids), "maxItems": len(ids), "items": item}}}


def merge_picks(ok: list[dict], chunk: list[int], cat: dict) -> list[dict]:
    """One pick per PARENT technique (cited lines united, first reason kept; a sub-technique named in the select
    step is kept as "named_sub"), with L labels for the verify prompt."""
    by = {}
    for c in ok:
        parent = c["technique"].split(".")[0]
        if parent not in cat["techniques"]:
            continue
        p = by.setdefault(parent, {**c, "technique": parent, "name": cat["techniques"][parent]["name"],
                                   "events": [], "named_sub": ""})
        p["events"] = sorted(set(p["events"]) | set(c["events"]))
        if "." in c["technique"] and not p["named_sub"]:
            p["named_sub"] = c["technique"]
    for p in by.values():
        p["lines"] = [f"L{chunk.index(i) + 1}" for i in p["events"]]
    return list(by.values())


def parse_checks(obj, picks: list[dict], attack, cat: dict) -> dict[str, dict]:
    """parent ID -> {verdict, sub ("" unless a listed sub-technique of THAT parent), sub_raw, reason}."""
    want = {p["technique"] for p in picks}
    out = {}
    for c in (obj or {}).get("checks") or []:
        if not isinstance(c, dict):
            continue
        tid, _ = C1.normalise_technique(c.get("technique"), attack)
        verdict = str(c.get("verdict", "")).strip().lower()
        if tid in want and tid not in out and verdict in ("shown", "not_shown"):
            sub_raw = str(c.get("sub_technique", "") or "")[:40]
            sub, _ = C1.normalise_technique(sub_raw, attack) if sub_raw.strip().lower() != "none" else (None, "")
            out[tid] = {"verdict": verdict, "sub": sub if sub in cat["techniques"][tid]["subs"] else "",
                        "sub_raw": sub_raw, "reason": str(c.get("reason", ""))[:400]}
    return out


def final_technique(pick: dict, check: dict | None, cat: dict) -> str:
    if check and check["sub"]:
        return check["sub"]
    if pick.get("named_sub") in cat["techniques"][pick["technique"]]["subs"]:
        return pick["named_sub"]
    return pick["technique"]


def pack_verify(picks, render_one, count, limit) -> list[list[dict]]:
    """Split the picks of one chunk into verify requests that each stay within `limit` prompt tokens."""
    packs, cur = [], []
    for p in picks:
        if cur and count(render_one(cur + [p])) > limit:
            packs.append(cur)
            cur = []
        cur.append(p)
    if cur:
        packs.append(cur)
    return packs


# ---------------------------------------------------------------- run
def _signal_to_exit(signum, _frame):
    raise SystemExit(128 + signum)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("profile"), ap.add_argument("run_dir")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    cfg = load_config(a.profile)
    run_dir = Path(a.run_dir).resolve()
    if not (run_dir / "verdicts.json").exists() or not (run_dir / "evidence.db").exists():
        print(f"missing verdicts.json or evidence.db in {run_dir}")
        return 2
    cfg.validate_for_run(need_server=not a.dry_run)
    model = cfg.model("triage")
    hz = I.harness_from(cfg)
    fingerprint = I.profile_fingerprint(cfg)
    attack = Attack.load(cfg.get("paths", "attack_stix"), cfg.get("paths", "attack_stix_url"))
    cat = load_catalog(cfg.get("paths", "attack_stix"))
    setup_logging(run_dir / "logs" / ("conclude_v2_dry.log" if a.dry_run else "conclude_v2.log"), False)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _signal_to_exit)
    verdicts = read_json(run_dir / "verdicts.json")
    store = EvidenceStore(run_dir / "evidence.db")
    evs = V.load_events(store)
    restored = I.restore_views(store, evs)      # long values the ingest cut are shown whole again
    byid = {e.id: e for e in evs}
    src_info = {s: V.source_constants(store, s) for s in {e.src for e in evs}}
    store.close()
    att = [int(k) for k, v in verdicts.items() if v["verdict"] == "attack"]
    export_intermediate_tracker(run_dir, att, byid)
    server = ServerManager(cfg, run_dir)
    client = LLMClient(cfg, server, run_dir / "audit" / "llm")
    fmt = client.formatter(model)
    # the catalog takes a fixed share of the prompt; the evidence gets the rest of the input limit (variable,
    # whole lines; a profile's evidence_tokens caps it when set)
    fixed = fmt.count(fmt.format(SYSTEM_PROMPT, SELECT.format(version=cat["version"], catalog=catalog_block(cat),
                                                               sources="", lines="")))
    budget = model.max_input_tokens - fixed - PROMPT_MARGIN
    if hz.evidence_tokens:
        budget = min(budget, hz.evidence_tokens)
    chunks = []
    for g in lineage_groups(att, byid):
        key = V.group_key(byid[g[0]])
        chunks += [(key, c) for c in F.split(g, byid, fmt.count, C1.NO_LINE_CAP, budget)]
    log.info("conclude v2: %d attack lines, %d request(s), catalog %d techniques (%d prompt tokens), evidence budget %d, "
             "profile %s (%s); %d cut line(s) restored, %d not restorable", len(att), len(chunks), len(cat["techniques"]),
             fixed, budget, Path(a.profile).stem, fingerprint, restored["restored"], restored["failed"])
    if a.dry_run:
        sizes = [fmt.count(fmt.format(SYSTEM_PROMPT, render_select(c, byid, src_info, cat))) for _, c in chunks]
        # worst single verify item: the largest chunk with the parent that has the most sub-techniques
        big = max((c for _, c in chunks), key=len, default=[])
        top = max((k for k in cat["techniques"] if "." not in k), key=lambda k: len(cat["techniques"][k]["subs"]))
        wp = [{"technique": top, "lines": ["L1"], "events": big[:1]}]
        wv = render_verify(big, byid, src_info, cat, wp)
        if fmt.count(fmt.format(SYSTEM_PROMPT, wv)) > model.max_input_tokens - PROMPT_MARGIN:
            wv = render_verify(big, byid, src_info, cat, wp, only=set(big[:1]))
        worst = fmt.count(fmt.format(SYSTEM_PROMPT, wv)) if big else 0
        atomic_write_json(run_dir / "conclude_v2_dry.json", {
            "model": model.name, "max_input_tokens": model.max_input_tokens, "catalog_tokens": fixed,
            "evidence_budget": budget, "requests": len(chunks), "max_select_tokens": max(sizes, default=0),
            "max_verify_tokens": worst, "worst_verify_parent": top})
        if chunks:
            (run_dir / "prompt_example_select.txt").write_text(fmt.format(SYSTEM_PROMPT, render_select(chunks[0][1], byid, src_info, cat)))
        return 0
    res_dir = run_dir / "conclude_v2_results"
    res_dir.mkdir(exist_ok=True)
    out = {"profile": str(Path(a.profile).resolve()), "fingerprint": fingerprint, "attack_version": cat["version"],
           "asked": [], "selected": [], "conclusions": [], "rejected": [], "failed": []}

    def ask(tag, user, schema, key, item_key, chunk):
        h = cache_key(model.name, fingerprint, tag, user, schema)
        cached = read_json(res_dir / f"{h}.json")
        if not (cached and cached.get("status") == "ok"):
            t0 = time.time()
            res = I.complete(client, model, context_tokens, SYSTEM_PROMPT, user, tag, schema=schema)
            cached = {"status": "ok", "tag": tag, "events": chunk, "answer": extract_json(res.text, key, item_key=item_key),
                      "hit_limit": res.hit_limit, "finish": res.finish, "prompt_tokens": res.prompt_tokens,
                      "max_output_tokens": max(model.max_output_tokens, context_tokens - res.prompt_tokens),
                      "output_tokens": res.output_tokens, "seconds": round(time.time() - t0, 1)}
            atomic_write_json(res_dir / f"{h}.json", cached)
        out["asked"].append({k: cached.get(k) for k in ("tag", "events", "finish", "hit_limit", "prompt_tokens",
                                                         "output_tokens", "seconds")} | {"group": key_of[tag]})
        return cached["answer"]

    key_of = {}
    context_tokens = int(cfg.get("budget", "context_tokens"))   # output limit = context - prompt (i_lib.complete)
    try:
        queue = [(key, chunk, f"s_{i:02d}", 0) for i, (key, chunk) in enumerate(chunks, 1)]
        n = 0
        while queue:
            key, chunk, tag, depth = queue.pop(0)
            n += 1
            key_of[tag] = key
            answer = ask(tag, render_select(chunk, byid, src_info, cat), select_schema(), "conclusions", "technique", chunk)
            last = out["asked"][-1]
            if answer is None or last.get("hit_limit"):
                # no usable answer (cut off / loop): never drop the lines - ask again in two halves
                out["failed"].append({"tag": tag, "group": key, "events": chunk, "why": "cut_off",
                                      "finish": last.get("finish")})
                if len(chunk) > 1 and depth < RETRY_DEPTH:
                    h = len(chunk) // 2
                    queue[:0] = [(key, chunk[:h], f"{tag}_h0", depth + 1), (key, chunk[h:], f"{tag}_h1", depth + 1)]
                    log.warning("conclude v2 %s (%d lines): answer cut off (%s) -> asking again in two halves", tag,
                                len(chunk), last.get("finish"))
                    continue
                log.warning("conclude v2 %s (%d lines): answer cut off (%s), no retry left", tag, len(chunk),
                            last.get("finish"))
                if answer is None:
                    continue
            ok, rej = C1.validate(answer, chunk, attack)
            out["rejected"] += [{**r, "group": key, "tag": tag} for r in rej]
            picks = merge_picks(ok, chunk, cat)
            out["selected"] += [{k: v for k, v in p.items() if k != "lines"} | {"group": key, "tag": tag} for p in picks]
            if not picks:
                log.info("conclude v2 %d/%d %s (%d lines): nothing selected; rejected %d", n, len(chunks), key,
                         len(chunk), len(rej))
                continue
            limit = model.max_input_tokens - PROMPT_MARGIN

            def shown(ps):
                """All chunk lines when they fit with these picks, else only the lines the picks cite; if even those
                do not fit, the cited lines are shortened (marked) - the select step showed them whole."""
                full_view = render_verify(chunk, byid, src_info, cat, ps)
                if fmt.count(fmt.format(SYSTEM_PROMPT, full_view)) <= limit:
                    return full_view
                only = {i for p in ps for i in p["events"]}
                holder = SimpleNamespace(events=[], shortened={})
                tok = lambda h: fmt.count(fmt.format(SYSTEM_PROMPT, render_verify(
                    chunk, I.Overlay(byid, h.shortened), src_info, cat, ps, only=only)))
                I.shorten_to_fit(holder, sorted(only), byid, tok, limit)
                return render_verify(chunk, I.Overlay(byid, holder.shortened), src_info, cat, ps, only=only)
            packs = pack_verify(picks, lambda ps: fmt.format(SYSTEM_PROMPT, shown(ps)), fmt.count, limit)
            checks = {}
            for m, pack in enumerate(packs):
                vtag = f"v_{n:02d}" if len(packs) == 1 else f"v_{n:02d}_{m}"
                key_of[vtag] = key
                checks.update(parse_checks(ask(vtag, shown(pack),
                                               verify_schema([p["technique"] for p in pack], cat), "checks", "technique",
                                               chunk), pack, attack, cat))
            for p in picks:
                c = checks.get(p["technique"])
                rec = {k: v for k, v in p.items() if k != "lines"} | {"group": key, "tag": tag}
                if c and c["verdict"] == "not_shown":
                    out["rejected"].append({**rec, "why": "not_shown", "verify_reason": c["reason"]})
                else:
                    tid = final_technique(p, c, cat)
                    out["conclusions"].append({**rec, "parent": p["technique"], "technique": tid,
                                               "name": cat["techniques"][tid]["name"],
                                               "verified": c["verdict"] if c else "unverified",
                                               "sub_answer": c["sub_raw"] if c else "",
                                               "verify_reason": c["reason"] if c else ""})
            log.info("conclude v2 %d/%d %s (%d lines): selected %s, verified %s; rejected %d", n, len(chunks), key,
                     len(chunk), [p["technique"] for p in picks], {k: (v["verdict"], v["sub"]) for k, v in checks.items()},
                     len(rej))
    except MemoryGuardError as e:
        log.error("conclude v2 stopped by memory guard: %s", e)
        return 5
    except (LLMError, ContextBudgetError) as e:
        log.error("conclude v2 stopped: %s", e)
        return 1
    finally:
        server.stop()
        if not a.dry_run:
            atomic_write_json(run_dir / "conclusions_v2.json", out)
    log.info("conclude v2 done: selected %s, final %s", sorted({c["technique"] for c in out["selected"]}),
             sorted({c["technique"] for c in out["conclusions"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
