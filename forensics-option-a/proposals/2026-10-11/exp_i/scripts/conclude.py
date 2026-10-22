"""Experiment I final step: which attack happened, from the lines judged "attack" (bound or not).

Attack lines are grouped by process lineage (connected through the processes they refer to: actor,
created process, parent, target/source process; i_lib.linked_pids), split in time order within the
profile's evidence_tokens, and the model names the ATT&CK techniques that the cited lines show. The
prompt carries no technique candidates or hints. Checks: the technique must be a current ATT&CK ID
(hdf.attack.Attack.canonical after normalising case and separator), every cited line must be an L label
of that request; anything else goes to "rejected". Labels are never read here.

usage: conclude.py PROFILE RUN_DIR   (reads RUN_DIR/verdicts.json + evidence.db, writes RUN_DIR/conclusions.json)
exit: 0 ok, 1 LLM error, 5 memory guard, 2 missing input
"""
import re
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, "/home/ubuntu/forensics-option-a")
sys.path.insert(0, "/home/ubuntu/forensics-option-a/proposals/2026-10-09/exp_f/scripts")
sys.path.insert(0, str(Path(__file__).resolve().parent))   # i_lib (python -I does not add it)
from hdf.attack import Attack  # noqa: E402
from hdf.config import load_config  # noqa: E402
from hdf.llm import (ContextBudgetError, LLMClient, LLMError, MemoryGuardError,  # noqa: E402
                     ServerManager, extract_json)
from hdf.store import EvidenceStore  # noqa: E402
from hdf.util import atomic_write_json, log, read_json, setup_logging  # noqa: E402
import f_lib as F  # noqa: E402
import i_lib as I  # noqa: E402

V = F.V
SYSTEM_PROMPT = V.SYSTEM
NO_LINE_CAP = 10 ** 6      # requests are cut by the token budget only
V1_EVIDENCE_TOKENS = 4000  # v1 baseline: experiment H evidence budget (Harness default became 0 = variable)

CONCLUDE = """{sources}
The lines below were judged to be part of an attack. They are events of processes that are linked to each other by process id, in time order.
=== ATTACK LINES ===
{lines}
=== END ===

Task: name the MITRE ATT&CK techniques that these lines show.
Rules:
1. Name a technique only when the lines you cite show it on their own. Do not name techniques that these lines do not show.
2. "technique": the ATT&CK technique ID; use the sub-technique ID when the cited lines show which one.
3. "lines": the L labels of every line that shows it.
4. "reason": one short sentence naming the field values of the cited lines you relied on.
5. If the lines show no technique, answer with an empty list.

Respond with one JSON object only:
{{"conclusions": [{{"technique": "<ATT&CK technique ID>", "lines": ["L<n>"], "reason": "<short reason>"}}]}}"""


def schema() -> dict:
    item = {"type": "object", "additionalProperties": False, "required": ["technique", "lines", "reason"],
            "properties": {"technique": {"type": "string"},
                           "lines": {"type": "array", "minItems": 1, "items": {"type": "string", "pattern": "^L[0-9]+$"}},
                           "reason": {"type": "string"}}}
    return {"type": "object", "additionalProperties": False, "required": ["conclusions"],
            "properties": {"conclusions": {"type": "array", "items": item}}}


_ID = re.compile(r"(?<![A-Z0-9])T\d{4}(?:[./]\d{3})?(?![0-9])")


def normalise_technique(raw, attack: Attack) -> tuple[str | None, str]:
    """(current ATT&CK ID, "") or (None, why). Accepts any case, '/' or '.' as the sub-technique separator and
    text around the ID (e.g. its name); a value naming two different IDs is rejected."""
    found = {m.replace("/", ".") for m in _ID.findall(str(raw or "").upper())}
    if not found:
        return None, "bad_format"
    if len(found) > 1:
        return None, "several_ids"
    c = attack.canonical(found.pop())
    return (c, "") if c else (None, "unknown_technique")


def lineage_groups(ids: list[int], byid) -> list[list[int]]:
    """Connected components of attack lines that share a referred process (union-find over (host, pid))."""
    parent: dict = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in ids:
        nodes = [("ev", i)] + [("p",) + p for p in I.linked_pids(byid[i])]
        for n in nodes[1:]:
            parent[find(n)] = find(nodes[0])
        find(nodes[0])
    comps: dict = {}
    for i in ids:
        comps.setdefault(find(("ev", i)), []).append(i)
    groups = [sorted(c, key=lambda i: (byid[i].epoch, i)) for c in comps.values()]
    return sorted(groups, key=lambda g: (byid[g[0]].epoch, g[0]))


def render(chunk: list[int], byid, src_info) -> str:
    srcs = []
    for s in sorted({byid[i].src for i in chunk}):
        label, fmt, constants = src_info[s]
        srcs.append(f"Evidence source {label} (format: {fmt}).{(' ' + constants) if constants else ''}")
    lines = [V.line_text(byid[i], n) for n, i in enumerate(chunk, 1)]
    return CONCLUDE.format(sources="\n".join(srcs), lines="\n".join(lines))


def validate(obj, chunk: list[int], attack: Attack) -> tuple[list[dict], list[dict]]:
    ok, rejected = [], []
    for c in (obj or {}).get("conclusions") or []:
        if not isinstance(c, dict):
            continue
        rec = {"technique_raw": str(c.get("technique", ""))[:40], "lines": [str(x) for x in c.get("lines") or []][:50],
               "reason": str(c.get("reason", ""))[:400]}
        tid, why = normalise_technique(c.get("technique"), attack)
        if not tid:
            rejected.append({**rec, "why": why})
            continue
        nums = [re.fullmatch(r"L(\d+)", x.strip()) for x in rec["lines"]]
        if not nums or not all(m and 1 <= int(m.group(1)) <= len(chunk) for m in nums):
            rejected.append({**rec, "technique": tid, "why": "bad_line"})
            continue
        ok.append({"technique": tid, "name": attack.name(tid),
                   "events": sorted({chunk[int(m.group(1)) - 1] for m in nums}), "reason": rec["reason"]})
    return ok, rejected


def _signal_to_exit(signum, _frame):
    raise SystemExit(128 + signum)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print(__doc__)
        return 2
    cfg = load_config(argv[0])
    run_dir = Path(argv[1]).resolve()
    if not (run_dir / "verdicts.json").exists() or not (run_dir / "evidence.db").exists():
        print(f"missing verdicts.json or evidence.db in {run_dir}")
        return 2
    cfg.validate_for_run(need_server=True)
    model = cfg.model("triage")
    hz = I.harness_from(cfg)
    fingerprint = I.profile_fingerprint(cfg)
    attack = Attack.load(cfg.get("paths", "attack_stix"), cfg.get("paths", "attack_stix_url"))
    setup_logging(run_dir / "logs" / "conclude.log", False)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _signal_to_exit)
    verdicts = read_json(run_dir / "verdicts.json")
    store = EvidenceStore(run_dir / "evidence.db")
    evs = V.load_events(store)
    byid = {e.id: e for e in evs}
    src_info = {s: V.source_constants(store, s) for s in {e.src for e in evs}}
    store.close()
    att = [int(k) for k, v in verdicts.items() if v["verdict"] == "attack"]
    server = ServerManager(cfg, run_dir)
    client = LLMClient(cfg, server, run_dir / "audit" / "llm")
    fmt = client.formatter(model)
    res_dir = run_dir / "conclude_results"
    res_dir.mkdir(exist_ok=True)
    chunks = []
    for g in lineage_groups(att, byid):
        key = V.group_key(byid[g[0]])
        chunks += [(key, c) for c in F.split(g, byid, fmt.count, NO_LINE_CAP, hz.evidence_tokens or V1_EVIDENCE_TOKENS)]
    log.info("conclude: %d attack lines, %d request(s), profile %s (%s)", len(att), len(chunks), Path(argv[0]).stem,
             fingerprint)
    out = {"profile": str(Path(argv[0]).resolve()), "fingerprint": fingerprint, "attack_version": getattr(attack, "version", ""),
           "asked": [], "conclusions": [], "rejected": []}
    try:
        for n, (key, chunk) in enumerate(chunks, 1):
            user = render(chunk, byid, src_info)
            tag = f"c_{n:02d}"
            h = V.request_hash(model.name, f"exp-i-conclude|{fingerprint}|{tag}|{user}")
            cached = read_json(res_dir / f"{h}.json")
            if not (cached and cached.get("status") == "ok"):
                t0 = time.time()
                res = client.complete(model, SYSTEM_PROMPT, user, tag, schema=schema())
                obj = extract_json(res.text, "conclusions", item_key="technique")
                cached = {"status": "ok", "tag": tag, "group": key, "events": chunk, "answer": obj,
                          "hit_limit": res.hit_limit, "finish": res.finish, "prompt_tokens": res.prompt_tokens,
                          "output_tokens": res.output_tokens, "seconds": round(time.time() - t0, 1)}
                atomic_write_json(res_dir / f"{h}.json", cached)
            ok, rej = validate(cached["answer"], chunk, attack)
            out["asked"].append({"tag": tag, "group": key, "events": chunk, "finish": cached.get("finish"),
                                 "hit_limit": cached.get("hit_limit")})
            out["conclusions"] += [{**c, "group": key, "tag": tag} for c in ok]
            out["rejected"] += [{**r, "group": key, "tag": tag} for r in rej]
            log.info("conclude %d/%d %s (%d lines): %s; rejected %d", n, len(chunks), key, len(chunk),
                     sorted({c["technique"] for c in ok}), len(rej))
    except MemoryGuardError as e:
        log.error("conclude stopped by memory guard: %s", e)
        return 5
    except (LLMError, ContextBudgetError) as e:
        log.error("conclude stopped: %s", e)
        return 1
    finally:
        server.stop()
        atomic_write_json(run_dir / "conclusions.json", out)
    log.info("conclude done: techniques %s", sorted({c["technique"] for c in out["conclusions"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
