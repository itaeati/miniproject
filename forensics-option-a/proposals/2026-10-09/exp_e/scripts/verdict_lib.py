"""Experiment E: per-line attack/normal verdicts on process-grouped evidence.

Grouping is mechanical (equal field values only); every judgement is made by the LLM.
Field-name lists are generic Windows/Sysmon schema names, not dataset values.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

# Process id of the process that performed the logged action, in priority order.
ACTOR_PID_FIELDS = ["SourceProcessId", "ProcessId", "ProcessID"]
# Process id of a process created by the logged action.
NEW_PID_FIELDS = ["NewProcessId"]
PARENT_PID_FIELDS = ["ParentProcessId"]
IMAGE_FIELDS = ["SourceImage", "Image", "ProcessName", "NewProcessName"]
CMD_FIELDS = ["CommandLine"]

SYSTEM = ("You are a digital forensics and incident response (DFIR) analyst. You reason only from the evidence "
          "given in the request. You never add hosts, accounts, addresses, file names, commands, tools, malware "
          "or threat-actor names that are not written in that evidence. You answer with a single JSON object.")

USER = """Evidence source {label} (format: {fmt}).
{constants}
{scope}
Context lines (how this process and its parent were started; for reference only, do not judge them):
{context}
=== LINES TO JUDGE ===
{lines}
=== END ===

Task: for EVERY line from L1 to L{n}, decide whether the logged event is part of an attack or normal activity.
Rules:
1. Answer "normal" only when the line, read together with the context lines and the other lines above, clearly shows legitimate activity.
2. If you are unsure, or the event could be a step of malicious activity, answer "attack".
3. Give exactly one verdict for each line. Do not skip, merge or group lines.
4. "reason": one short sentence naming the field values of that line you relied on.

Respond with one JSON object only:
{{"verdicts": [{{"line": "L<n>", "verdict": "attack|normal", "reason": "<short reason>"}}]}}"""


def parse_fields(full: str) -> dict:
    out = {}
    for part in full.split(" | "):
        if "=" in part:
            k, v = part.split("=", 1)
            out.setdefault(k.strip(), v.strip())
    return out


def norm_pid(v) -> int | None:
    if v is None:
        return None
    s = str(v).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def first(fields: dict, keys: list[str]):
    for k in keys:
        if fields.get(k):
            return fields[k]
    return None


@dataclass
class Ev:
    id: int
    src: int
    ts: str
    epoch: float
    host: str
    view: str
    fields: dict
    actor: int | None
    new: int | None
    parent: int | None


@dataclass
class Request:
    key: str            # group key
    part: int
    title: str          # process description shown to the model
    events: list[int]   # event ids to judge, in order (L1..Ln)
    context: list[int]  # event ids shown as context only
    tag: str = ""
    hash: str = ""
    lines: list[str] = field(default_factory=list)


def load_events(store) -> list[Ev]:
    evs = []
    for r in store.db.execute("SELECT id, src, ts, ts_epoch, host, full, view FROM events ORDER BY ts_epoch, id"):
        f = parse_fields(r["full"] or "")
        evs.append(Ev(r["id"], r["src"], r["ts"] or "", r["ts_epoch"] or 0.0, r["host"] or "", r["view"] or "",
                      f, norm_pid(first(f, ACTOR_PID_FIELDS)), norm_pid(first(f, NEW_PID_FIELDS)),
                      norm_pid(first(f, PARENT_PID_FIELDS))))
    return evs


def group_key(e: Ev) -> str:
    return f"{e.host}|pid={e.actor}" if e.actor is not None else f"{e.host}|src={e.src}|no-process"


def creation_records(evs: list[Ev], host: str, pid: int) -> list[Ev]:
    """Events that record the start of process `pid`: a creator event naming it as the new
    process, or the process's own event that carries its command line and parent."""
    out = [e for e in evs if e.host == host and (
        e.new == pid or (e.actor == pid and first(e.fields, CMD_FIELDS) and e.parent is not None))]
    return out[:3]


def parent_of(evs: list[Ev], host: str, pid: int) -> int | None:
    for e in evs:
        if e.host != host:
            continue
        if e.new == pid and e.actor is not None:
            return e.actor
        if e.actor == pid and e.parent is not None:
            return e.parent
    return None


def line_text(e: Ev, n: int) -> str:
    return f"[L{n}] {e.ts or 'no-timestamp'} host={e.host or '-'} :: {e.view}"


def build_requests(evs: list[Ev], max_lines: int, count=None, max_tokens: int = 0) -> list[Request]:
    """One group per acting process (time order). A group is split into requests of at most
    max_lines lines and, when `count` is given, at most max_tokens evidence tokens."""
    groups: dict[str, list[Ev]] = defaultdict(list)
    for e in evs:
        groups[group_key(e)].append(e)
    reqs = []
    for key, members in sorted(groups.items(), key=lambda kv: (kv[1][0].epoch, kv[1][0].id)):
        host, actor = members[0].host, members[0].actor
        ctx: list[int] = []
        if actor is None:
            title = "The lines below are events without a process id, in time order."
        else:
            images = Counter(first(m.fields, IMAGE_FIELDS) for m in members if first(m.fields, IMAGE_FIELDS))
            image = images.most_common(1)[0][0] if images else "(image not recorded)"
            title = (f"The lines below are all events whose acting process is process id {actor} "
                     f"({image}) on host {host or '-'}, in time order.")
            own = {m.id for m in members}
            ctx = [c.id for c in creation_records(evs, host, actor) if c.id not in own]
            par = parent_of(evs, host, actor)
            if par is not None:
                ctx += [c.id for c in creation_records(evs, host, par) if c.id not in own and c.id not in ctx]
        parts, cur, cur_tok = [], [], 0
        for m in members:
            t = count(line_text(m, len(cur) + 1)) + 1 if count else 0
            if cur and (len(cur) >= max_lines or (count and max_tokens and cur_tok + t > max_tokens)):
                parts.append(cur)
                cur, cur_tok = [], 0
            cur.append(m.id)
            cur_tok += t
        if cur:
            parts.append(cur)
        for part, ids in enumerate(parts, 1):
            reqs.append(Request(key, part, title, ids, ctx))
    return reqs


def render(req: Request, byid: dict[int, Ev], label: str, fmt: str, constants: str) -> str:
    lines = [line_text(byid[i], n) for n, i in enumerate(req.events, 1)]
    ctx = [f"[C{n}] {byid[i].ts or 'no-timestamp'} host={byid[i].host or '-'} :: {byid[i].view}"
           for n, i in enumerate(req.context, 1)] or ["(none in the evidence)"]
    req.lines = lines
    return USER.format(label=label, fmt=fmt, constants=constants, scope=req.title, context="\n".join(ctx),
                       lines="\n".join(lines), n=len(lines))


def schema(n: int) -> dict:
    item = {"type": "object", "additionalProperties": False, "required": ["line", "verdict", "reason"],
            "properties": {"line": {"type": "string", "pattern": "^L[0-9]+$"},
                           "verdict": {"enum": ["attack", "normal"]},
                           "reason": {"type": "string"}}}
    return {"type": "object", "additionalProperties": False, "required": ["verdicts"],
            "properties": {"verdicts": {"type": "array", "minItems": n, "maxItems": n, "items": item}}}


def parse_verdicts(obj: dict | None, n: int) -> dict[int, dict]:
    """Line number (1..n) -> {verdict, reason}; first valid answer per line wins."""
    out: dict[int, dict] = {}
    if not obj:
        return out
    for v in obj.get("verdicts") or []:
        if not isinstance(v, dict):
            continue
        m = re.fullmatch(r"L(\d+)", str(v.get("line", "")).strip())
        verdict = str(v.get("verdict", "")).strip().lower()
        if not m or verdict not in ("attack", "normal"):
            continue
        k = int(m.group(1))
        if 1 <= k <= n and k not in out:
            out[k] = {"verdict": verdict, "reason": str(v.get("reason", ""))[:400]}
    return out


def request_hash(model_name: str, text: str) -> str:
    return hashlib.sha256(f"exp-e-1|{model_name}|{text}".encode()).hexdigest()[:24]


def source_constants(store, src: int) -> tuple[str, str, str]:
    s = store.db.execute("SELECT label, fmt, constants FROM sources WHERE id=?", (src,)).fetchone()
    constants = json.loads(s["constants"] or "{}")
    txt = ""
    if constants:
        txt = ("Fields with the same value in every event of this source (omitted from lines): "
               + "; ".join(f"{k}={v}" for k, v in constants.items()))
        if len(txt) > 2000:
            txt = txt[:2000] + "…"
    return s["label"], s["fmt"], txt
