"""Experiment I common logic (same for every model profile).

merge_answers: a line counts as "attack" when ANY answer for it said attack, whether or not its quote
bound the answer to the line (recall first, 2026-10-10). An attack that never bound is kept with
bound=False / evidence="insufficient" so the reviewer sees it was not tied to the line.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
from dataclasses import dataclass

sys.path.insert(0, "/home/ubuntu/forensics-option-a/proposals/2026-10-09/exp_f/scripts")
import f_lib as F  # noqa: E402


def merge_answers(bound: dict[int, dict], rejected: dict[int, list[dict]], line_ids: list[int]) -> dict[int, dict]:
    """One result per line: verdict attack|normal|no_verdict, bound, reason, quote, answers (all answers)."""
    out = {}
    for i in line_ids:
        b = bound.get(i)
        rej = rejected.get(i, [])
        answers = ([{**b, "bound": True}] if b else []) + [{**r, "bound": False} for r in rej]
        if b and b["verdict"] == "attack":
            pick, is_bound = b, True
        elif any(r["verdict"] == "attack" for r in rej):
            pick, is_bound = next(r for r in rej if r["verdict"] == "attack"), False
        elif b:
            pick, is_bound = b, True
        else:
            out[i] = {"verdict": "no_verdict", "bound": False, "reason": "", "quote": "", "answers": answers}
            continue
        rec = {"verdict": pick["verdict"], "bound": is_bound, "reason": pick.get("reason", ""),
               "quote": pick.get("quote", ""), "answers": answers}
        if "round" in pick:
            rec["round"] = pick["round"]
        if not is_bound:
            rec["evidence"] = "insufficient"
        out[i] = rec
    return out


# ---------------------------------------------------------------- per-model profile: [harness] table
CONTEXT_HEADER = "Context lines (how this process and its parent were started; for reference only, do not judge them):\n"
SAME_REFS = "Lines of this same process that were judged to be part of an attack (for reference only, do not judge them):"
# used instead when some reference lines come from another process that the judged lines name by process id
LINKED_REFS = ("Lines of this process, or of a process that the lines to judge name by process id, that were judged "
               "to be part of an attack (for reference only, do not judge them):")


@dataclass(frozen=True)
class Harness:
    """Per-model harness values. Requests are packed variably (user direction 2026-10-10): whole lines only,
    as many as fit, so that prompt <= max_input_tokens and prompt + expected answer <= context_tokens, where the
    expected answer = output_base + output_per_line * lines (measured per model). max_lines / evidence_tokens
    are optional fixed caps (0 = none; experiment H used 20 / 4000)."""
    max_lines: int = 0
    evidence_tokens: int = 0
    recheck_attack_tokens: int = 2000   # reference attack lines shown in a re-check request (whole lines)
    recheck_attack_lines: int = 15
    context_position: str = "before"    # "before" | "after" the lines to judge
    max_rounds: int = 3
    output_base: int = 600              # expected answer tokens per request ...
    output_per_line: int = 100          # ... plus per judged line


def harness_from(cfg) -> Harness:
    """The profile's [harness] table; unknown keys, wrong types or a bad context_position raise ValueError."""
    raw = dict(cfg.get("harness", default={}) or {})
    fields = {f.name: f for f in dataclasses.fields(Harness)}
    unknown = sorted(set(raw) - set(fields))
    if unknown:
        raise ValueError(f"[harness]: unknown key(s) {unknown}; allowed {sorted(fields)}")
    for k, v in raw.items():
        want = type(getattr(Harness(), k))
        if type(v) is not want:
            raise ValueError(f"[harness] {k} = {v!r}: expected {want.__name__}")
    hz = Harness(**raw)
    if hz.context_position not in ("before", "after"):
        raise ValueError(f"[harness] context_position must be 'before' or 'after', got {hz.context_position!r}")
    return hz


def profile_fingerprint(cfg) -> str:
    """sha256[:12] of the decoding settings of the judging model plus the whole (resolved) [harness] table."""
    m = cfg.model("triage")
    key = {"model": {"name": m.name, "enable_thinking": m.enable_thinking, "sampling": m.sampling,
                     "structured_after": m.structured_after, "max_output_tokens": m.max_output_tokens},
           "output_budget": {"mode": "dynamic", "context_tokens": int(cfg.get("budget", "context_tokens"))},
           "repetition": {"window_chars": cfg.get("server", "repetition_window_chars"),
                          "max_ratio": cfg.get("server", "repetition_max_ratio")},
           "harness": dataclasses.asdict(harness_from(cfg))}
    return hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()[:12]


def render(req, byid, label, fmt, constants, attack_ids=None, context_position: str = "before") -> str:
    """f_lib.render; with context_position="after" the context block moves behind === END ===.
    Rules, task and format text are unchanged."""
    if context_position not in ("before", "after"):
        raise ValueError(f"context_position must be 'before' or 'after', got {context_position!r}")
    short = getattr(req, "shortened", None)
    if short:
        assert not set(short) & set(req.events), "a line to judge is never shortened"
        byid = Overlay(byid, short)
    user = F.render(req, byid, label, fmt, constants, attack_ids=attack_ids)
    if attack_ids:
        own = _proc(byid[req.events[0]])
        if any(_proc(byid[i]) != own for i in attack_ids):
            assert user.count(SAME_REFS) == 1
            user = user.replace(SAME_REFS, LINKED_REFS)
    if context_position == "before":
        return user
    start = user.index(CONTEXT_HEADER)
    stops = [user.index(m, start) for m in (SAME_REFS, LINKED_REFS, "=== LINES TO JUDGE ===") if m in user[start:]]
    stop = min(stops)
    block = user[start:stop]
    rest = user[:start] + user[stop:]
    end = rest.index("=== END ===\n") + len("=== END ===\n")
    return rest[:end] + block + rest[end:]


# ---------------------------------------------------------------- recursive re-check
# Generic Windows/Sysmon field names of a process an event points at (not dataset values).
LINK_PID_FIELDS = ["TargetProcessId", "SourceProcessId"]


def _proc(e) -> tuple[str, int] | None:
    return (e.host, e.actor) if e.actor is not None else None


def linked_pids(e) -> set[tuple[str, int]]:
    """(host, pid) of every process the event refers to: actor, created process, parent, target/source process."""
    pids = {e.actor, e.new, e.parent} | {F.V.norm_pid(e.fields.get(k)) for k in LINK_PID_FIELDS}
    return {(e.host, p) for p in pids if p is not None}


def evidence_sets(verdicts, byid) -> dict[int, frozenset[int]]:
    """For every line judged normal: the attack lines of every process it refers to (its own included)."""
    att = {}
    for i, v in verdicts.items():
        p = _proc(byid[i])
        if v["verdict"] == "attack" and p is not None:
            att.setdefault(p, set()).add(i)
    out = {}
    for i, v in verdicts.items():
        if v["verdict"] != "normal":
            continue
        ev = set().union(*(att.get(p, set()) for p in linked_pids(byid[i])))
        if ev:
            out[i] = frozenset(ev)
    return out


def recheck_targets(reqs, verdicts, byid, seen: dict[int, frozenset[int]], count=None, hz: Harness = Harness(),
                    overhead_of=None, max_input: int = 0, context: int = 0):
    """Re-check requests [(V.Request of normal lines, reference attack ids)]: normal lines whose own process or a
    process they refer to has attack lines, skipping lines already re-checked with the same evidence set.
    Lines are asked within their own process group (its title and context), in time order, packed variably
    (pack; the reference lines take at most recheck_attack_tokens). overhead_of(request) = prompt tokens of the
    re-check template for that group without lines; count = token counter for one line."""
    ev = evidence_sets(verdicts, byid)
    groups, first_req = {}, {}
    for r in reqs:
        groups.setdefault(r.key, []).extend(r.events)
        first_req.setdefault(r.key, r)
    out = []
    for key, ids in groups.items():
        todo = [i for i in ids if i in ev and seen.get(i) != ev[i]]
        if not todo:
            continue
        r0 = first_req[key]
        oh = (overhead_of(r0) + hz.recheck_attack_tokens) if (overhead_of and count) else 0
        count_of = (lambda i: count(F.V.line_text(byid[i], 1)) + 1) if count else None
        for part, chunk in enumerate(pack(todo, count_of, oh, hz, max_input, context), 1):
            pool = sorted(set().union(*(ev[i] for i in chunk)))
            refs = F.pick_attack_refs(pool, chunk, byid, count, hz.recheck_attack_tokens, hz.recheck_attack_lines)
            out.append((sub_request(r0, chunk), refs))
    return out


# ---------------------------------------------------------------- dynamic output budget (common part)
def complete(client, model, context_tokens: int, system: str, user: str, tag: str, schema=None):
    """client.complete with the output limit set per request: everything the prompt leaves of the context
    (reasoning + answer), never less than the configured max_output_tokens. The input limit is unchanged
    (context - max_output_tokens), so every prompt still gets at least the configured output room."""
    fmt = client.formatter(model)
    n_in = fmt.count(fmt.format(system, user))
    out = max(model.max_output_tokens, context_tokens - n_in)
    return client.complete(dataclasses.replace(model, max_output_tokens=out), system, user, tag, schema=schema)


# ---------------------------------------------------------------- no cut log lines (common part)
import re  # noqa: E402

CUT_MARK = re.compile(r"…\[\+(\d+) chars\]")
VIEW_MAX_CHARS = 1500   # hdf view.max_value_chars used when the evidence DBs were built (default_config.toml)


def restore_views(store, evs) -> dict:
    """Undo the ingest's cut of long values in every event's view (hdf/ingest.py writes
    "<key>=<first 1500 chars>…[+N chars]"; the full record is kept in events.full). For each cut, the text
    "<key>=<those 1500 chars>" is located in the full record (newlines shown as " ↵ ", as in the view) and the
    value is extended by exactly the N characters the marker announced. Lines are then shown whole; the request
    splitting never cuts a line. Changes e.view in place; returns counts (failed = a cut that could not be located
    uniquely, left as it is)."""
    from hdf.ingest import NEWLINES
    rows = {r[0]: r[1] for r in store.db.execute("SELECT id, full FROM events WHERE view LIKE '%…[+%'")}
    stats = {"restored": 0, "failed": 0, "failed_ids": []}
    for e in evs:
        if e.id not in rows or not CUT_MARK.search(e.view):
            continue
        full = NEWLINES.sub(" ↵ ", rows[e.id] or "")
        out, pos, ok = [], 0, True
        for m in CUT_MARK.finditer(e.view):
            start = m.start() - VIEW_MAX_CHARS
            head = re.search(r"(?:^| \| )([^=|]+)=$", e.view[pos:start]) if start >= pos else None
            if not head:
                ok = False
                break
            needle = f"{head.group(1)}={e.view[start:m.start()]}"
            at = full.find(needle)
            if at < 0 or full.find(needle, at + 1) >= 0:
                ok = False
                break
            v0 = at + len(head.group(1)) + 1
            value = full[v0:v0 + VIEW_MAX_CHARS + int(m.group(1))]
            if len(value) != VIEW_MAX_CHARS + int(m.group(1)):
                ok = False
                break
            out.append(e.view[pos:start] + value)
            pos = m.end()
        if ok:
            e.view = "".join(out) + e.view[pos:]
            stats["restored"] += 1
        else:
            stats["failed"] += 1
            stats["failed_ids"].append(e.id)
    return stats


# ---------------------------------------------------------------- variable packing (common part)
def pack(ids: list[int], count_of, overhead: int, hz: Harness, max_input: int, context: int) -> list[list[int]]:
    """Greedy, in order, whole lines: a request takes the next line while overhead + line tokens <= max_input and
    overhead + line tokens + output_base + output_per_line * lines <= context (and the optional fixed caps hold).
    A line that does not fit even alone is asked alone (never cut). count_of None: only the fixed line cap."""
    out, cur, tok = [], [], 0
    for i in ids:
        t = count_of(i) if count_of else 0
        n = len(cur) + 1
        fits = (not hz.max_lines or n <= hz.max_lines)
        if count_of:
            fits = fits and overhead + tok + t <= max_input \
                and overhead + tok + t + hz.output_base + hz.output_per_line * n <= context \
                and (not hz.evidence_tokens or tok + t <= hz.evidence_tokens)
        if cur and not fits:
            out.append(cur)
            cur, tok = [], 0
        cur.append(i)
        tok += t
    if cur:
        out.append(cur)
    return out


# ---------------------------------------------------------------- reference lines shortened only when needed
SHORT_MARK = re.compile(r"…\[\+\d+ chars not shown\]")
SHORT_MIN_CHARS = 400


class Overlay:
    """byid with some events' view replaced (shortened reference lines); every other id passes through."""

    def __init__(self, byid, views: dict[int, str]):
        self.byid, self.views = byid, views

    def __getitem__(self, i):
        e = self.byid[i]
        return dataclasses.replace(e, view=self.views[i]) if i in self.views else e

    def __contains__(self, i):
        return i in self.byid


def sub_request(req, ids):
    """Same group request with other lines to judge; keeps the shortened reference lines."""
    r = F.V.Request(req.key, req.part, req.title, list(ids), req.context)
    if getattr(req, "shortened", None):
        r.shortened = dict(req.shortened)
    return r


def shorten_to_fit(req, candidates, byid, tokens_fn, budget: int) -> int:
    """Shorten reference lines (context / attack-reference ids in `candidates`, never a line to judge), longest
    first, keeping the head and marking the rest "…[+N chars not shown]", until tokens_fn(req) <= budget or no
    line can be shortened below SHORT_MIN_CHARS. Stores the views in req.shortened; returns tokens_fn(req)."""
    cand = [i for i in dict.fromkeys(candidates) if i not in set(req.events)]
    req.shortened = dict(getattr(req, "shortened", None) or {})
    t = tokens_fn(req)
    while t > budget:
        cur = {i: req.shortened.get(i, byid[i].view) for i in cand}
        heads = {i: (len(SHORT_MARK.sub("", v)) if SHORT_MARK.search(v) else len(v)) for i, v in cur.items()}
        i = max((i for i in cand if heads[i] > SHORT_MIN_CHARS), key=lambda i: heads[i], default=None)
        if i is None:
            break
        full = byid[i].view
        keep = max(SHORT_MIN_CHARS, int(heads[i] * 0.6))
        req.shortened[i] = full[:keep] + f"…[+{len(full) - keep} chars not shown]"
        t = tokens_fn(req)
    return t
