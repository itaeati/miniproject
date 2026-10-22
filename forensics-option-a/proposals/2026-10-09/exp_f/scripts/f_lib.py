"""Experiment F: experiment E plus (1) line binding and (2) same-process re-check.

(1) Every verdict carries "quote": text copied from the judged line. The quote is accepted
    when it occurs in that line and not in every line of the request. A verdict with a rejected
    quote counts as missing; the line is asked again with the other missing lines (round 1) and
    then alone (round 2), where the line cannot be confused with another.
(2) In every process group with at least one "attack" line, the lines judged "normal" are
    asked again, shown together with the raw text of that process's attack lines.
Grouping, context and limits are experiment E's (verdict_lib.py, imported unchanged).
"""
from __future__ import annotations

import re
import sys

sys.path.insert(0, "/home/ubuntu/forensics-option-a/proposals/2026-10-09/exp_e/scripts")
import verdict_lib as V  # noqa: E402

SYSTEM = V.SYSTEM
MIN_QUOTE_CHARS = 6

_RULES = """3. Give exactly one verdict for each line. Do not skip, merge or group lines.
4. "quote": copy, character for character, a part of THAT line that distinguishes it from the other lines to judge.
5. "reason": one short sentence naming the field values of that line you relied on."""

_FORMAT = """Respond with one JSON object only:
{{"verdicts": [{{"line": "L<n>", "quote": "<text copied from that line>", "verdict": "attack|normal", "reason": "<short reason>"}}]}}"""

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
1. An event is "attack" if it is a direct malicious action, OR if it is executed within an attack session / spawned process lineage (including routine system calls, DLL loading, handle management, or registry queries that support or maintain that malicious execution environment). If you are unsure whether an event supports the malicious activity, answer "attack".
2. Answer "normal" only when the line clearly belongs to an independent, legitimate background system process running outside any attack lineage.
""" + _RULES + "\n\n" + _FORMAT

RECHECK = """Evidence source {label} (format: {fmt}).
{constants}
{scope}
Context lines (how this process and its parent were started; for reference only, do not judge them):
{context}
Lines of this same process that were judged to be part of an attack (for reference only, do not judge them):
{attack}
=== LINES TO JUDGE ===
{lines}
=== END ===

Task: the lines from L1 to L{n} were first judged normal. Judge EVERY one of them again in the light of the attack lines above: does the logged event belong to that same malicious activity, as a step of it, a preparation for it, a support for it or a result of it?
Rules:
1. Treat any event executed by this process as "attack" if it supports, prepares, maintains, or results from the attack activity shown above, even if the individual API call appears benign in isolation. If you are unsure, answer "attack".
2. Answer "normal" only when the event is completely independent and provably unrelated to the attack context.
""" + _RULES + "\n\n" + _FORMAT


def body(e: V.Ev) -> str:
    """The text of a line as the model sees it, without the [Ln] label."""
    return f"{e.ts or 'no-timestamp'} host={e.host or '-'} :: {e.view}"


def norm(s: str) -> str:
    """Comparison form: line-break marks dropped, doubled backslashes collapsed (JSON over-escaping),
    whitespace collapsed, lower case."""
    s = str(s).replace("\u21b5", " ")
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return re.sub(r"\s+", " ", s).strip().lower()


MIN_FRAGMENT_CHARS = 3


def fragments(quote: str) -> list[str]:
    """A quote may join several parts of the line with '|' (fields that are not adjacent there)."""
    return [f for f in (norm(x) for x in str(quote).split("|")) if len(f) >= MIN_FRAGMENT_CHARS]


def render(req: V.Request, byid, label, fmt, constants, attack_ids: list[int] | None = None) -> str:
    lines = [V.line_text(byid[i], n) for n, i in enumerate(req.events, 1)]
    ctx = [f"[C{n}] {body(byid[i])}" for n, i in enumerate(req.context, 1)] or ["(none in the evidence)"]
    req.lines = lines
    common = dict(label=label, fmt=fmt, constants=constants, scope=req.title, context="\n".join(ctx),
                  lines="\n".join(lines), n=len(lines))
    if attack_ids is None:
        return USER.format(**common)
    att = [f"[A{n}] {body(byid[i])}" for n, i in enumerate(attack_ids, 1)]
    return RECHECK.format(attack="\n".join(att), **common)


def schema(n: int) -> dict:
    item = {"type": "object", "additionalProperties": False, "required": ["line", "quote", "verdict", "reason"],
            "properties": {"line": {"type": "string", "pattern": "^L[0-9]+$"},
                           "quote": {"type": "string"},
                           "verdict": {"enum": ["attack", "normal"]},
                           "reason": {"type": "string"}}}
    return {"type": "object", "additionalProperties": False, "required": ["verdicts"],
            "properties": {"verdicts": {"type": "array", "minItems": n, "maxItems": n, "items": item}}}


def quote_check(quote: str, k: int, bodies: list[str]) -> str:
    """'ok' / 'ok_shared' (accepted), or why the quote does not bind the verdict to line k (1-based).
    Every '|'-separated part of the quote must occur in line k. The parts may also occur together
    in some other lines ('ok_shared': repeated lines often differ only in a timestamp), but not in
    every line of the request: such a quote cannot tell line k from its neighbours, so a shifted
    answer would pass."""
    frags = fragments(quote)
    if not frags or max(len(f) for f in frags) < MIN_QUOTE_CHARS:
        return "too_short"
    own = norm(bodies[k - 1])
    if not all(f in own for f in frags):
        return "not_in_line"
    others = [norm(b) for j, b in enumerate(bodies, 1) if j != k]
    has = lambda o: all(f in o for f in frags)
    if not others or not any(has(o) for o in others):
        return "ok"
    if all(has(o) for o in others):
        # only acceptable when no quote could tell this line apart: its whole text occurs in every other line
        return "ok_shared" if all(own in o for o in others) else "in_every_line"
    return "ok_shared"


def parse_verdicts(obj: dict | None, bodies: list[str]) -> tuple[dict[int, dict], list[dict]]:
    """(line number -> {verdict, reason, quote}, rejected answers). First valid answer per line wins."""
    out, rejected = {}, []
    if not obj:
        return out, rejected
    n = len(bodies)
    for v in obj.get("verdicts") or []:
        if not isinstance(v, dict):
            continue
        m = re.fullmatch(r"L(\d+)", str(v.get("line", "")).strip())
        verdict = str(v.get("verdict", "")).strip().lower()
        if not m or verdict not in ("attack", "normal"):
            continue
        k = int(m.group(1))
        if not 1 <= k <= n or k in out:
            continue
        quote = str(v.get("quote", ""))
        why = quote_check(quote, k, bodies)
        rec = {"verdict": verdict, "reason": str(v.get("reason", ""))[:400], "quote": quote[:300]}
        if why in ("ok", "ok_shared"):
            out[k] = {**rec, "quote_shared": why == "ok_shared"}
        else:
            rejected.append({"line": k, "why": why, **rec})
    return out, rejected


def pick_attack_refs(attack_ids: list[int], target_ids: list[int], byid, count, max_tokens: int,
                     max_lines: int) -> list[int]:
    """Attack lines of the same process closest in time to the target lines, within the budget,
    returned in time order."""
    lo = min(byid[i].epoch for i in target_ids)
    hi = max(byid[i].epoch for i in target_ids)
    dist = lambda i: max(lo - byid[i].epoch, byid[i].epoch - hi, 0.0)
    chosen, tok = [], 0
    for i in sorted(attack_ids, key=lambda i: (dist(i), byid[i].epoch, i)):
        t = count(f"[A{len(chosen) + 1}] {body(byid[i])}") + 1 if count else 0
        if len(chosen) >= max_lines or (count and chosen and tok + t > max_tokens):
            break
        chosen.append(i)
        tok += t
    return sorted(chosen, key=lambda i: (byid[i].epoch, i))


def split(ids: list[int], byid, count, max_lines: int, max_tokens: int) -> list[list[int]]:
    parts, cur, tok = [], [], 0
    for i in ids:
        t = count(V.line_text(byid[i], len(cur) + 1)) + 1 if count else 0
        if cur and (len(cur) >= max_lines or (count and max_tokens and tok + t > max_tokens)):
            parts.append(cur)
            cur, tok = [], 0
        cur.append(i)
        tok += t
    if cur:
        parts.append(cur)
    return parts
