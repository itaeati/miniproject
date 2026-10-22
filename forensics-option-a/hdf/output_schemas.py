"""JSON schemas the model server enforces on each answer (structured output). They
fix only the shape of the answer, the same shape the prompts in prompts.py describe;
every value is still checked against the evidence afterwards.

No string carries maxLength: with a length limit the grammar refused backslash escapes
and Windows paths came out with '/' (measured 2026-10-07). Array limits only stop a
runaway list; they are well above what one request can ground."""
from __future__ import annotations

from .prompts import ENTITY_KEYS

_STR = {"type": "string"}
_TECHNIQUES = {"type": "array", "maxItems": 8, "items": {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"}}
_SEVERITY = {"enum": ["high", "medium", "low"]}


def _ids(prefixes: str, max_items: int, min_items: int = 0) -> dict:
    s = {"type": "array", "maxItems": max_items, "items": {"type": "string", "pattern": f"^[{prefixes}][0-9]+$"}}
    if min_items:
        s["minItems"] = min_items
    return s


def _entities() -> dict:
    return {"type": "object", "additionalProperties": False, "required": ENTITY_KEYS,
            "properties": {k: {"type": "array", "maxItems": 12, "items": _STR} for k in ENTITY_KEYS}}


def _obj(props: dict) -> dict:
    return {"type": "object", "additionalProperties": False, "required": list(props), "properties": props}


def _queries(max_items: int, min_items: int) -> dict:
    return {"type": "array", "minItems": min_items, "maxItems": max_items, "items": _obj({
        "purpose": _STR,
        "keywords": {"type": "array", "minItems": 1, "maxItems": 5, "items": _STR},
        "host": _STR, "time_from": _STR, "time_to": _STR})}


def findings() -> dict:
    """TRIAGE (phase 1)."""
    return _obj({"findings": {"type": "array", "maxItems": 20, "items": _obj({
        "refs": _ids("P", 40, 1), "severity": _SEVERITY, "observation": _STR,
        "entities": _entities(), "techniques": _TECHNIQUES})}})


def leads() -> dict:
    """REDUCE (phase 2)."""
    return _obj({"leads": {"type": "array", "maxItems": 30, "items": _obj({
        "refs": _ids("FL", 60, 1), "severity": _SEVERITY, "summary": _STR,
        "entities": _entities(), "techniques": _TECHNIQUES})}})


def hypotheses(max_hypotheses: int, max_queries: int) -> dict:
    """HYPOTHESIZE (phase 2)."""
    return _obj({"hypotheses": {"type": "array", "maxItems": max(1, max_hypotheses), "items": _obj({
        "statement": _STR, "refs": _ids("FL", 20), "techniques": _TECHNIQUES,
        "entities": _entities(), "queries": _queries(max(1, max_queries), 1)})}})


def verdict(max_queries: int) -> dict:
    """EVALUATE (phase 3)."""
    return _obj({
        "verdict": {"enum": ["SUPPORTED", "REFUTED", "INSUFFICIENT"]},
        "rationale": _STR,
        "supporting_events": _ids("E", 40),
        "refuting_events": _ids("E", 40),
        "confirmed_techniques": _TECHNIQUES,
        "new_pivots": {"type": "array", "maxItems": 10, "items": _obj({"value": _STR, "refs": _ids("E", 10, 1)})},
        "follow_up_queries": _queries(max(1, max_queries), 0)})


def summary(max_sentences: int) -> dict:
    """NARRATIVE (phase 4)."""
    return _obj({"summary": {"type": "array", "maxItems": max(1, max_sentences), "items": _STR}})
