"""Type coercion for model output. Nothing here raises: malformed parts are
dropped or replaced by empty values, and the caller decides what that means."""
from __future__ import annotations

import re
from typing import Any

from .prompts import ENTITY_KEYS

REF_RE = {p: re.compile(rf"\b{p}(\d+)\b", re.I) for p in ("P", "F", "L", "E", "H")}


def as_str(x: Any, limit: int = 4000) -> str:
    if x is None:
        return ""
    if isinstance(x, (dict, list)):
        return ""
    return str(x).strip()[:limit]


def _scalars(v: Any, depth: int = 0) -> list[str]:
    """Scalar values inside a structured item, e.g. {"name": "x.exe"} -> ["x.exe"]."""
    if v is None:
        return []
    if isinstance(v, (str, int, float)):
        s = str(v).strip()
        return [s] if s else []
    if depth >= 3:
        return []
    items = v.values() if isinstance(v, dict) else v if isinstance(v, list) else []
    return [s for x in items for s in _scalars(x, depth + 1)]


def as_str_list(x: Any, limit_items: int = 50, limit_len: int = 2000, join_items: bool = False) -> list[str]:
    """Strings from a model-produced list. An item given as an object or nested list
    contributes its longest scalar value (the identifying value, e.g. a path rather
    than an action word), or all of its values joined into one string with
    join_items=True (used where an ID is extracted from the item)."""
    if x is None:
        return []
    if isinstance(x, (str, int, float, dict)):
        x = [x]
    if not isinstance(x, list):
        return []
    out = []
    for v in x:
        if isinstance(v, (dict, list)):
            parts = _scalars(v)
            vals = [" ".join(parts) if join_items else max(parts, key=len)] if parts else []
        elif v is None:
            continue
        else:
            vals = [str(v).strip()]
        for s in vals:
            if s and s not in out:
                out.append(s[:limit_len])
            if len(out) >= limit_items:
                return out
    return out


def as_refs(x: Any, prefix: str) -> list[int]:
    """Extract numeric ids for a given prefix from strings like 'P12', 'p12', '[P12]', or bare ints."""
    out: list[int] = []
    items = x if isinstance(x, list) else [x]
    for v in items:
        if isinstance(v, bool) or v is None:
            continue
        if isinstance(v, int):
            out.append(v)
            continue
        for m in REF_RE[prefix].finditer(str(v)):
            out.append(int(m.group(1)))
    return list(dict.fromkeys(out))


def as_entities(x: Any) -> dict[str, list[str]]:
    out = {k: [] for k in ENTITY_KEYS}
    if not isinstance(x, dict):
        return out
    for k, v in x.items():
        key = str(k).strip().lower().replace(" ", "_")
        if key not in out:
            key = "other"
        for s in as_str_list(v):
            if s not in out[key]:
                out[key].append(s)
    return out


def as_severity(x: Any) -> str:
    s = as_str(x).lower()
    return s if s in ("high", "medium", "low") else "low"


def as_list_of_dicts(x: Any, limit: int = 100) -> list[dict]:
    if isinstance(x, dict):
        x = [x]
    if not isinstance(x, list):
        return []
    return [v for v in x if isinstance(v, dict)][:limit]


def as_verdict(x: Any) -> str:
    """Exactly one verdict word must be present; anything else (including an
    echoed 'SUPPORTED|REFUTED|INSUFFICIENT') is treated as INSUFFICIENT."""
    s = as_str(x).upper()
    hits = [v for v in ("SUPPORTED", "REFUTED", "INSUFFICIENT") if v in s]
    return hits[0] if len(hits) == 1 else "INSUFFICIENT"


def entity_values(ents: dict[str, list[str]]) -> list[str]:
    return [v for k in ENTITY_KEYS for v in ents.get(k, [])]
