"""Deterministic grounding of LLM output against evidence text.

A claim survives only if every concrete artifact it mentions (addresses, file
names, paths, registry keys, hashes, SIDs, accounts in DOMAIN\\user form,
timestamps, quoted strings, threat-actor and software names) occurs in the text
of the evidence it cites. Matching is case-insensitive substring matching on
normalised text; nothing is matched "approximately".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .attack import Attack
from .store import norm_text

_PATTERNS = [
    ("url", re.compile(r"\b(?:https?|ftp|ldap|smb)://[^\s\"'<>()\[\]{}]+", re.I)),
    ("win_path", re.compile(r"\b[a-zA-Z]:\\[^\s\"'<>|*?]+")),
    ("unc_path", re.compile(r"\\\\[\w.$-]+\\[^\s\"'<>|*?]+")),
    ("registry", re.compile(r"\b(?:HKLM|HKCU|HKU|HKCR|HKCC|HKEY_[A-Z_]+)[\\:][^\s\"'<>]*", re.I)),
    ("unix_path", re.compile(r"(?<![\w:/.])/(?:[\w.+@-]+/)+[\w.+@-]*")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("ipv6", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b")),
    ("hash", re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")),
    ("sid", re.compile(r"\bS-1-\d+(?:-\d+){1,14}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("account", re.compile(r"\b[\w.-]{2,}\\[\w.$-]{2,}\b")),
    ("datetime", re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?")),
    ("time", re.compile(r"(?<![\d:])\d{2}:\d{2}:\d{2}(?![\d:])")),
    ("dotted_name", re.compile(r"(?<![\w\\/.-])[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z][A-Za-z0-9]{1,9}\b")),
    ("quoted", re.compile(r"`([^`\n]{3,200})`|\"([^\"\n]{3,200})\"")),
]

# Dotted tokens that are ordinary prose, not artifacts.
_PROSE_DOTTED = {"e.g", "i.e", "etc", "vs", "a.m", "p.m", "u.s"}


def extract_artifacts(text: str) -> list[tuple[str, str]]:
    """Return (kind, value) for every concrete artifact mentioned in text."""
    out: list[tuple[str, str]] = []
    spans: list[tuple[int, int]] = []
    for kind, rx in _PATTERNS:
        for m in rx.finditer(text or ""):
            if kind == "quoted":
                val = m.group(1) or m.group(2)
                s, e = m.span(1) if m.group(1) else m.span(2)
            else:
                val, (s, e) = m.group(0), m.span()
            if any(s >= a and e <= b for a, b in spans):
                continue  # already covered by a longer artifact
            val = val.rstrip(".,;:)]}'\"")
            if kind == "dotted_name":
                low = val.lower()
                if low in _PROSE_DOTTED or re.fullmatch(r"[\d.]+", val) or len(val) < 4:
                    continue
            if kind == "ipv4" and any(int(x) > 255 for x in val.split(".")):
                continue
            if len(val) < 3:
                continue
            spans.append((s, e))
            out.append((kind, val))
    return out


@dataclass
class GroundResult:
    ok: bool
    missing: list[str] = field(default_factory=list)


class Grounder:
    def __init__(self, attack: Attack | None):
        self.attack = attack

    @staticmethod
    def value_in(value: str, haystack_norm: str) -> bool:
        v = norm_text(str(value)).strip(" '\"`")
        if len(v) < 2:
            return False
        if v in haystack_norm:
            return True
        # Paths are sometimes written with forward slashes by the model.
        if "/" in v and v.replace("/", "\\") in haystack_norm:
            return True
        return False

    def check_text(self, text: str, haystack_norm: str, cited_ts: list[str] | None = None) -> GroundResult:
        """All artifacts and actor/software names in text must occur in the evidence."""
        missing = []
        for kind, val in extract_artifacts(text):
            if kind in ("datetime", "time"):
                if cited_ts and any(val.replace(" ", "T") in t or val in t for t in cited_ts):
                    continue
                if self.value_in(val, haystack_norm):
                    continue
                missing.append(val)
                continue
            if not self.value_in(val, haystack_norm):
                missing.append(val)
        if self.attack:
            for name in self.attack.named_actors(text) + self.attack.named_software(text):
                if not self.value_in(name, haystack_norm):
                    missing.append(name)
        return GroundResult(not missing, sorted(set(missing)))

    def filter_values(self, values: list[str], haystack_norm: str) -> tuple[list[str], list[str]]:
        kept, dropped = [], []
        for v in values:
            (kept if self.value_in(v, haystack_norm) else dropped).append(v)
        return kept, dropped


_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z\[(\"'`])|\n+")


def split_sentences(text: str) -> list[str]:
    parts = [p.strip() for p in _SENT_SPLIT.split(text or "")]
    return [p for p in parts if p]
