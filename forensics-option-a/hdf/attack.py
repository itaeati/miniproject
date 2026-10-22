"""MITRE ATT&CK knowledge from the official STIX bundle.

Used to (1) reject technique IDs that do not exist, (2) map revoked IDs to their
replacements, and (3) list threat-actor and software names so that a claim
naming one of them can be rejected unless the name appears in cited evidence.
"""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

from .util import atomic_write_json, log, read_json

TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_INDEX_VERSION = 2


def _ext_id(obj: dict) -> str | None:
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"]
    return None


class Attack:
    def __init__(self, techniques: dict, actors: list[str], software: list[str], version: str):
        self.techniques = techniques  # id -> {name, revoked_by, deprecated}
        self.actor_names = actors
        self.software_names = software
        self.version = version
        self._actor_re = self._names_regex(actors)
        self._software_re = self._names_regex(software)

    @staticmethod
    def _names_regex(names: list[str]):
        if not names:
            return None
        parts = sorted({re.escape(n) for n in names}, key=len, reverse=True)
        return re.compile(r"(?<![\w-])(?:" + "|".join(parts) + r")(?![\w-])", re.IGNORECASE)

    # ------------------------------------------------------------ loading
    @classmethod
    def load(cls, stix_path: str | Path, url: str | None = None) -> "Attack":
        stix_path = Path(stix_path)
        index_path = stix_path.with_suffix(".index.json")
        idx = read_json(index_path)
        if idx and idx.get("v") == _INDEX_VERSION and stix_path.exists() and \
                idx.get("mtime") == stix_path.stat().st_mtime:
            return cls(idx["techniques"], idx["actors"], idx["software"], idx["version"])
        if not stix_path.exists():
            if not url:
                raise FileNotFoundError(f"ATT&CK STIX bundle not found: {stix_path}")
            log.info("[attack] downloading ATT&CK STIX bundle")
            stix_path.parent.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(url, headers={"User-Agent": "hdf"})
            with urllib.request.urlopen(req, timeout=300) as r, open(stix_path, "wb") as f:
                f.write(r.read())
        with open(stix_path, encoding="utf-8") as f:
            bundle = json.load(f)
        objs = bundle.get("objects", [])
        by_stix = {o["id"]: o for o in objs if "id" in o}
        revoked_by = {}
        for o in objs:
            if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
                revoked_by[o["source_ref"]] = o["target_ref"]
        techniques = {}
        for o in objs:
            if o.get("type") != "attack-pattern":
                continue
            tid = _ext_id(o)
            if not tid or not tid.startswith("T"):
                continue
            rb = None
            if o.get("revoked"):
                tgt = by_stix.get(revoked_by.get(o["id"], ""))
                rb = _ext_id(tgt) if tgt else None
            techniques[tid] = {"name": o.get("name", ""), "revoked_by": rb,
                               "deprecated": bool(o.get("x_mitre_deprecated")) and not o.get("revoked")}
        actors, software = set(), set()
        for o in objs:
            names = [o.get("name", "")] + list(o.get("aliases", []) or []) + list(o.get("x_mitre_aliases", []) or [])
            names = [n for n in names if n and len(n) >= 4]
            if o.get("type") in ("intrusion-set", "campaign"):
                actors.update(names)
            elif o.get("type") in ("malware", "tool"):
                software.update(names)
        version = next((o.get("x_mitre_version", "?") for o in objs if o.get("type") == "x-mitre-collection"), "?")
        idx = {"v": _INDEX_VERSION, "mtime": stix_path.stat().st_mtime, "techniques": techniques,
               "actors": sorted(actors), "software": sorted(software), "version": version}
        atomic_write_json(index_path, idx)
        return cls(techniques, idx["actors"], idx["software"], version)

    # ------------------------------------------------------------ queries
    def canonical(self, tid: str) -> str | None:
        """Current technique ID for tid; None if unknown or deprecated without replacement."""
        tid = (tid or "").strip().upper()
        seen = set()
        while tid in self.techniques and tid not in seen:
            seen.add(tid)
            t = self.techniques[tid]
            if t["revoked_by"]:
                tid = t["revoked_by"]
                continue
            if t["deprecated"]:
                return None
            return tid
        return None

    def name(self, tid: str) -> str:
        t = self.techniques.get(tid)
        return t["name"] if t else ""

    def clean_ids(self, values) -> tuple[list[str], list[str]]:
        """Split values into (valid canonical IDs, rejected raw values)."""
        ok, bad = [], []
        for v in values or []:
            found = TECH_RE.findall(str(v).upper())
            if not found:
                bad.append(str(v))
                continue
            for t in found:
                c = self.canonical(t)
                if c and c not in ok:
                    ok.append(c)
                elif not c:
                    bad.append(t)
        return ok, bad

    def named_actors(self, text: str) -> list[str]:
        return sorted({m.group(0) for m in self._actor_re.finditer(text)}) if self._actor_re else []

    def named_software(self, text: str) -> list[str]:
        return sorted({m.group(0) for m in self._software_re.finditer(text)}) if self._software_re else []
