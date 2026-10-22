"""Phase 0: evidence ingestion.

Reads every file in the evidence location, parses it into events without
discarding fields, normalises timestamps to UTC, and builds the evidence store.
It also renders a compact "view" of each event for the LLM and groups events
into patterns (identical activity that differs only in volatile values such as
process IDs, ports or GUIDs), so repetitive noise is read once with a count
instead of thousands of times.

Nothing here encodes knowledge about specific attacks, tools, or event IDs:
compaction decisions are derived from per-source field statistics.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import os
import re
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterator
from xml.etree import ElementTree as ET

from .config import Config
from .store import EvidenceStore
from .timeparse import TimeParser, to_iso
from .util import log, sha256_text

GUID_RE = re.compile(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?")
GUID_FULL = re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$")
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{8,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DIGITS_RE = re.compile(r"\d+")
NUMERIC_SHAPE = re.compile(r"^(?:0x[0-9a-fA-F]+|-?\d+(?:\.\d+)?|[0-9a-fA-F]{8,}|\{?[0-9a-fA-F-]{36}\}?)$")
SYSLOG_HOST = re.compile(r"^(?:<\d+>\d?\s*)?[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s+(\S+)\s")
NEWLINES = re.compile(r"[\r\n\t]+")

DISTINCT_CAP = 64
PLACEHOLDER_VALUES = {"", "-", "null", "None", "N/A"}


def flatten(obj, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}{k}"
            if isinstance(v, dict):
                out.update(flatten(v, key + "."))
            elif isinstance(v, list):
                if all(not isinstance(x, (dict, list)) for x in v):
                    sv = ", ".join(str(x) for x in v)
                else:
                    sv = json.dumps(v, ensure_ascii=False, separators=(",", ":"))
                if sv not in PLACEHOLDER_VALUES:
                    out[key] = sv
            elif v is not None:
                sv = str(v)
                if sv.strip() not in PLACEHOLDER_VALUES:
                    out[key] = sv
    return out


LABELLED_LINE = re.compile(r"^\s*([^:\r\n]{1,80}?):(?:\s+(.*))?$")


def residual_text(text: str, others: list[str], drop_guid: bool = True) -> str:
    """The parts of a long text value that no other field of the event holds.

    The text is read as "label: value" lines; lines without a label continue the value of
    the label above until a blank line (or stand alone). A label whose values are all held by other fields
    (or are empty, "-", or a GUID when drop_guid) is dropped, and so is a label with no
    value (a heading). Everything else is kept in its original order, so information
    that exists only in this text (for example a decoded description) is not lost."""
    exact = {" ".join(o.casefold().split()) for o in others}
    hay = " \x1f ".join(exact)

    def held(v: str) -> bool:
        n = " ".join(v.casefold().split()).strip(" '\"")
        if not n or n == "-" or (drop_guid and GUID_FULL.match(n)):
            return True
        return n in exact or (len(n) >= 4 and n in hay)

    groups: list[list] = []  # [label or None, [value lines]]
    open_label = False  # an unlabelled line continues the label above until a blank line
    for line in text.splitlines():
        if not line.strip():
            open_label = False
            continue
        m = LABELLED_LINE.match(line)
        # "C:\..." at the start of a line is a value, not a one-letter label
        if m and len(m.group(1).strip()) > 1:
            groups.append([m.group(1).strip(), [m.group(2).strip()] if m.group(2) and m.group(2).strip() else []])
            open_label = True
        elif open_label:
            groups[-1][1].append(line.strip())
        else:
            groups.append([None, [line.strip()]])
    kept = []
    for label, vals in groups:
        if not vals or all(held(v) for v in vals):
            continue
        kept.append(f"{label}: {' '.join(vals)}" if label else " ".join(vals))
    return " ↵ ".join(kept)


def mask_text(v: str) -> str:
    """Mask volatile parts of a value for pattern grouping (IPv4 addresses are kept)."""
    ips = IPV4_RE.findall(v)
    tmp = IPV4_RE.sub("\x00", v)
    tmp = GUID_RE.sub("<g>", tmp)
    tmp = HEX_RE.sub("<h>", tmp)
    tmp = DIGITS_RE.sub("#", tmp)
    for ip in ips:
        tmp = tmp.replace("\x00", ip, 1)
    return tmp


class _FieldStat:
    __slots__ = ("count", "first", "varied", "distinct", "capped", "numeric")

    def __init__(self, value: str):
        self.count = 0
        self.first = value
        self.varied = False
        self.distinct: set[str] = set()
        self.capped = False
        self.numeric = True

    def add(self, value: str) -> None:
        self.count += 1
        if value != self.first:
            self.varied = True
        if self.numeric and not NUMERIC_SHAPE.match(value):
            self.numeric = False
        if not self.capped:
            self.distinct.add(value)
            if len(self.distinct) >= DISTINCT_CAP:
                self.capped = True
                self.distinct = set()

    @property
    def n_distinct(self) -> int:
        return DISTINCT_CAP if self.capped else len(self.distinct)


class Ingestor:
    def __init__(self, cfg: Config, store: EvidenceStore, run_dir: Path):
        self.cfg = cfg
        self.store = store
        self.run_dir = Path(run_dir)
        ing = cfg.section("ingest")
        self.tp = TimeParser(ing.get("default_timezone", "UTC"), int(ing.get("assume_year") or 0))
        self.ts_keys = list(ing.get("timestamp_keys", []))
        self.host_keys = list(ing.get("host_keys", []))
        self.max_doc_bytes = int(ing.get("max_json_document_mb", 1024)) * 1024 * 1024
        self.extract = bool(ing.get("extract_archives", True))
        self.view_cfg = cfg.section("view")
        self.next_src = 1

    # ------------------------------------------------------------------ public
    def ingest(self, inputs: list[Path]) -> dict:
        files = []
        for p in inputs:
            files.extend(self._discover(Path(p).resolve(), depth=0))
        log.info("[ingest] %d files discovered", len(files))
        for path in files:
            self._ingest_file(path)
        log.info("[ingest] building search index")
        self.store.finalize()
        summary = self.store.stats()
        summary["sources"] = [dict(r) for r in self.store.sources()]
        for s in summary["sources"]:
            s.pop("constants", None)
        self.store.set_meta("ingest_summary", summary)
        return summary

    # --------------------------------------------------------------- discovery
    def _discover(self, path: Path, depth: int) -> list[Path]:
        if path.is_dir():
            out = []
            run_dir = self.run_dir.resolve()
            extracted = run_dir / "extracted"
            for root, dirs, names in os.walk(path):
                rp = Path(root).resolve()
                # never ingest this run's own outputs (except archives it extracted)
                in_run = rp == run_dir or run_dir in rp.parents
                in_extracted = rp == extracted or extracted in rp.parents
                if in_run and not in_extracted:
                    dirs[:] = []
                    continue
                dirs.sort()
                for n in sorted(names):
                    out.extend(self._discover(Path(root) / n, depth))
            return out
        if not path.is_file():
            return []
        if self.extract and zipfile.is_zipfile(path) and depth < 3:
            dest = self.run_dir / "extracted" / f"{sha256_text(str(path))[:10]}_{path.stem}"
            self._safe_extract(path, dest)
            return self._discover(dest, depth + 1)
        return [path]

    def _safe_extract(self, zpath: Path, dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zpath) as z:
            for m in z.infolist():
                target = (dest / m.filename).resolve()
                if dest.resolve() not in target.parents and target != dest.resolve():
                    log.warning("[ingest] skipping unsafe archive member %s in %s", m.filename, zpath)
                    continue
                if m.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(m) as src, open(target, "wb") as out:
                    while True:
                        b = src.read(1 << 20)
                        if not b:
                            break
                        out.write(b)

    # ----------------------------------------------------------------- parsing
    def _open_text(self, path: Path):
        if path.suffix.lower() == ".gz":
            return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
        return open(path, encoding="utf-8", errors="replace")

    def _sniff(self, path: Path) -> str:
        if path.suffix.lower() == ".evtx":
            return "evtx"
        try:
            if path.suffix.lower() == ".gz":
                with gzip.open(path, "rb") as f:
                    head = f.read(65536)
            else:
                with open(path, "rb") as f:
                    head = f.read(65536)
        except OSError as e:
            return f"error:{e}"
        if head.startswith(b"ElfFile"):
            return "evtx"
        if b"\x00" in head:
            return "binary"
        text = head.decode("utf-8", errors="replace").lstrip("﻿")
        first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
        if first.startswith("{"):
            try:
                json.loads(first)
                return "jsonl"
            except ValueError:
                return "json"
        if first.startswith("["):
            return "json"
        lines = [ln for ln in text.splitlines()[:20] if ln.strip()]
        if len(lines) >= 2:
            try:
                dialect = csv.Sniffer().sniff("\n".join(lines[:10]), delimiters=",\t;|")
                has_header = csv.Sniffer().has_header("\n".join(lines[:10]))
                counts = {ln.count(dialect.delimiter) for ln in lines[:10]}
                if has_header and len(counts) == 1 and next(iter(counts)) >= 2:
                    return "csv"
            except csv.Error:
                pass
        return "text"

    def _records(self, path: Path, fmt: str, stats: dict) -> Iterator[tuple[int, dict | None, str]]:
        """Yield (line_number, fields or None, raw_text)."""
        if fmt == "jsonl":
            with self._open_text(path) as f:
                for n, line in enumerate(f, 1):
                    s = line.strip().lstrip("﻿")
                    if not s:
                        continue
                    try:
                        obj = json.loads(s)
                    except ValueError:
                        stats["parse_errors"] += 1
                        yield n, None, s
                        continue
                    if isinstance(obj, dict):
                        recs = self._record_list(obj)
                        if recs is None:
                            yield n, flatten(obj), s
                        else:  # one line holding a container of records
                            for r in recs:
                                yield n, flatten(r), json.dumps(r, ensure_ascii=False)
                    else:
                        yield n, None, s
        elif fmt == "json":
            size = path.stat().st_size
            if size > self.max_doc_bytes:
                raise ValueError(f"JSON document of {size} bytes exceeds ingest.max_json_document_mb")
            with self._open_text(path) as f:
                doc = json.load(f)
            recs = None
            if isinstance(doc, list):
                recs = doc
            elif isinstance(doc, dict):
                recs = self._record_list(doc) or [doc]
            for n, r in enumerate(recs or [], 1):
                if isinstance(r, dict):
                    yield n, flatten(r), json.dumps(r, ensure_ascii=False)
                else:
                    yield n, None, json.dumps(r, ensure_ascii=False)
        elif fmt == "csv":
            with self._open_text(path) as f:
                sample = f.read(65536)
                f.seek(0)
                dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
                reader = csv.DictReader(f, dialect=dialect)
                for n, row in enumerate(reader, 2):
                    fields = {str(k): str(v) for k, v in row.items()
                              if k is not None and v is not None and str(v).strip() not in PLACEHOLDER_VALUES}
                    yield n, fields, dialect.delimiter.join(str(v) for v in row.values() if v is not None)
        elif fmt == "evtx":
            yield from self._evtx(path, stats)
        else:
            with self._open_text(path) as f:
                for n, line in enumerate(f, 1):
                    s = line.rstrip("\r\n")
                    if s.strip():
                        yield n, None, s

    @staticmethod
    def _record_list(obj: dict) -> list | None:
        """Records of a container object such as {"Records": [{...}, ...]}: exactly one value is a
        non-empty list of objects and every other value is a scalar."""
        lists = [v for v in obj.values() if isinstance(v, list) and v and all(isinstance(x, dict) for x in v)]
        others = [v for v in obj.values() if isinstance(v, (dict, list)) and not any(v is l for l in lists)]
        return lists[0] if len(lists) == 1 and not others else None

    def _evtx(self, path: Path, stats: dict) -> Iterator[tuple[int, dict | None, str]]:
        try:
            from Evtx.Evtx import Evtx  # python-evtx
        except ImportError as e:
            raise RuntimeError("python-evtx is required to read .evtx files") from e
        with Evtx(str(path)) as ev:
            for rec in ev.records():
                try:
                    xml = rec.xml()
                    root = ET.fromstring(xml)
                except Exception:
                    stats["parse_errors"] += 1
                    continue
                fields: dict[str, str] = {}
                for el in root.iter():
                    tag = el.tag.split("}")[-1]
                    if tag == "Data":
                        name = el.attrib.get("Name") or f"Data{len(fields)}"
                        if el.text and el.text.strip() not in PLACEHOLDER_VALUES:
                            fields[name] = el.text.strip()
                        continue
                    for ak, av in el.attrib.items():
                        if av and av.strip() not in PLACEHOLDER_VALUES:
                            fields[f"{tag}.{ak}"] = av
                    if el.text and el.text.strip() and len(el) == 0 and el.text.strip() not in PLACEHOLDER_VALUES:
                        fields.setdefault(tag, el.text.strip())
                yield rec.record_num(), fields, xml

    # --------------------------------------------------------------- per file
    def _pick_ts(self, fields: dict, year_hint: int) -> tuple[datetime | None, str, str | None]:
        for k in self.ts_keys:
            if k in fields:
                dt, q = self.tp.parse(fields[k], year_hint)
                if dt:
                    return dt, q, k
        candidates = sorted(fields, key=lambda k: (0 if re.search("time|date", k, re.I) else 1))
        for k in candidates:
            v = fields[k]
            if len(v) > 64:
                continue
            dt, q = self.tp.parse(v, year_hint)
            if dt:
                return dt, q, k
        return None, "none", None

    def _pick_host(self, fields: dict) -> tuple[str, str | None]:
        for k in self.host_keys:
            v = fields.get(k)
            if v and v.strip():
                return v.strip(), k
        return "", None

    def _ingest_file(self, path: Path) -> None:
        src = self.next_src
        self.next_src += 1
        label = f"S{src}"
        fmt = self._sniff(path)
        db = self.store.db
        db.execute("INSERT INTO sources(id, path, label, fmt, status) VALUES(?,?,?,?,?)",
                   (src, str(path), label, fmt, "reading"))
        if fmt in ("binary",) or fmt.startswith("error:"):
            db.execute("UPDATE sources SET status=?, note=? WHERE id=?",
                       ("unsupported", "binary or unreadable file; not analysed", src))
            db.commit()
            log.warning("[ingest] %s %s: unsupported (%s)", label, path, fmt)
            return
        year_hint = datetime.fromtimestamp(path.stat().st_mtime).year
        stats = {"parse_errors": 0, "no_ts": 0, "events": 0}
        sig_stats: dict[tuple[str, str], _FieldStat] = {}
        src_stats: dict[str, _FieldStat] = {}
        ts_key_counter: Counter = Counter()
        host_key_counter: Counter = Counter()
        offsets: dict[tuple[str, str], list[float]] = {}
        batch = []
        try:
            for line_no, fields, raw in self._records(path, fmt, stats):
                if fields:
                    dt, q, tkey = self._pick_ts(fields, year_hint)
                    if dt is not None:
                        # offsets to other timestamp fields of the same event, for clock alignment
                        for ok in self.ts_keys:
                            if ok == tkey or ok not in fields:
                                continue
                            lst = offsets.setdefault((tkey, ok), [])
                            if len(lst) < 20000:
                                odt, _ = self.tp.parse(fields[ok], year_hint)
                                if odt is not None:
                                    lst.append(dt.timestamp() - odt.timestamp())
                    host, hkey = self._pick_host(fields)
                    ts_key_counter[tkey] += 1
                    host_key_counter[hkey] += 1
                    full = " | ".join(f"{k}={v}" for k, v in fields.items())
                    sig = sha256_text(*sorted(fields))[:12]
                    for k, v in fields.items():
                        st = sig_stats.get((sig, k))
                        if st is None:
                            st = sig_stats[(sig, k)] = _FieldStat(v)
                        st.add(v)
                        ss = src_stats.get(k)
                        if ss is None:
                            ss = src_stats[k] = _FieldStat(v)
                        ss.add(v)
                    payload = json.dumps({"s": sig, "t": tkey, "h": hkey, "f": fields}, ensure_ascii=False)
                else:
                    dt, q = self.tp.find_in_text(raw, year_hint)
                    m = SYSLOG_HOST.match(raw)
                    host = m.group(1) if m else ""
                    full = raw
                    payload = None
                    tkey = None
                if dt is None:
                    stats["no_ts"] += 1
                batch.append((src, line_no, to_iso(dt) if dt else None, dt.timestamp() if dt else None,
                              q, tkey if dt else None, host, full, payload))
                stats["events"] += 1
                if len(batch) >= 5000:
                    db.executemany("INSERT INTO events(src,line,ts,ts_epoch,ts_quality,ts_key,host,full,fields) "
                                   "VALUES(?,?,?,?,?,?,?,?,?)", batch)
                    batch.clear()
            if batch:
                db.executemany("INSERT INTO events(src,line,ts,ts_epoch,ts_quality,ts_key,host,full,fields) "
                               "VALUES(?,?,?,?,?,?,?,?,?)", batch)
            db.commit()
        except Exception as e:  # keep whatever was read, record the failure
            db.commit()
            db.execute("UPDATE sources SET status=?, note=?, events=?, parse_errors=? WHERE id=?",
                       ("error", f"{type(e).__name__}: {e}", stats["events"], stats["parse_errors"], src))
            db.commit()
            log.error("[ingest] %s %s: %s", label, path, e)
            if stats["events"] == 0:
                return
        clock = self._align_clocks(src, ts_key_counter, offsets)
        constants = {}
        if self.view_cfg.get("drop_source_constant_fields", True) and stats["events"] > 1:
            constants = {k: s.first for k, s in src_stats.items()
                         if s.count == stats["events"] and not s.varied}
        self._render_and_group(src, sig_stats, constants)
        status = "ok" if db.execute("SELECT status FROM sources WHERE id=?", (src,)).fetchone()[0] == "reading" \
            else "partial"
        db.execute("UPDATE sources SET status=?, events=?, parse_errors=?, no_timestamp=?, constants=?, clock=? "
                   "WHERE id=?", (status, stats["events"], stats["parse_errors"], stats["no_ts"],
                                  json.dumps(constants, ensure_ascii=False), json.dumps(clock), src))
        db.commit()
        log.info("[ingest] %s %s: fmt=%s events=%d parse_errors=%d no_timestamp=%d",
                 label, path.name, fmt, stats["events"], stats["parse_errors"], stats["no_ts"])

    # ------------------------------------------------------- clock alignment
    def _align_clocks(self, src: int, used: Counter, offsets: dict) -> dict:
        """Events of one source may take their time from different fields (for example a UTC field
        on some event types and a local-time field on others). The highest-priority field in use is
        the reference; another field is shifted onto it only if events carrying both fields show a
        consistent offset. Otherwise its events are marked as not aligned."""
        keys = [k for k in used if k]
        if len(keys) < 2:
            return {"reference": keys[0] if keys else None, "aligned": {}, "unaligned": {}}
        prio = {k: i for i, k in enumerate(self.ts_keys)}
        ref = min(keys, key=lambda k: prio.get(k, len(prio)))
        out = {"reference": ref, "aligned": {}, "unaligned": {}}
        db = self.store.db
        for k in keys:
            if k == ref:
                continue
            sample = sorted(offsets.get((ref, k), []))
            n = len(sample)
            if n >= 5:
                med = sample[n // 2]
                within = sum(1 for x in sample if abs(x - med) <= 2.0) / n
            else:
                med, within = 0.0, 0.0
            if n >= 5 and within >= 0.9:
                if abs(med) > 0.5:
                    db.execute("UPDATE events SET ts_epoch = ts_epoch + ?, "
                               "ts = strftime('%Y-%m-%dT%H:%M:%f', ts_epoch + ?, 'unixepoch') || 'Z', "
                               "ts_quality = 'aligned' WHERE src=? AND ts_key=?", (med, med, src, k))
                out["aligned"][k] = {"offset_s": round(med, 3), "samples": n, "events": used[k]}
                log.info("[ingest] S%d: %d events timed by %s aligned to %s (offset %+.1fs, %d samples)",
                         src, used[k], k, ref, med, n)
            else:
                db.execute("UPDATE events SET ts_quality = 'unaligned' WHERE src=? AND ts_key=?", (src, k))
                out["unaligned"][k] = {"samples": n, "consistent_fraction": round(within, 2), "events": used[k]}
                log.warning("[ingest] S%d: %d events timed by %s could not be aligned to %s (%d samples); "
                            "their order relative to other events is uncertain", src, used[k], k, ref, n)
        db.commit()
        return out

    # ------------------------------------------------------- render + patterns
    def _render_and_group(self, src: int, sig_stats: dict, constants: dict) -> None:
        db = self.store.db
        max_chars = int(self.view_cfg.get("max_value_chars", 1500))
        drop_guid = bool(self.view_cfg.get("drop_guid_values", True))
        drop_redundant = bool(self.view_cfg.get("drop_redundant_text_fields", True))
        patterns: dict[str, list] = {}
        next_pid = (db.execute("SELECT COALESCE(MAX(id),0) FROM patterns").fetchone()[0] or 0) + 1
        updates = []
        cur = db.execute("SELECT id, ts, ts_epoch, host, full, fields FROM events WHERE src=? ORDER BY id", (src,))
        for eid, ts, epoch, host, full, payload in cur:
            if payload:
                p = json.loads(payload)
                fields, sig, tkey, hkey = p["f"], p["s"], p["t"], p["h"]
                view_parts, key_parts = [], [sig]
                long_vals = [v for v in fields.values() if len(v) >= 4]
                for k, v in fields.items():
                    if k in (tkey, hkey):
                        continue
                    st = sig_stats.get((sig, k))
                    # pattern key
                    if k not in constants:
                        if st is not None and st.numeric and st.n_distinct > 20:
                            key_parts.append(f"{k}=<n>")
                        elif st is not None and st.capped and st.count >= 2 * DISTINCT_CAP:
                            key_parts.append(f"{k}={mask_text(v)}")
                        else:
                            key_parts.append(f"{k}={v}")
                    # view
                    if k in constants:
                        continue
                    if drop_guid and GUID_FULL.match(v):
                        continue
                    if drop_redundant and len(v) >= 200:
                        others = [o for o in long_vals if o is not v and o != v]
                        if len(others) >= 4 and sum(1 for o in others if o in v) / len(others) >= 0.5:
                            # mostly a repeat of other fields: keep only what they do not hold
                            v = residual_text(v, [o for o in fields.values() if o is not v], drop_guid)
                            if not v:
                                continue
                    vv = NEWLINES.sub(" ↵ ", v)
                    if len(vv) > max_chars:
                        vv = vv[:max_chars] + f"…[+{len(vv) - max_chars} chars]"
                    view_parts.append(f"{k}={vv}")
                view = " | ".join(view_parts) if view_parts else "(all fields constant for this source)"
                key = "\x1f".join(key_parts)
            else:
                vv = NEWLINES.sub(" ↵ ", full)
                view = vv if len(vv) <= max_chars * 2 else vv[:max_chars * 2] + f"…[+{len(vv) - max_chars * 2} chars]"
                # digits (timestamps, PIDs, counters) are masked so the same message groups together
                key = "TEXT\x1f" + mask_text(full)
            kh = sha256_text(str(src), key)[:24]
            pat = patterns.get(kh)
            if pat is None:
                pat = patterns[kh] = [next_pid, 0, epoch, epoch, ts, ts, Counter(), eid]
                next_pid += 1
            pat[1] += 1
            if epoch is not None:
                if pat[2] is None or epoch < pat[2]:
                    pat[2], pat[4], pat[7] = epoch, ts, eid
                if pat[3] is None or epoch > pat[3]:
                    pat[3], pat[5] = epoch, ts
            pat[6][host or ""] += 1
            updates.append((view, pat[0], eid))
            if len(updates) >= 5000:
                db.executemany("UPDATE events SET view=?, pattern=? WHERE id=?", updates)
                updates.clear()
        if updates:
            db.executemany("UPDATE events SET view=?, pattern=? WHERE id=?", updates)
        db.executemany(
            "INSERT INTO patterns(id,src,key_hash,count,first_epoch,last_epoch,first_ts,last_ts,hosts,rep_event) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(p[0], src, kh, p[1], p[2], p[3], p[4], p[5], json.dumps(dict(p[6].most_common()), ensure_ascii=False),
              p[7]) for kh, p in patterns.items()])
        db.commit()
