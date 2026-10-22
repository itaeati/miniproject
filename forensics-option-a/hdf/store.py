"""Evidence store (SQLite).

Every parsed event is kept in full. The LLM only ever sees compact renderings,
but drill-down search and all grounding checks run against the full records.
A trigram FTS index gives case-insensitive substring search over full events.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sources(
    id INTEGER PRIMARY KEY, path TEXT, label TEXT, fmt TEXT, status TEXT, note TEXT,
    events INTEGER DEFAULT 0, parse_errors INTEGER DEFAULT 0, no_timestamp INTEGER DEFAULT 0,
    constants TEXT, clock TEXT);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY, src INTEGER, line INTEGER, ts TEXT, ts_epoch REAL, ts_quality TEXT, ts_key TEXT,
    host TEXT, full TEXT, view TEXT, fields TEXT, pattern INTEGER);
CREATE TABLE IF NOT EXISTS patterns(
    id INTEGER PRIMARY KEY, src INTEGER, key_hash TEXT UNIQUE, count INTEGER,
    first_epoch REAL, last_epoch REAL, first_ts TEXT, last_ts TEXT, hosts TEXT, rep_event INTEGER);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS ev_epoch ON events(ts_epoch, id);
CREATE INDEX IF NOT EXISTS ev_host_epoch ON events(host, ts_epoch, id);
CREATE INDEX IF NOT EXISTS ev_pattern ON events(pattern);
CREATE INDEX IF NOT EXISTS ev_src ON events(src, ts_epoch, id);
CREATE INDEX IF NOT EXISTS pat_src ON patterns(src, first_epoch);
"""


@dataclass
class Event:
    id: int
    src: int
    line: int
    ts: str | None
    ts_epoch: float | None
    host: str
    full: str
    view: str
    pattern: int | None


def norm_text(s: str) -> str:
    """Normalisation shared by grounding and search: case-folded, unified backslashes."""
    s = s.casefold()
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return " ".join(s.split())


class EvidenceStore:
    def __init__(self, path: Path, create: bool = False):
        self.path = Path(path)
        if not create and not self.path.exists():
            raise FileNotFoundError(f"evidence store not found: {self.path}")
        self.db = sqlite3.connect(str(self.path))
        self.db.row_factory = sqlite3.Row
        if create:
            self.db.executescript(SCHEMA)
        self._norm_cache: dict[int, str] = {}

    def close(self) -> None:
        self.db.close()

    # -- meta ---------------------------------------------------------------
    def set_meta(self, key: str, value) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, json.dumps(value)))
        self.db.commit()

    def get_meta(self, key: str, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    # -- build --------------------------------------------------------------
    def finalize(self) -> None:
        self.db.executescript(INDEXES)
        self.db.execute("DROP TABLE IF EXISTS events_fts")
        self.db.execute(
            "CREATE VIRTUAL TABLE events_fts USING fts5(full, content='events', content_rowid='id', "
            "tokenize='trigram case_sensitive 0')")
        self.db.execute("INSERT INTO events_fts(rowid, full) SELECT id, full FROM events")
        self.db.execute("UPDATE events SET fields=NULL")
        self.db.commit()
        self.db.execute("VACUUM")

    # -- reads --------------------------------------------------------------
    def _event(self, r: sqlite3.Row) -> Event:
        return Event(r["id"], r["src"], r["line"], r["ts"], r["ts_epoch"], r["host"] or "",
                     r["full"] or "", r["view"] or "", r["pattern"])

    def event(self, eid: int) -> Event | None:
        r = self.db.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        return self._event(r) if r else None

    def events(self, ids: Iterable[int]) -> list[Event]:
        ids = list(dict.fromkeys(int(i) for i in ids))
        out: list[Event] = []
        for i in range(0, len(ids), 500):
            part = ids[i:i + 500]
            q = f"SELECT * FROM events WHERE id IN ({','.join('?' * len(part))})"
            out.extend(self._event(r) for r in self.db.execute(q, part))
        order = {e: n for n, e in enumerate(ids)}
        out.sort(key=lambda e: order[e.id])
        return out

    def norm_full(self, eid: int) -> str:
        if eid not in self._norm_cache:
            e = self.event(eid)
            if len(self._norm_cache) > 20000:
                self._norm_cache.clear()
            self._norm_cache[eid] = norm_text(f"{e.full} host={e.host} ts={e.ts}") if e else ""
        return self._norm_cache[eid]

    def sources(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM sources ORDER BY id"))

    def source_label(self, src: int) -> str:
        r = self.db.execute("SELECT label FROM sources WHERE id=?", (src,)).fetchone()
        return r[0] if r else f"S{src}"

    def source_path(self, src: int) -> str:
        r = self.db.execute("SELECT path FROM sources WHERE id=?", (src,)).fetchone()
        return r[0] if r else "?"

    def hosts(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT DISTINCT host FROM events WHERE host IS NOT NULL")]

    def stats(self) -> dict:
        r = self.db.execute(
            "SELECT COUNT(*), MIN(ts), MAX(ts), COUNT(DISTINCT host), SUM(ts IS NULL) FROM events").fetchone()
        p = self.db.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
        return {"events": r[0], "first_ts": r[1], "last_ts": r[2], "hosts": r[3],
                "events_without_timestamp": r[4] or 0, "patterns": p}

    def patterns_for_source(self, src: int) -> list[sqlite3.Row]:
        return list(self.db.execute(
            "SELECT * FROM patterns WHERE src=? ORDER BY first_epoch IS NULL, first_epoch, id", (src,)))

    def pattern(self, pid: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM patterns WHERE id=?", (pid,)).fetchone()

    def pattern_event_ids(self, pid: int, limit: int = 0) -> list[int]:
        q = "SELECT id FROM events WHERE pattern=? ORDER BY ts_epoch, id"
        if limit:
            q += f" LIMIT {int(limit)}"
        return [r[0] for r in self.db.execute(q, (pid,))]

    # -- drill-down search ----------------------------------------------------
    def search(self, keywords: list[str], host: str | None = None, t_from: float | None = None,
               t_to: float | None = None, limit: int = 100000) -> tuple[list[int], int]:
        """Events containing ALL keywords (case-insensitive substring), ordered by time.

        Returns (matching ids, total count). Keywords shorter than three characters
        cannot use the trigram index and are applied as a post-filter.
        """
        kws = []
        for k in keywords:
            k = str(k).strip()
            while "\\\\" in k:
                k = k.replace("\\\\", "\\")
            if k:
                kws.append(k)
        if not kws:
            return [], 0
        filters, fargs = [], []
        if host:
            filters.append("lower(e.host) = ?")
            fargs.append(host.lower())
        if t_from is not None:
            filters.append("e.ts_epoch >= ?")
            fargs.append(t_from)
        if t_to is not None:
            filters.append("e.ts_epoch <= ?")
            fargs.append(t_to)
        order = " ORDER BY e.ts_epoch IS NULL, e.ts_epoch, e.id"

        def scan_clauses(words):
            return [f"instr(lower(e.full), ?) > 0" for _ in words], [w.lower() for w in words]

        indexed = [k for k in kws if len(k) >= 3]
        short = [k for k in kws if len(k) < 3]
        where, args = [], []
        if indexed:
            where.append("e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
            args.append(" AND ".join('"' + k.replace('"', '""') + '"' for k in indexed))
        c, a = scan_clauses(short)
        where += c
        args += a
        try:
            ids = [r[0] for r in self.db.execute(
                f"SELECT e.id FROM events e WHERE {' AND '.join(where + filters)}{order}", args + fargs)]
        except sqlite3.OperationalError:
            # Unusual characters can break FTS query syntax: fall back to a full scan.
            c, a = scan_clauses(kws)
            ids = [r[0] for r in self.db.execute(
                f"SELECT e.id FROM events e WHERE {' AND '.join(c + filters)}{order}", a + fargs)]
        return ids[:limit], len(ids)

    def neighbors(self, eid: int, n: int) -> list[int]:
        """n events before and after eid on the same host, in chronological order."""
        e = self.event(eid)
        if not e or n <= 0:
            return [eid] if e else []
        if e.ts_epoch is None:
            rows_b = self.db.execute(
                "SELECT id FROM events WHERE src=? AND id<? ORDER BY id DESC LIMIT ?", (e.src, eid, n))
            rows_a = self.db.execute(
                "SELECT id FROM events WHERE src=? AND id>? ORDER BY id LIMIT ?", (e.src, eid, n))
        else:
            rows_b = self.db.execute(
                "SELECT id FROM events WHERE host=? AND (ts_epoch<? OR (ts_epoch=? AND id<?)) "
                "ORDER BY ts_epoch DESC, id DESC LIMIT ?", (e.host, e.ts_epoch, e.ts_epoch, eid, n))
            rows_a = self.db.execute(
                "SELECT id FROM events WHERE host=? AND (ts_epoch>? OR (ts_epoch=? AND id>?)) "
                "ORDER BY ts_epoch, id LIMIT ?", (e.host, e.ts_epoch, e.ts_epoch, eid, n))
        before = [r[0] for r in rows_b][::-1]
        after = [r[0] for r in rows_a]
        return before + [eid] + after

    def contains_anywhere(self, value: str) -> bool:
        ids, _ = self.search([value], limit=1)
        return bool(ids)

    def iter_events(self, src: int | None = None) -> Iterator[Event]:
        q = "SELECT * FROM events" + (" WHERE src=?" if src is not None else "") + " ORDER BY id"
        cur = self.db.execute(q, (src,) if src is not None else ())
        for r in cur:
            yield self._event(r)
