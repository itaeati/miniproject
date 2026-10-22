"""Timestamp normalisation to timezone-aware UTC.

Every event timestamp is converted to UTC before sorting, so evidence from
different sources (different formats, offsets, epoch units) is merged into a
single chronology. Values that cannot be parsed are reported, never guessed.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

UTC = timezone.utc

_ISO = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}(?::\d{2})?)(?P<frac>[.,]\d+)?"
    r"\s*(?P<tz>Z|[+-]\d{2}:?\d{2}|UTC|GMT)?", re.IGNORECASE)
_CLF = re.compile(r"(?P<v>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})")
_SYSLOG = re.compile(r"^(?:<\d+>\d?\s*)?(?P<v>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})")
_US = re.compile(r"(?P<v>\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\s?[AP]M)?)", re.IGNORECASE)
_NUMERIC = re.compile(r"^\d{9,19}(?:\.\d+)?$")

# Plausible absolute range for evidence timestamps (1990-01-01 .. 2100-01-01).
_MIN_EPOCH = 631152000.0
_MAX_EPOCH = 4102444800.0


def to_iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class TimeParser:
    def __init__(self, default_timezone: str = "UTC", assume_year: int = 0):
        self.default_tz = UTC if default_timezone.upper() == "UTC" else ZoneInfo(default_timezone)
        self.assume_year = assume_year

    # -- public -----------------------------------------------------------
    def parse(self, value, year_hint: int | None = None) -> tuple[datetime | None, str]:
        """Return (utc_datetime, quality). quality: exact | assumed_tz | assumed_year | none."""
        if value is None or isinstance(value, bool):
            return None, "none"
        if isinstance(value, (int, float)):
            dt = self._epoch(float(value))
            return (dt, "exact") if dt else (None, "none")
        s = str(value).strip()
        if not s:
            return None, "none"
        if _NUMERIC.match(s):
            dt = self._epoch(float(s))
            return (dt, "exact") if dt else (None, "none")
        m = _ISO.match(s)
        if m and m.end() >= len(s) - 1:
            return self._from_iso_match(m)
        m = _CLF.fullmatch(s)
        if m:
            return datetime.strptime(m.group("v"), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC), "exact"
        m = _US.fullmatch(s)
        if m:
            dt = self._us(m.group("v"))
            if dt:
                return dt, "assumed_tz"
        m = _SYSLOG.match(s)
        if m and m.end() >= len(s) - 1:
            return self._syslog(m.group("v"), year_hint)
        return None, "none"

    def find_in_text(self, line: str, year_hint: int | None = None) -> tuple[datetime | None, str]:
        """Locate a timestamp inside a free-text log line (searches the line head)."""
        head = line[:200]
        m = _ISO.search(head)
        if m:
            dt, q = self._from_iso_match(m)
            if dt:
                return dt, q
        m = _CLF.search(head)
        if m:
            try:
                return datetime.strptime(m.group("v"), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC), "exact"
            except ValueError:
                pass
        m = _SYSLOG.match(head)
        if m:
            dt, q = self._syslog(m.group("v"), year_hint)
            if dt:
                return dt, q
        m = _US.search(head)
        if m:
            dt = self._us(m.group("v"))
            if dt:
                return dt, "assumed_tz"
        return None, "none"

    # -- helpers ----------------------------------------------------------
    def _epoch(self, x: float) -> datetime | None:
        for scale in (1.0, 1e3, 1e6, 1e9):
            v = x / scale
            if _MIN_EPOCH <= v <= _MAX_EPOCH:
                return datetime.fromtimestamp(v, UTC)
        return None

    def _from_iso_match(self, m: re.Match) -> tuple[datetime | None, str]:
        time_part = m.group("time")
        if len(time_part) == 5:
            time_part += ":00"
        frac = (m.group("frac") or "").replace(",", ".")
        if frac:
            frac = frac[:7]  # datetime supports microseconds (6 digits)
        tz = m.group("tz")
        try:
            dt = datetime.fromisoformat(f"{m.group('date')}T{time_part}{frac}")
        except ValueError:
            return None, "none"
        if tz:
            t = tz.upper()
            if t in ("Z", "UTC", "GMT"):
                return dt.replace(tzinfo=UTC), "exact"
            t = t if ":" in t else f"{t[:3]}:{t[3:]}"
            sign = 1 if t[0] == "+" else -1
            off = timedelta(hours=int(t[1:3]), minutes=int(t[4:6])) * sign
            return dt.replace(tzinfo=timezone(off)).astimezone(UTC), "exact"
        return dt.replace(tzinfo=self.default_tz).astimezone(UTC), "assumed_tz"

    def _us(self, v: str) -> datetime | None:
        for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M:%S%p", "%m/%d/%Y %H:%M:%S"):
            try:
                return datetime.strptime(v.upper(), fmt).replace(tzinfo=self.default_tz).astimezone(UTC)
            except ValueError:
                continue
        return None

    def _syslog(self, v: str, year_hint: int | None) -> tuple[datetime | None, str]:
        year = self.assume_year or year_hint
        if not year:
            return None, "none"
        try:
            dt = datetime.strptime(f"{year} {' '.join(v.split())}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None, "none"
        return dt.replace(tzinfo=self.default_tz).astimezone(UTC), "assumed_year"
