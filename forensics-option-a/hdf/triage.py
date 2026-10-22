"""Phase 1: chunked triage of every event pattern by the triage model.

Per chunk results are written atomically to results/phase1/<hash>.json, keyed by
the chunk content, model and prompt version. Only successful results are reused
on resume; failed chunks are retried (and split in half if they keep failing).
Every finding is grounded against the full text of the events it cites.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .attack import Attack
from .config import Config, ModelConfig
from .grounding import Grounder
from . import output_schemas
from .llm import ContextBudgetError, LLMClient, extract_json
from .prompts import PROMPT_VERSION, SYSTEM, TRIAGE, entities_schema
from .schemas import as_entities, as_refs, as_severity, as_str, as_str_list, entity_values, as_list_of_dicts
from .store import EvidenceStore
from .util import append_jsonl, atomic_write_json, log, read_json, sha256_text

SHORTENED = " [line shortened to fit the context budget]"


@dataclass
class Chunk:
    id: str
    src: int
    label: str
    fmt: str
    constants: str
    pattern_ids: list[int]
    lines: list[str]
    tokens: int
    hash: str = ""
    shortened: list[int] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def _hosts_str(hosts_json: str, limit: int = 5) -> str:
    try:
        hosts = json.loads(hosts_json or "{}")
    except ValueError:
        hosts = {}
    items = [(h or "-", n) for h, n in hosts.items()]
    s = ", ".join(f"{h}({n})" for h, n in items[:limit])
    if len(items) > limit:
        s += f", +{len(items) - limit} more"
    return s


def pattern_line(p, view: str) -> str:
    if p["count"] == 1:
        hosts = list(json.loads(p["hosts"] or "{}").keys())
        return f"[P{p['id']}] {p['first_ts'] or 'no-timestamp'} host={hosts[0] if hosts and hosts[0] else '-'} :: {view}"
    return (f"[P{p['id']}] {p['first_ts'] or 'no-timestamp'} -> {p['last_ts'] or 'no-timestamp'} x{p['count']} "
            f"hosts={_hosts_str(p['hosts'])} :: {view}")


class Triage:
    def __init__(self, cfg: Config, store: EvidenceStore, client: LLMClient, model: ModelConfig,
                 grounder: Grounder, attack: Attack, run_dir: Path):
        self.cfg = cfg
        self.store = store
        self.client = client
        self.model = model
        self.grounder = grounder
        self.attack = attack
        self.run_dir = Path(run_dir)
        self.res_dir = self.run_dir / "results" / "phase1"
        self.audit = self.run_dir / "audit" / "rejections.jsonl"
        t = cfg.section("triage")
        self.attempts = int(t.get("attempts_per_chunk", 2))
        self.chunk_evidence_tokens = int(t.get("chunk_evidence_tokens", 0) or 0)
        self.max_split = int(t.get("max_split_depth", 3))
        self.allow_partial = bool(t.get("allow_partial", False))
        self.margin = int(cfg.get("budget", "safety_margin_tokens", default=64))

    # ------------------------------------------------------------- planning
    def plan(self) -> tuple[list[Chunk], dict]:
        fmt = self.client.formatter(self.model)
        cov = self.cfg.section("coverage")
        sources = [s for s in self.store.sources() if s["status"] in ("ok", "partial") and s["events"]]
        per_source = []
        for s in sources:
            pats = self.store.patterns_for_source(s["id"])
            reps = {e.id: e.view for e in self.store.events([p["rep_event"] for p in pats])}
            lines = [pattern_line(p, reps.get(p["rep_event"], "")) for p in pats]
            per_source.append((s, pats, lines, fmt.count_many(lines)))
        total_patterns = sum(len(x[1]) for x in per_source)
        total_events = sum(p["count"] for x in per_source for p in x[1])
        selected: set[int] | None = None
        if cov.get("mode") == "budget":
            budget = int(cov.get("llm_token_budget") or 0)
            ranked = sorted(((p["count"], len(json.loads(p["hosts"] or "{}")), p["first_epoch"] or 0, p["id"], t)
                             for _, pats, _, toks in per_source for p, t in zip(pats, toks)))
            selected, used = set(), 0
            for _, _, _, pid, t in ranked:
                if used + t > budget:
                    continue
                selected.add(pid)
                used += t
        chunks: list[Chunk] = []
        for s, pats, lines, toks in per_source:
            constants = json.loads(s["constants"] or "{}")
            const_txt = ""
            if constants:
                const_txt = ("Fields with the same value in every event of this source (omitted from lines): "
                             + "; ".join(f"{k}={v}" for k, v in constants.items()))
                if len(const_txt) > 2000:
                    const_txt = const_txt[:2000] + "…"
            overhead = fmt.count(fmt.format(SYSTEM, TRIAGE.format(
                label=s["label"], fmt=s["fmt"], constants=const_txt, lines="", entities=entities_schema())))
            budget = self.model.max_input_tokens - overhead - self.margin
            if self.chunk_evidence_tokens:
                budget = min(budget, self.chunk_evidence_tokens)
            if budget < 500:
                raise ContextBudgetError(f"instructions alone use {overhead} tokens; input budget too small")
            cur_ids, cur_lines, cur_tok, cur_short = [], [], 0, []
            n = 0

            def flush():
                nonlocal cur_ids, cur_lines, cur_tok, cur_short, n
                if cur_lines:
                    n += 1
                    c = Chunk(f"{s['label']}-c{n}", s["id"], s["label"], s["fmt"], const_txt, cur_ids, cur_lines,
                              cur_tok + overhead, shortened=cur_short)
                    c.hash = sha256_text(PROMPT_VERSION, self.model.name, str(self.model.enable_thinking),
                                         self.model.sampling, str(self.model.structured_output),
                                         const_txt, c.text)
                    chunks.append(c)
                cur_ids, cur_lines, cur_tok, cur_short = [], [], 0, []

            for p, line, t in zip(pats, lines, toks):
                if selected is not None and p["id"] not in selected:
                    continue
                t += 1  # newline
                if t > budget:
                    line = self._shorten(line, budget - fmt.count(SHORTENED) - 2)
                    t = fmt.count(line) + 1
                    cur_short.append(p["id"])
                if cur_tok + t > budget:
                    flush()
                cur_ids.append(p["id"])
                cur_lines.append(line)
                cur_tok += t
            flush()
        read_ids = {pid for c in chunks for pid in c.pattern_ids}
        read_events = sum(p["count"] for _, pats, _, _ in per_source for p in pats if p["id"] in read_ids)
        coverage = {
            "mode": cov.get("mode"), "patterns_total": total_patterns, "patterns_read": len(read_ids),
            "events_total": total_events, "events_in_read_patterns": read_events,
            "patterns_shortened": sum(len(c.shortened) for c in chunks), "chunks": len(chunks),
            "unsupported_sources": [dict(path=s["path"], status=s["status"], note=s["note"])
                                    for s in self.store.sources() if s["status"] not in ("ok",)],
        }
        return chunks, coverage

    def _shorten(self, line: str, max_tokens: int) -> str:
        fmt = self.client.formatter(self.model)
        lo, hi = 0, len(line)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if fmt.count(line[:mid]) <= max_tokens:
                lo = mid
            else:
                hi = mid - 1
        return line[:lo] + SHORTENED

    # ------------------------------------------------------------- running
    def run(self) -> dict:
        chunks, coverage = self.plan()
        atomic_write_json(self.run_dir / "state" / "phase1_plan.json",
                          {"coverage": coverage, "chunks": [{"id": c.id, "hash": c.hash, "tokens": c.tokens,
                                                             "patterns": len(c.pattern_ids)} for c in chunks]})
        log.info("[phase1] %d chunks, %d/%d patterns (%d/%d events) to read with %s",
                 len(chunks), coverage["patterns_read"], coverage["patterns_total"],
                 coverage["events_in_read_patterns"], coverage["events_total"], self.model.name)
        failed: list[str] = []
        done_hashes: list[str] = []
        for i, c in enumerate(chunks, 1):
            hashes, fails = self._process(c, 0, f"{i}/{len(chunks)}")
            done_hashes += hashes
            failed += fails
        findings = self._merge(done_hashes)
        coverage["chunks_failed"] = failed
        coverage["findings"] = len(findings)
        atomic_write_json(self.run_dir / "state" / "phase1_coverage.json", coverage)
        if failed and not self.allow_partial:
            raise RuntimeError(
                f"{len(failed)} chunk(s) could not be analysed: {failed[:10]}. Re-run the same command to retry "
                f"them, or set triage.allow_partial=true to continue with a documented coverage gap.")
        return coverage

    def _process(self, c: Chunk, depth: int, progress: str) -> tuple[list[str], list[str]]:
        path = self.res_dir / f"{c.hash}.json"
        cached = read_json(path)
        if cached and cached.get("status") == "ok":
            return [c.hash], []
        user = TRIAGE.format(label=c.label, fmt=c.fmt, constants=c.constants, lines=c.text,
                             entities=entities_schema())
        reason = ""
        for attempt in range(1, self.attempts + 1):
            note = "" if attempt == 1 else (
                "\n\nYour previous answer was incomplete or not valid JSON. Keep the reasoning short and make "
                "sure the final answer is one complete JSON object.")
            try:
                res = self.client.complete(self.model, SYSTEM, user + note, f"p1_{c.id}_d{depth}_a{attempt}",
                                           schema=output_schemas.findings())
            except ContextBudgetError as e:
                reason = str(e)
                break
            obj = extract_json(res.text, "findings", item_key="refs")
            if obj is None:
                reason = "output truncated" if res.hit_limit else "no valid JSON in output"
                log.warning("[phase1] %s %s: %s (attempt %d)", progress, c.id, reason, attempt)
                continue
            if obj.get("_salvaged"):
                log.warning("[phase1] %s %s: answer was not one valid JSON object; %d complete findings salvaged",
                            progress, c.id, len(obj["findings"]))
            findings, rejected = self._ground(c, obj)
            atomic_write_json(path, {"status": "ok", "chunk": c.id, "src": c.label, "patterns": c.pattern_ids,
                                     "findings": findings, "rejected": rejected,
                                     "salvaged": bool(obj.get("_salvaged")), "truncated": res.hit_limit,
                                     "prompt_tokens": res.prompt_tokens, "output_tokens": res.output_tokens})
            if rejected:
                append_jsonl(self.audit, [dict(phase=1, chunk=c.id, **r) for r in rejected])
            log.info("[phase1] %s %s: %d findings kept, %d claims rejected", progress, c.id, len(findings),
                     len(rejected))
            return [c.hash], []
        if depth < self.max_split and len(c.pattern_ids) > 1:
            log.warning("[phase1] %s %s: %s -> splitting", progress, c.id, reason)
            mid = len(c.pattern_ids) // 2
            hashes, fails = [], []
            for k, (ids, lines) in enumerate(((c.pattern_ids[:mid], c.lines[:mid]),
                                              (c.pattern_ids[mid:], c.lines[mid:])), 1):
                sub = Chunk(f"{c.id}.{k}", c.src, c.label, c.fmt, c.constants, ids, lines, 0,
                            shortened=[p for p in c.shortened if p in ids])
                sub.hash = sha256_text(PROMPT_VERSION, self.model.name, str(self.model.enable_thinking),
                                       c.constants, sub.text)
                h, f = self._process(sub, depth + 1, progress)
                hashes += h
                fails += f
            return hashes, fails
        atomic_write_json(path, {"status": "failed", "chunk": c.id, "reason": reason})
        log.error("[phase1] %s %s failed: %s", progress, c.id, reason)
        return [], [c.id]

    # Entity kinds specific enough to identify the line they were copied from.
    REPAIR_KINDS = ("command_lines", "files", "registry_keys", "hashes", "ips", "domains", "urls")
    REPAIR_MIN_CHARS = 8
    REPAIR_MAX_LINES = 3

    def _ground(self, c: Chunk, obj: dict) -> tuple[list[dict], list[dict]]:
        kept, rejected = [], []
        allowed = set(c.pattern_ids)
        for raw in as_list_of_dicts(obj.get("findings")):
            refs_all = as_refs(raw.get("refs"), "P")
            refs = [r for r in refs_all if r in allowed]
            for r in refs_all:
                if r not in allowed:
                    rejected.append({"kind": "ref_not_in_chunk", "value": f"P{r}"})
            ents = as_entities(raw.get("entities"))
            obs = as_str(raw.get("observation"), 1500)
            check = self._check(refs, ents, obs)
            repaired = None
            if check["unverified_specific"]:
                # The values are right but the cited line is not: re-cite the chunk lines that
                # hold every such value verbatim, then ground again (2026-10-08: the model
                # continued a P-id sequence and cited neighbour lines instead of the last one).
                new_refs, note = self._repair_refs(c, refs, check["unverified_specific"], check["verified_specific"])
                if new_refs:
                    repaired = {"from": [f"P{r}" for r in refs], "to": [f"P{r}" for r in new_refs],
                                "values": check["unverified_specific"]}
                    refs, check = new_refs, self._check(new_refs, ents, obs)
                    append_jsonl(self.audit, [dict(phase=1, chunk=c.id, kind="refs_repaired_by_content",
                                                   **repaired)])
                elif note:
                    rejected.append({"kind": note, "value": check["unverified_specific"][:5]})
            if not refs:
                rejected.append({"kind": "finding_without_valid_refs", "value": obs[:300]})
                continue
            clean, gr, pats, rep_ids = check["clean"], check["gr"], check["pats"], check["rep_ids"]
            rejected += [{"kind": f"entity_not_in_cited_events:{k}", "value": v}
                         for k, vals in check["bad"].items() for v in vals]
            if obs and not gr.ok:
                rejected.append({"kind": "observation_unverified", "value": obs, "missing": gr.missing})
            techs, bad_t = self.attack.clean_ids(as_str_list(raw.get("techniques"), join_items=True))
            rejected += [{"kind": "invalid_technique", "value": t} for t in bad_t]
            if not (obs and gr.ok) and not any(clean.values()):
                # nothing the model said about these lines survived grounding
                rejected.append({"kind": "finding_without_verified_content", "value": obs[:300],
                                 "refs": [f"P{r}" for r in refs]})
                continue
            hosts = sorted({h for p in pats for h in json.loads(p["hosts"] or "{}") if h})
            epochs = [p["first_epoch"] for p in pats if p["first_epoch"] is not None]
            f = {
                "chunk": c.id, "src": c.label, "refs": refs, "events": rep_ids,
                "first_ts": min((p["first_ts"] for p in pats if p["first_ts"]), default=None),
                "last_ts": max((p["last_ts"] for p in pats if p["last_ts"]), default=None),
                "first_epoch": min(epochs) if epochs else None,
                "hosts": hosts, "severity": as_severity(raw.get("severity")),
                "observation": obs if (obs and gr.ok) else None,
                "entities": clean, "techniques": techs,
            }
            if repaired:
                f["refs_repaired"] = repaired
            kept.append(f)
        return kept, rejected

    def _check(self, refs: list[int], ents: dict, obs: str) -> dict:
        """Ground entities and observation against the cited lines' full events."""
        pats = [p for p in (self.store.pattern(r) for r in refs) if p is not None]
        rep_ids = [p["rep_event"] for p in pats]
        hay = " ".join(self.store.norm_full(e) for e in rep_ids)
        cited_ts = [t for p in pats for t in (p["first_ts"], p["last_ts"]) if t]
        clean, bad = {}, {}
        for k, vals in ents.items():
            clean[k], bad[k] = self.grounder.filter_values(vals, hay)
        gr = self.grounder.check_text(obs, hay, cited_ts)
        def specific(d):
            return [v for k in self.REPAIR_KINDS for v in d.get(k, []) if len(v.strip()) >= self.REPAIR_MIN_CHARS]
        return {"pats": pats, "rep_ids": rep_ids, "clean": clean, "bad": bad, "gr": gr,
                "unverified_specific": specific(bad), "verified_specific": specific(clean)}

    def _repair_refs(self, c: Chunk, refs: list[int], values: list[str], verified: list[str]) -> tuple[list[int], str]:
        """Chunk lines that contain every unverified specific value that occurs in the chunk
        at all (values found nowhere stay unverified), plus the originally cited lines that
        hold a verified specific value. Returns (new refs, "") or ([], reason)."""
        lines = {}
        for pid in c.pattern_ids:
            p = self.store.pattern(pid)
            if p is not None:
                lines[pid] = self.store.norm_full(p["rep_event"])
        present = [v for v in values if any(self.grounder.value_in(v, t) for t in lines.values())]
        if not present:
            return [], ""
        cand = [pid for pid, t in lines.items() if pid not in refs
                and all(self.grounder.value_in(v, t) for v in present)]
        if not cand:
            return [], "refs_repair_no_single_line"
        if len(cand) > self.REPAIR_MAX_LINES:
            return [], "refs_repair_ambiguous"
        keep = [r for r in refs if r in lines and any(self.grounder.value_in(v, lines[r]) for v in verified)]
        return keep + cand, ""

    def _merge(self, hashes: list[str]) -> list[dict]:
        findings = []
        for h in dict.fromkeys(hashes):
            r = read_json(self.res_dir / f"{h}.json") or {}
            if r.get("status") == "ok":
                findings.extend(r.get("findings", []))
        findings.sort(key=lambda f: (f.get("first_epoch") is None, f.get("first_epoch") or 0, f["chunk"]))
        for i, f in enumerate(findings, 1):
            f["id"] = f"F{i}"
        atomic_write_json(self.run_dir / "findings.json", findings)
        n_ent = sum(len(entity_values(f["entities"])) for f in findings)
        log.info("[phase1] merged %d grounded findings (%d verified entities)", len(findings), n_ent)
        return findings
