"""Phase 4: evidence-only report.

Report content is either computed directly from the evidence store (tables,
timeline, entities, coverage) or is model text that passed grounding checks
(hypothesis statements already verified in phase 3; narrative sentences
verified here one by one). Refuted and unverified hypotheses are not reproduced.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .attack import TECH_RE, Attack
from .config import Config, ModelConfig
from .grounding import Grounder, split_sentences
from . import output_schemas
from .llm import LLMClient, LLMError, MemoryGuardError, extract_json
from .prompts import NARRATIVE, PROMPT_VERSION, SYSTEM
from .schemas import as_refs, as_str_list
from .store import EvidenceStore
from .util import append_jsonl, atomic_write_json, atomic_write_text, log, read_jsonl

CITE_RE = re.compile(r"\[(?:\s*E\d+\s*,?)+\]")


def md_cell(s: str, limit: int = 300) -> str:
    # cut before escaping: a cut inside an escaped \| leaves a backslash that is not in the evidence
    s = (s or "").replace("\n", " ")
    s = s if len(s) <= limit else s[:limit] + "…"
    return s.replace("|", "\\|")


class Reporter:
    def __init__(self, cfg: Config, store: EvidenceStore, client: LLMClient | None, model: ModelConfig,
                 grounder: Grounder, attack: Attack, run_dir: Path):
        self.cfg = cfg
        self.store = store
        self.client = client
        self.model = model
        self.g = grounder
        self.attack = attack
        self.run_dir = Path(run_dir)
        self.audit = self.run_dir / "audit" / "rejections.jsonl"

    def _hay(self, ids) -> str:
        return " ".join(self.store.norm_full(e) for e in dict.fromkeys(ids))

    def build(self, coverage: dict, state: dict, findings: list[dict]) -> dict:
        items = {i["id"]: i for i in state.get("items_all", [])}
        hyps = state.get("hypotheses", [])
        conclusions = []
        for h in hyps:
            if h.get("status") != "SUPPORTED":
                continue
            techs = [(t, "confirmed") for t in h.get("confirmed_techniques", [])]
            if not techs:
                techs = [(t, "hypothesis") for t in h.get("techniques", [])]
            motivating = [e for r in h.get("refs", []) if r in items for e in items[r]["events"]]
            conclusions.append({
                "id": h["id"], "statement": h["statement"],
                "techniques": [{"id": t, "name": self.attack.name(t), "basis": b} for t, b in techs],
                "evidence_events": h.get("supporting_events", []),
                "motivating_events": list(dict.fromkeys(motivating)),
                "motivating_items": h.get("refs", []),
                "entities": h.get("entities", {}),
            })
        cited = list(dict.fromkeys(e for c in conclusions for e in c["evidence_events"]))
        timeline = []
        for ev in sorted(self.store.events(cited), key=lambda e: (e.ts_epoch is None, e.ts_epoch or 0, e.id)):
            timeline.append({"event": ev.id, "ts": ev.ts, "host": ev.host, "source": self.store.source_label(ev.src),
                             "file": self.store.source_path(ev.src), "line": ev.line, "view": ev.view,
                             "conclusions": [c["id"] for c in conclusions if ev.id in c["evidence_events"]]})
        entities: dict[str, list[str]] = {}
        for c in conclusions:
            hay = self._hay(c["evidence_events"] + c["motivating_events"])
            for k, vals in c["entities"].items():
                for v in vals:
                    if self.g.value_in(v, hay) and v not in entities.setdefault(k, []):
                        entities[k].append(v)
        hosts = sorted({t["host"] for t in timeline if t["host"]})
        if hosts:
            entities["hosts"] = sorted(set(entities.get("hosts", [])) | set(hosts))
        tech_index: dict[str, dict] = {}
        for c in conclusions:
            for t in c["techniques"]:
                d = tech_index.setdefault(t["id"], {"id": t["id"], "name": t["name"], "basis": set(),
                                                    "conclusions": [], "events": []})
                d["basis"].add(t["basis"])
                d["conclusions"].append(c["id"])
                d["events"] += [e for e in c["evidence_events"] if e not in d["events"]]
        techniques = [dict(v, basis=sorted(v["basis"])) for v in tech_index.values()]
        narrative, removed, narrative_note = self._narrative(conclusions)
        audit_rows = read_jsonl(self.audit)
        rej = Counter(r.get("kind", "?").split(":")[0] for r in audit_rows if r.get("kind") != "refs_repaired_by_content")
        repaired = sum(1 for r in audit_rows if r.get("kind") == "refs_repaired_by_content")
        status_counts = Counter(h.get("status") for h in hyps)
        problems = [f"triage chunk failed: {c}" for c in coverage.get("chunks_failed", [])]
        # a failed reduction is replaced by a deterministic merge and loses only lead summaries
        problems += [f"{e['step']}: {e['reason']}" for e in state.get("errors", [])
                     if not e["step"].startswith("p2_reduce")]
        notes = [f"{e['step']}: {e['reason']} (items merged without a summary)" for e in state.get("errors", [])
                 if e["step"].startswith("p2_reduce")]
        if findings and not hyps:
            problems.append("no hypothesis could be generated, so no finding was tested")
        report = {
            "status": "incomplete" if problems else "complete",
            "problems": problems,
            "notes": notes,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "engine": {"prompt_version": PROMPT_VERSION, "attack_version": self.attack.version,
                       "triage_model": self.cfg.model("triage").name, "reasoner_model": self.model.name},
            "evidence": self.store.get_meta("ingest_summary", {}),
            "coverage": coverage,
            "findings": len(findings),
            "hypotheses": dict(status_counts),
            "conclusions": conclusions,
            "techniques": techniques,
            "timeline": timeline,
            "entities": entities,
            "narrative": narrative,
            "narrative_note": narrative_note,  # why there is no summary, when generation failed
            "audit": {"rejected_claims": dict(rej), "narrative_sentences_removed": removed,
                      "citations_repaired": repaired},
        }
        atomic_write_json(self.run_dir / "report.json", report)
        atomic_write_text(self.run_dir / "report.md", self.render_md(report))
        log.info("[phase4] report: %d conclusions, %d techniques, %d timeline events",
                 len(conclusions), len(techniques), len(timeline))
        return report

    # ------------------------------------------------------------ narrative
    def _narrative(self, conclusions: list[dict]) -> tuple[list[dict], int, str]:
        """Returns (verified sentences, sentences removed, note on a failed generation)."""
        if not conclusions or not self.cfg.get("report", "narrative", default=True) or self.client is None:
            return [], 0, ""
        allowed = {e for c in conclusions for e in c["evidence_events"]}
        allowed_techs = {t["id"] for c in conclusions for t in c["techniques"]}
        fmt = self.client.formatter(self.model)
        facts, used = [], 0
        budget = self.model.max_input_tokens - fmt.count(fmt.format(SYSTEM, NARRATIVE.format(facts="", n=8))) - 200
        for c in conclusions:
            lines = [f"[{c['id']}] {c['statement']}"]
            if c["techniques"]:
                lines.append("  techniques: " + ", ".join(f"{t['id']} {t['name']}" for t in c["techniques"]))
            for ev in self.store.events(c["evidence_events"][:12]):
                lines.append(f"  [E{ev.id}] {ev.ts or 'no-timestamp'} host={ev.host or '-'} :: {md_cell(ev.view, 400)}")
            block = "\n".join(lines)
            t = fmt.count(block)
            if used + t > budget:
                break
            facts.append(block)
            used += t
        try:
            res = self.client.complete(self.model, SYSTEM, NARRATIVE.format(facts="\n".join(facts), n=8), "p4_narrative",
                                       schema=output_schemas.summary(8))
        except MemoryGuardError:
            raise
        except LLMError as e:
            log.warning("[phase4] narrative skipped: %s", e)
            return [], 0, f"summary request failed ({type(e).__name__}); see the run log"
        note = ""
        if res.hit_limit:
            note = (f"summary generation did not finish (finish={res.finish or 'unknown'}, "
                    f"{res.output_tokens} output tokens)")
            log.warning("[phase4] %s", note)
        obj = extract_json(res.text, "summary") or {}
        if "summary" not in obj and not note:
            note = "summary answer had no summary field"
            log.warning("[phase4] %s", note)
        kept, removed = [], 0
        for s in as_str_list(obj.get("summary"), 20, 2000):
            for sent in split_sentences(s):
                cites = [e for e in as_refs(sent, "E") if e in allowed]
                body = CITE_RE.sub("", sent).strip()
                if not cites or not body:
                    removed += 1
                    append_jsonl(self.audit, [{"phase": 4, "kind": "narrative_sentence_without_valid_citation",
                                               "value": sent}])
                    continue
                ts = [e.ts for e in self.store.events(cites) if e.ts]
                gr = self.g.check_text(body, self._hay(cites), ts)
                bad_t = [t for t in TECH_RE.findall(body) if t not in allowed_techs]
                if bad_t:
                    gr.ok, gr.missing = False, gr.missing + bad_t
                if not gr.ok:
                    removed += 1
                    append_jsonl(self.audit, [{"phase": 4, "kind": "narrative_sentence_unverified",
                                               "value": sent, "missing": gr.missing}])
                    continue
                kept.append({"text": body, "events": cites})
        return kept, removed, note

    @staticmethod
    def _clock_txt(clock) -> str:
        try:
            c = json.loads(clock) if isinstance(clock, str) else (clock or {})
        except ValueError:
            return "-"
        parts = [f"{k}→{c.get('reference')} {v['offset_s']:+g}s" for k, v in (c.get("aligned") or {}).items()]
        parts += [f"{k}: NOT aligned ({v['events']} events, order uncertain)" for k, v in (c.get("unaligned") or {}).items()]
        return md_cell("; ".join(parts), 200) if parts else (c.get("reference") or "-")

    # ------------------------------------------------------------ markdown
    def render_md(self, r: dict) -> str:
        L = []
        L.append("# Forensic Investigation Report\n")
        L.append(f"Generated {r['generated_at']} · triage model `{r['engine']['triage_model']}` · reasoning model "
                 f"`{r['engine']['reasoner_model']}` · ATT&CK v{r['engine']['attack_version']} · prompts "
                 f"`{r['engine']['prompt_version']}`\n")
        L.append("> Every statement in this report is either computed directly from the evidence store or is a model "
                 "assessment whose concrete values (hosts, accounts, paths, addresses, times, names) were checked "
                 "against the events it cites. `E<n>` identifies an event in `evidence.db`; its source file and "
                 "line are listed in the timeline.\n")
        ev = r.get("evidence", {})
        cov = r.get("coverage", {})
        if r.get("status") == "incomplete":
            L.append("**Status: INCOMPLETE.** The analysis did not run to completion; the absence of conclusions "
                     "below is not a negative finding.\n")
            for p in r.get("problems", []):
                L.append(f"- {md_cell(p, 400)}")
            L.append("")
        L.append("## 1. Evidence and coverage\n")
        L.append(f"- Events: {ev.get('events', '?')} · hosts: {ev.get('hosts', '?')} · time range: "
                 f"{ev.get('first_ts')} .. {ev.get('last_ts')} · events without timestamp: "
                 f"{ev.get('events_without_timestamp', 0)}")
        L.append(f"- Triage coverage ({cov.get('mode')}): {cov.get('patterns_read')}/{cov.get('patterns_total')} event "
                 f"patterns read, representing {cov.get('events_in_read_patterns')}/{cov.get('events_total')} events; "
                 f"{cov.get('patterns_shortened', 0)} pattern lines shortened; failed chunks: "
                 f"{len(cov.get('chunks_failed', []))}")
        L.append(f"- Triage findings kept after grounding: {r.get('findings', 0)} · hypotheses: "
                 + ", ".join(f"{k} {v}" for k, v in sorted(r.get("hypotheses", {}).items())) + "\n")
        L.append("| Source | File | Format | Status | Events | Parse errors | No timestamp | Clock |")
        L.append("|---|---|---|---|---|---|---|---|")
        for s in ev.get("sources", []):
            L.append(f"| {s['label']} | {md_cell(Path(s['path']).name, 80)} | {s['fmt']} | {s['status']} | "
                     f"{s['events']} | {s['parse_errors']} | {s['no_timestamp']} | {self._clock_txt(s.get('clock'))} |")
        L.append("")
        L.append("## 2. Conclusions supported by evidence\n")
        if not r["conclusions"]:
            L.append("No hypothesis reached SUPPORTED status. No conclusions are drawn."
                     + (" The run is incomplete (see the status above)." if r.get("status") == "incomplete" else "")
                     + "\n")
        for c in r["conclusions"]:
            L.append(f"### {c['id']}. {c['statement']}\n")
            if c["techniques"]:
                L.append("ATT&CK: " + "; ".join(
                    f"{t['id']} {t['name']} ({'confirmed on cited events' if t['basis'] == 'confirmed' else 'from the supported hypothesis'})"
                    for t in c["techniques"]) + "\n")
            L.append("| Event | Time (UTC) | Host | Content |")
            L.append("|---|---|---|---|")
            for e in self.store.events(c["evidence_events"]):
                L.append(f"| E{e.id} | {e.ts or '-'} | {md_cell(e.host, 60)} | {md_cell(e.view)} |")
            L.append("")
        L.append("## 3. Timeline of supporting evidence\n")
        if r["timeline"]:
            L.append("| Time (UTC) | Event | Host | Source:line | Conclusions |")
            L.append("|---|---|---|---|---|")
            for t in r["timeline"]:
                L.append(f"| {t['ts'] or '-'} | E{t['event']} | {md_cell(t['host'], 60)} | {t['source']}:{t['line']} | "
                         f"{', '.join(t['conclusions'])} |")
        else:
            L.append("(none)")
        L.append("")
        L.append("## 4. Entities in supporting evidence\n")
        if r["entities"]:
            for k, vals in r["entities"].items():
                if vals:
                    L.append(f"- {k}: " + ", ".join(f"`{md_cell(v, 200)}`" for v in vals))
        else:
            L.append("(none)")
        L.append("")
        L.append("## 5. Summary (model-written; every sentence checked against its cited events)\n")
        if r["narrative"]:
            for s in r["narrative"]:
                L.append(f"- {s['text']} [" + ", ".join(f"E{e}" for e in s["events"]) + "]")
        else:
            L.append(f"(no summary: {r['narrative_note']})" if r.get("narrative_note") else "(no summary)")
        if r["narrative"] and r.get("narrative_note"):
            L.append(f"\n(partial: {r['narrative_note']})")
        L.append("")
        L.append("## 6. Not concluded\n")
        hc = r.get("hypotheses", {})
        L.append(f"- Refuted hypotheses: {hc.get('REFUTED', 0)}; unverified hypotheses: {hc.get('UNVERIFIED', 0)}. "
                 "Their statements are not conclusions and are kept only in `state/investigation.json`.")
        rc = r["audit"]["rejected_claims"]
        if rc:
            L.append("- Model claims removed by grounding checks: " +
                     ", ".join(f"{k}: {v}" for k, v in sorted(rc.items())) + " (details: `audit/rejections.jsonl`).")
        if r["audit"].get("citations_repaired"):
            L.append(f"- Phase-1 findings re-cited to the line that holds their values verbatim: "
                     f"{r['audit']['citations_repaired']} (the model cited a different line; details: "
                     f"`refs_repaired_by_content` in `audit/rejections.jsonl`).")
        if r["audit"]["narrative_sentences_removed"]:
            L.append(f"- Summary sentences removed: {r['audit']['narrative_sentences_removed']}.")
        L.append("")
        return "\n".join(L) + "\n"
