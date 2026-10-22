"""Phases 2-3: hierarchical reduction, hypothesis generation, drill-down
verification and the two feedback paths.

Feedback path 1: refuted / unverifiable hypotheses (with reasons) are fed back
into hypothesis generation so that alternatives are proposed instead.
Feedback path 2: new pivot values found in evidence are searched across the
whole evidence store; the events found are fed back into hypothesis generation.

Verdict rules enforced in code, independent of the model:
- SUPPORTED needs at least one cited event that was actually shown to the model,
  and every artifact in the hypothesis must occur in the cited / motivating events.
- REFUTED needs cited refuting events. No matches is INSUFFICIENT, never REFUTED.
- Hypotheses still unresolved at the end are UNVERIFIED and are not conclusions.
"""
from __future__ import annotations

import re
from pathlib import Path

from .attack import Attack
from .config import Config, ModelConfig
from .grounding import Grounder
from . import output_schemas
from .llm import ContextBudgetError, LLMClient, LLMError, extract_json
from .prompts import EVALUATE, HYPOTHESIZE, REDUCE, SYSTEM, entities_schema
from .schemas import (as_entities, as_list_of_dicts, as_refs, as_severity, as_str, as_str_list, as_verdict,
                      entity_values)
from .store import EvidenceStore, norm_text
from .timeparse import TimeParser
from .util import append_jsonl, atomic_write_json, log, read_json, sha256_text

SEV_RANK = {"high": 3, "medium": 2, "low": 1}
ITEM_REF = re.compile(r"\b([FL])(\d+)\b", re.I)


def _ents_str(ents: dict) -> str:
    parts = [f"{k}=" + "; ".join(v) for k, v in ents.items() if v]
    return " | ".join(parts)


class Investigation:
    def __init__(self, cfg: Config, store: EvidenceStore, client: LLMClient, model: ModelConfig,
                 grounder: Grounder, attack: Attack, run_dir: Path):
        self.cfg = cfg
        self.store = store
        self.client = client
        self.model = model
        self.g = grounder
        self.attack = attack
        self.run_dir = Path(run_dir)
        inv = cfg.section("investigation")
        self.max_iter = int(inv.get("max_iterations", 4))
        self.max_h = int(inv.get("max_hypotheses", 5))
        self.evidence_tokens = int(inv.get("evidence_tokens", 7000))
        self.k_matches = int(inv.get("matches_per_query", 6))
        self.k_neighbors = int(inv.get("neighbor_events", 3))
        self.max_q = int(inv.get("max_queries_per_hypothesis", 4))
        self.max_pivots = int(inv.get("max_pivots_per_iteration", 8))
        self.margin = int(cfg.get("budget", "safety_margin_tokens", default=64))
        ing = cfg.section("ingest")
        self.tp = TimeParser(ing.get("default_timezone", "UTC"), int(ing.get("assume_year") or 0))
        self.audit = self.run_dir / "audit" / "rejections.jsonl"
        self.state_path = self.run_dir / "state" / "investigation.json"
        self.hosts_lower = {h.lower(): h for h in store.hosts() if h}
        self.items: dict[str, dict] = {}
        self.errors: list[dict] = []
        self.failed_prompts: set[str] = set()

    # ================================================================ utils
    def _fmt(self):
        return self.client.formatter(self.model)

    def _reject(self, phase: int, kind: str, value, **extra) -> None:
        append_jsonl(self.audit, [dict(phase=phase, kind=kind, value=value, **extra)])

    def _hay(self, event_ids) -> str:
        return " ".join(self.store.norm_full(e) for e in dict.fromkeys(event_ids))

    def _event_line(self, eid: int, mark: str = "") -> str:
        e = self.store.event(eid)
        if not e:
            return ""
        src = self.store.source_label(e.src)
        return f"[E{e.id}]{mark} {e.ts or 'no-timestamp'} host={e.host or '-'} src={src}:{e.line} :: {e.view}"

    def _schema(self, key: str) -> dict:
        if key == "leads":
            return output_schemas.leads()
        if key == "hypotheses":
            return output_schemas.hypotheses(self.max_h, self.max_q)
        if key == "verdict":
            return output_schemas.verdict(self.max_q)
        raise ValueError(f"no output schema for {key!r}")

    def _ask(self, prompt: str, key: str, tag: str) -> dict | None:
        h = sha256_text(self.model.name, prompt)
        if h in self.failed_prompts:
            log.warning("[phase2] %s: identical request already failed; not repeated", tag)
            return None
        reasons = []
        for attempt in (1, 2):
            note = "" if attempt == 1 else ("\n\nYour previous answer was incomplete or not valid JSON. Keep the "
                                            "reasoning short and output one complete JSON object.")
            try:
                res = self.client.complete(self.model, SYSTEM, prompt + note, f"{tag}_a{attempt}",
                                           schema=self._schema(key))
            except ContextBudgetError as e:
                log.warning("[phase2] %s: %s", tag, e)
                self.errors.append({"step": tag, "reason": str(e)[:300]})
                self.failed_prompts.add(h)
                return None
            obj = extract_json(res.text, key)
            if obj is not None:
                return obj
            reasons.append("truncated output" if res.hit_limit else "no valid JSON")
            log.warning("[phase2] %s: %s (attempt %d)", tag, reasons[-1], attempt)
        self.errors.append({"step": tag, "reason": "; ".join(reasons)})
        self.failed_prompts.add(h)
        return None

    # ================================================================ items
    def _finding_item(self, f: dict) -> dict:
        t = f"{f.get('first_ts') or 'no-timestamp'}"
        if f.get("last_ts") and f.get("last_ts") != f.get("first_ts"):
            t += f" .. {f['last_ts']}"
        text = (f"[{f['id']}] {t} sev={f['severity']} hosts={','.join(f.get('hosts') or []) or '-'} "
                f"src={f['src']} events={','.join('E%d' % e for e in f['events'][:6])}"
                f" | observation: {f.get('observation') or '(not verified, see entities)'}")
        ents = _ents_str(f.get("entities", {}))
        if ents:
            text += f" | entities: {ents}"
        if f.get("techniques"):
            text += f" | techniques: {', '.join(f['techniques'])}"
        return {"id": f["id"], "text": text, "events": list(f["events"]), "severity": f["severity"],
                "epoch": f.get("first_epoch"), "entities": f.get("entities", {}),
                "techniques": list(f.get("techniques", [])), "first_ts": f.get("first_ts"),
                "last_ts": f.get("last_ts")}

    def _reduce(self, items: list[dict]) -> list[dict]:
        fmt = self._fmt()
        hyp_overhead = fmt.count(fmt.format(SYSTEM, HYPOTHESIZE.format(
            overview=self._overview(), items="", context="", max_h=self.max_h, entities=entities_schema())))
        # leave room for the feedback context blocks added in later iterations
        reserve = min(2500, self.model.max_input_tokens // 5)
        target = self.model.max_input_tokens - hyp_overhead - self.margin - reserve
        if target < 200:
            raise ContextBudgetError(f"reasoner input budget too small for hypothesis generation (target {target})")
        red_overhead = fmt.count(fmt.format(SYSTEM, REDUCE.format(items="", entities=entities_schema())))
        batch_budget = self.model.max_input_tokens - red_overhead - self.margin
        level, next_l = 0, 1
        for it in items:
            it["tokens"] = fmt.count(it["text"]) + 1
        while sum(i["tokens"] for i in items) > target:
            level += 1
            before = sum(i["tokens"] for i in items)
            log.info("[phase2] reduce level %d: %d items, %d tokens > %d", level, len(items), before, target)
            batches, cur, cur_t = [], [], 0
            for it in sorted(items, key=lambda i: (i["epoch"] is None, i["epoch"] or 0)):
                if cur and cur_t + it["tokens"] > batch_budget:
                    batches.append(cur)
                    cur, cur_t = [], 0
                cur.append(it)
                cur_t += it["tokens"]
            if cur:
                batches.append(cur)
            new_items = []
            for b_i, batch in enumerate(batches, 1):
                leads, next_l = self._reduce_batch(batch, level, b_i, next_l)
                new_items.extend(leads)
            for it in new_items:
                it["tokens"] = fmt.count(it["text"]) + 1
            after = sum(i["tokens"] for i in new_items)
            items = new_items
            if after >= before * 0.95 or level >= 8:
                raise RuntimeError(f"hierarchical reduction is not converging ({before} -> {after} tokens)")
        return items

    def _reduce_batch(self, batch: list[dict], level: int, b_i: int, next_l: int) -> tuple[list[dict], int]:
        by_id = {i["id"].upper(): i for i in batch}
        prompt = REDUCE.format(items="\n".join(i["text"] for i in batch), entities=entities_schema())
        obj = self._ask(prompt, "leads", f"p2_reduce_l{level}_b{b_i}")
        leads, covered = [], set()
        for raw in as_list_of_dicts((obj or {}).get("leads")):
            refs = [f"{p.upper()}{n}" for p, n in ITEM_REF.findall(" ".join(as_str_list(raw.get("refs"))))]
            refs = [r for r in dict.fromkeys(refs) if r in by_id]
            if not refs:
                self._reject(2, "lead_without_valid_refs", as_str(raw.get("summary"))[:300])
                continue
            covered.update(refs)
            leads.append(self._make_lead(raw, [by_id[r] for r in refs], next_l))
            next_l += 1
        # Items the model did not cite are merged deterministically so nothing is lost.
        rest = [i for i in batch if i["id"].upper() not in covered]
        if rest:
            leads.append(self._make_lead({}, rest, next_l, deterministic=True))
            next_l += 1
        return leads, next_l

    def _make_lead(self, raw: dict, members: list[dict], n: int, deterministic: bool = False) -> dict:
        events = list(dict.fromkeys(e for m in members for e in m["events"]))
        hay = self._hay(events)
        member_ts = [t for m in members for t in (m.get("first_ts"), m.get("last_ts")) if t]
        summary = None
        if not deterministic:
            s = as_str(raw.get("summary"), 1500)
            gr = self.g.check_text(s, hay, member_ts)
            if s and gr.ok:
                summary = s
            elif s:
                self._reject(2, "lead_summary_unverified", s, missing=gr.missing)
        ents = {}
        if deterministic:
            for m in members:
                for k, vals in m["entities"].items():
                    ents.setdefault(k, [])
                    ents[k] += [v for v in vals if v not in ents[k]]
            techs = list(dict.fromkeys(t for m in members for t in m["techniques"]))
        else:
            for k, vals in as_entities(raw.get("entities")).items():
                ok, bad = self.g.filter_values(vals, hay)
                ents[k] = ok
                for v in bad:
                    self._reject(2, f"lead_entity_unverified:{k}", v)
            techs, bad_t = self.attack.clean_ids(as_str_list(raw.get("techniques"), join_items=True))
            for t in bad_t:
                self._reject(2, "invalid_technique", t)
        sev = max((m["severity"] for m in members), key=lambda s: SEV_RANK.get(s, 0))
        if not deterministic:
            sev = max(sev, as_severity(raw.get("severity")), key=lambda s: SEV_RANK.get(s, 0))
        epochs = [m["epoch"] for m in members if m["epoch"] is not None]
        first = min((m["first_ts"] for m in members if m.get("first_ts")), default=None)
        last = max((m["last_ts"] for m in members if m.get("last_ts")), default=None)
        lid = f"L{n}"
        refs = ",".join(m["id"] for m in members)
        text = (f"[{lid}] {first or 'no-timestamp'} .. {last or 'no-timestamp'} sev={sev} refs={refs}"
                f" | summary: {summary or ('(merged without summary)' if deterministic else '(not verified)')}")
        es = _ents_str(ents)
        if es:
            text += f" | entities: {es}"
        if techs:
            text += f" | techniques: {', '.join(techs)}"
        item = {"id": lid, "text": text, "events": events, "severity": sev, "epoch": min(epochs) if epochs else None,
                "entities": ents, "techniques": techs, "first_ts": first, "last_ts": last,
                "members": [m["id"] for m in members]}
        self.items[lid] = item
        return item

    # ================================================================ hypotheses
    def _overview(self) -> str:
        st = self.store.stats()
        srcs = self.store.sources()
        lines = [f"- events: {st['events']} in {len(srcs)} sources; time range {st['first_ts']} .. {st['last_ts']}",
                 f"- hosts ({st['hosts']}): " + ", ".join(sorted(h for h in self.hosts_lower.values())[:40])]
        for s in srcs:
            lines.append(f"- source {s['label']}: format {s['fmt']}, {s['events']} events, status {s['status']}")
        return "\n".join(lines)

    def _context_block(self, hyps: list[dict], pivot_events: list[int], budget: int) -> str:
        fmt = self._fmt()
        parts = []
        sup = [h for h in hyps if h["status"] == "SUPPORTED"]
        rej = [h for h in hyps if h["status"] in ("REFUTED", "UNVERIFIED") or
               (h["status"] == "INSUFFICIENT" and not h["pending"])]
        if sup:
            parts.append("Hypotheses already supported by evidence (do not repeat):\n" +
                         "\n".join(f"- [{h['id']}] {h['statement']}" for h in sup))
        if rej:
            parts.append("Hypotheses rejected or not verifiable so far (do not repeat; consider alternatives):\n" +
                         "\n".join(f"- [{h['id']}] {h['statement']} -- {h['status']}: {h.get('reason') or ''}"
                                   for h in rej))
        text = "\n\n".join(parts)
        if pivot_events:
            head = "\n\nEvents found by searching new pivot values across all evidence:\n"
            lines, used = [], fmt.count(text + head)
            for eid in pivot_events:
                ln = self._event_line(eid)
                t = fmt.count(ln) + 1
                if used + t > budget:
                    break
                lines.append(ln)
                used += t
            if lines:
                text += head + "\n".join(lines)
        if fmt.count(text) > budget:  # keep the newest information
            while parts and fmt.count(text) > budget:
                parts.pop(0)
                text = "\n\n".join(parts)
        return ("\n" + text + "\n") if text else ""

    def _generate(self, items: list[dict], hyps: list[dict], pivot_events: list[int], it: int) -> list[dict]:
        fmt = self._fmt()
        overview = self._overview()
        items_txt = "\n".join(i["text"] for i in items)
        base = HYPOTHESIZE.format(overview=overview, items=items_txt, context="", max_h=self.max_h,
                                  entities=entities_schema())
        room = self.model.max_input_tokens - fmt.count(fmt.format(SYSTEM, base)) - self.margin
        context = self._context_block(hyps, pivot_events, max(0, room))
        prompt = HYPOTHESIZE.format(overview=overview, items=items_txt, context=context, max_h=self.max_h,
                                    entities=entities_schema())
        obj = self._ask(prompt, "hypotheses", f"p2_hypothesize_i{it}")
        out = []
        existing = {norm_text(h["statement"]) for h in hyps}
        for raw in as_list_of_dicts((obj or {}).get("hypotheses"))[: self.max_h]:
            h = self._clean_hypothesis(raw, len(hyps) + len(out) + 1)
            if h and norm_text(h["statement"]) not in existing:
                out.append(h)
                existing.add(norm_text(h["statement"]))
        return out

    def _store_has(self, value: str) -> bool:
        return self.store.contains_anywhere(value)

    def _clean_hypothesis(self, raw: dict, n: int) -> dict | None:
        statement = as_str(raw.get("statement"), 1500)
        if not statement:
            return None
        refs = [f"{p.upper()}{k}" for p, k in ITEM_REF.findall(" ".join(as_str_list(raw.get("refs"))))]
        refs = [r for r in dict.fromkeys(refs) if r in self.items]
        # every artifact or actor/software name in the statement must exist somewhere in the evidence
        missing = []
        from .grounding import extract_artifacts
        for kind, val in extract_artifacts(statement):
            if kind in ("datetime", "time"):
                continue
            if not self._store_has(val):
                missing.append(val)
        for name in self.attack.named_actors(statement) + self.attack.named_software(statement):
            if not self._store_has(name):
                missing.append(name)
        if missing:
            self._reject(2, "hypothesis_mentions_values_not_in_evidence", statement, missing=missing)
            return None
        ents = {}
        for k, vals in as_entities(raw.get("entities")).items():
            ents[k] = [v for v in vals if self._store_has(v)]
            for v in vals:
                if v not in ents[k]:
                    self._reject(2, f"hypothesis_entity_not_in_evidence:{k}", v)
        techs, bad_t = self.attack.clean_ids(as_str_list(raw.get("techniques"), join_items=True))
        for t in bad_t:
            self._reject(2, "invalid_technique", t)
        queries = self._clean_queries(raw.get("queries"))
        if not queries:  # deterministic fallback: search each verified entity
            queries = [{"purpose": "locate entity", "keywords": [v], "host": None, "t_from": None, "t_to": None}
                       for v in entity_values(ents)[: self.max_q]]
        return {"id": f"H{n}", "statement": statement, "refs": refs, "techniques": techs, "entities": ents,
                "pending": queries, "tested": [], "status": "OPEN", "reason": "", "supporting_events": [],
                "refuting_events": [], "confirmed_techniques": [], "history": []}

    def _clean_queries(self, raw) -> list[dict]:
        out = []
        for q in as_list_of_dicts(raw)[: self.max_q]:
            kws = [k for k in as_str_list(q.get("keywords"), 5, 300) if len(k.strip()) >= 2]
            if not kws:
                continue
            host = as_str(q.get("host"))
            host = self.hosts_lower.get(host.lower()) if host else None
            tf, _ = self.tp.parse(as_str(q.get("time_from"))) if as_str(q.get("time_from")) else (None, "")
            tt, _ = self.tp.parse(as_str(q.get("time_to"))) if as_str(q.get("time_to")) else (None, "")
            out.append({"purpose": as_str(q.get("purpose"), 300), "keywords": kws, "host": host,
                        "t_from": tf.timestamp() if tf else None, "t_to": tt.timestamp() if tt else None})
        return out

    # ================================================================ evaluation
    def _evidence(self, queries: list[dict]) -> tuple[str, list[int], int]:
        fmt = self._fmt()
        blocks, shown, total_matches = [], [], 0
        used = 0
        budget = self.evidence_tokens
        for qi, q in enumerate(queries, 1):
            ids, total = self.store.search(q["keywords"], q["host"], q["t_from"], q["t_to"])
            total_matches += total
            if total <= self.k_matches:
                sample = ids
            else:  # spread samples across the whole time range of the matches
                step = (len(ids) - 1) / (self.k_matches - 1)
                sample = [ids[round(i * step)] for i in range(self.k_matches)]
            head = (f"Search {qi}: keywords={q['keywords']} host={q['host'] or 'any'} "
                    f"window={q['t_from'] or '-'}..{q['t_to'] or '-'} -> {total} matching events"
                    + (f"; {len(sample)} shown (* = match)" if total else ""))
            used += fmt.count(head) + 2
            lines = [head]
            for eid in sample:
                for nb in self.store.neighbors(eid, self.k_neighbors):
                    if nb in shown:
                        continue
                    ln = self._event_line(nb, "*" if nb == eid else "")
                    t = fmt.count(ln) + 1
                    if used + t > budget:
                        break
                    lines.append(ln)
                    shown.append(nb)
                    used += t
            blocks.append("\n".join(lines))
        return "\n\n".join(blocks), shown, total_matches

    def _evaluate(self, h: dict, it: int) -> list[dict]:
        """Run the hypothesis' pending queries and update its status. Returns new pivots."""
        queries = h["pending"][: self.max_q]
        h["pending"] = h["pending"][self.max_q:]
        h["tested"] += queries
        fmt = self._fmt()
        support_txt = "\n".join(self.items[r]["text"] for r in h["refs"] if r in self.items) or "(none)"
        base = EVALUATE.format(statement=h["statement"], techniques=", ".join(h["techniques"]) or "(none)",
                               support=support_txt, evidence="")
        room = self.model.max_input_tokens - fmt.count(fmt.format(SYSTEM, base)) - self.margin
        if room < 800:  # trim motivating findings to leave room for evidence
            support_txt = support_txt[: max(500, len(support_txt) // 3)] + " …"
            base = EVALUATE.format(statement=h["statement"], techniques=", ".join(h["techniques"]) or "(none)",
                                   support=support_txt, evidence="")
            room = self.model.max_input_tokens - fmt.count(fmt.format(SYSTEM, base)) - self.margin
        saved = self.evidence_tokens
        self.evidence_tokens = max(300, min(self.evidence_tokens, room))
        evidence, shown, total = self._evidence(queries)
        self.evidence_tokens = saved
        record = {"iteration": it, "queries": queries, "matches": total, "shown": len(shown)}
        if not shown:
            h["status"], h["reason"] = "INSUFFICIENT", "no events matched the verification searches"
            h["history"].append(dict(record, verdict="INSUFFICIENT", note="no matches"))
            return []
        prompt = EVALUATE.format(statement=h["statement"], techniques=", ".join(h["techniques"]) or "(none)",
                                 support=support_txt, evidence=evidence)
        obj = self._ask(prompt, "verdict", f"p3_eval_{h['id']}_i{it}")
        if obj is None:
            h["status"], h["reason"] = "INSUFFICIENT", "model returned no usable verdict"
            h["history"].append(dict(record, verdict="INSUFFICIENT", note="no usable verdict"))
            return []
        shown_set = set(shown)
        verdict = as_verdict(obj.get("verdict"))
        sup = [e for e in as_refs(obj.get("supporting_events"), "E") if e in shown_set]
        refu = [e for e in as_refs(obj.get("refuting_events"), "E") if e in shown_set]
        for e in as_refs(obj.get("supporting_events"), "E") + as_refs(obj.get("refuting_events"), "E"):
            if e not in shown_set:
                self._reject(3, "cited_event_not_shown", f"E{e}", hypothesis=h["id"])
        motivating = [e for r in h["refs"] if r in self.items for e in self.items[r]["events"]]
        reason = ""
        if verdict == "SUPPORTED":
            hay = self._hay(sup + motivating)
            ts = [self.store.event(e).ts for e in sup + motivating if self.store.event(e)]
            gr = self.g.check_text(h["statement"], hay, [t for t in ts if t])
            missing_ents = [v for v in entity_values(h["entities"]) if not self.g.value_in(v, hay)]
            if not sup:
                verdict, reason = "INSUFFICIENT", "model said SUPPORTED but cited no shown event"
            elif not gr.ok or missing_ents:
                verdict = "INSUFFICIENT"
                reason = f"claimed values not in cited events: {sorted(set(gr.missing + missing_ents))[:8]}"
        elif verdict == "REFUTED" and not refu:
            verdict, reason = "INSUFFICIENT", "model said REFUTED but cited no shown event"
        rationale = as_str(obj.get("rationale"), 2000)
        rgr = self.g.check_text(rationale, self._hay(shown + motivating))
        if rationale and not rgr.ok:
            self._reject(3, "rationale_unverified", rationale, hypothesis=h["id"], missing=rgr.missing)
            rationale = ""
        techs, bad_t = self.attack.clean_ids(as_str_list(obj.get("confirmed_techniques"), join_items=True))
        for t in bad_t:
            self._reject(3, "invalid_technique", t)
        h["status"] = verdict
        h["reason"] = reason or rationale or ""
        if verdict == "SUPPORTED":
            h["supporting_events"] = list(dict.fromkeys(h["supporting_events"] + sup))
            h["confirmed_techniques"] = list(dict.fromkeys(h["confirmed_techniques"] + techs))
        elif verdict == "REFUTED":
            h["refuting_events"] = list(dict.fromkeys(h["refuting_events"] + refu))
        else:
            tested = {tuple(q["keywords"]) for q in h["tested"]}
            for q in self._clean_queries(obj.get("follow_up_queries")):
                if tuple(q["keywords"]) not in tested:
                    h["pending"].append(q)
        h["history"].append(dict(record, verdict=verdict, reason=h["reason"], supporting=sup, refuting=refu))
        pivots = []
        for p in as_list_of_dicts(obj.get("new_pivots"), 20):
            val = as_str(p.get("value"), 300)
            refs = [e for e in as_refs(p.get("refs"), "E") if e in shown_set]
            if val and len(val) >= 3 and refs and self.g.value_in(val, self._hay(refs)):
                pivots.append({"value": val, "refs": refs, "from": h["id"]})
            elif val:
                self._reject(3, "pivot_unverified", val, hypothesis=h["id"])
        return pivots

    # ================================================================ main loop
    def run(self, findings: list[dict]) -> dict:
        state = read_json(self.state_path) or {}
        if state.get("done"):
            log.info("[phase2] investigation already complete; reusing state")
            self.items = {i["id"]: i for i in state.get("items_all", [])}
            return state
        self.items = {}
        for f in findings:
            it = self._finding_item(f)
            self.items[it["id"]] = it
        if state.get("items"):
            self.items.update({i["id"]: i for i in state.get("items_all", [])})
            items = [self.items[i] for i in state["items"] if i in self.items]
            hyps = state.get("hypotheses", [])
            pivots = state.get("pivots", {})
            pivot_events = state.get("pivot_events", [])
            self.errors = state.get("errors", [])
            self.failed_prompts = set(state.get("failed_prompts", []))
            start = int(state.get("iteration", 0)) + 1
            log.info("[phase2] resuming at iteration %d", start)
        else:
            if not findings:
                log.warning("[phase2] no grounded findings from phase 1; nothing to investigate")
                state = {"done": True, "hypotheses": [], "items": [], "items_all": [], "pivots": {},
                         "pivot_events": [], "iteration": 0, "note": "no findings"}
                atomic_write_json(self.state_path, state)
                return state
            items = self._reduce(list(self.items.values()))
            hyps = self._generate(items, [], [], 0)
            pivots, pivot_events, start = {}, [], 1
            self._save(items, hyps, pivots, pivot_events, 0, False)
        it = start - 1
        for it in range(start, self.max_iter + 1):
            log.info("[phase3] iteration %d: %d hypotheses (%s)", it, len(hyps),
                     ", ".join(f"{h['id']}={h['status']}" for h in hyps))
            changed = False
            for h in hyps:
                if h["status"] in ("OPEN", "INSUFFICIENT") and h["pending"]:
                    before = h["status"]
                    for p in self._evaluate(h, it):
                        if p["value"] not in pivots:
                            pivots[p["value"]] = {"refs": p["refs"], "from": p["from"], "searched": False}
                    changed |= h["status"] != before or h["status"] == "INSUFFICIENT" and bool(h["pending"])
                    log.info("[phase3]   %s -> %s %s", h["id"], h["status"], h["reason"][:160])
            # feedback path 2: search new pivots across all evidence
            new_events = []
            for val in [v for v, p in pivots.items() if not p["searched"]][: self.max_pivots]:
                ids, total = self.store.search([val])
                pivots[val]["searched"] = True
                pivots[val]["matches"] = total
                pick = ids if len(ids) <= 4 else [ids[0], ids[len(ids) // 3], ids[2 * len(ids) // 3], ids[-1]]
                new_events += [e for e in pick if e not in pivot_events and e not in new_events]
            if new_events:
                pivot_events += new_events
                changed = True
                log.info("[phase3]   pivot search added %d events", len(new_events))
            # feedback path 1: regenerate with rejected hypotheses and pivot evidence as context
            needs_regen = new_events or any(h["status"] == "REFUTED" and not h.get("fed_back") for h in hyps) or \
                all(h["status"] in ("SUPPORTED", "REFUTED") or not h["pending"] for h in hyps)
            if needs_regen and it < self.max_iter:
                for h in hyps:
                    if h["status"] == "REFUTED":
                        h["fed_back"] = True
                new = self._generate(items, hyps, pivot_events, it)
                if new:
                    hyps += new
                    changed = True
                    log.info("[phase3]   %d new/revised hypotheses", len(new))
            self._save(items, hyps, pivots, pivot_events, it, False)
            if not changed:
                log.info("[phase3] converged at iteration %d", it)
                break
        for h in hyps:
            if h["status"] in ("OPEN", "INSUFFICIENT"):
                h["status"] = "UNVERIFIED"
        return self._save(items, hyps, pivots, pivot_events, it if hyps else 0, True)

    def _save(self, items, hyps, pivots, pivot_events, it, done) -> dict:
        state = {"done": done, "iteration": it, "items": [i["id"] for i in items],
                 "items_all": [dict(v, tokens=v.get("tokens", 0)) for v in self.items.values()],
                 "hypotheses": hyps, "pivots": pivots, "pivot_events": pivot_events,
                 "errors": self.errors, "failed_prompts": sorted(self.failed_prompts)}
        atomic_write_json(self.state_path, state)
        return state
