#!/usr/bin/env python3
"""
SANS Hunt Evil & Lineage-Anchored Benchmark Harness
- Phase 1: Process Tree Reconstruction (PPID-PID) & Chronological Sorting (ts_epoch)
- Phase 2: SANS 3-Anchor Forensic CoT Triage (Normal vs Attack) + Causal Lineage Propagation
- Phase 3: MITRE ATT&CK Technique Attribution across 5 Methods
- Phase 4: Cross-Model Benchmark Evaluation (FoundationSec-8B, Gemma-4-26B, Qwen3.8-27B)
Target Device: Khadas Mind 2 (Intel Core Ultra 7 258V, Arc Xe2 GPU via OpenVINO GenAI)
"""
import os
import sys
import json
import time
import re
import math
import signal
import hashlib
import argparse
import dataclasses
from pathlib import Path
from collections import Counter
from types import SimpleNamespace

# Set script paths
SCRIPT_DIR = Path(__file__).resolve().parent
EXP_I_DIR = SCRIPT_DIR.parent
FORENSICS_ROOT = EXP_I_DIR.parents[2]
WORKSPACE_ROOT = FORENSICS_ROOT.parent
sys.path.insert(0, str(FORENSICS_ROOT))
sys.path.insert(0, str(SCRIPT_DIR))

import conclude as C1
import conclude_v2 as C2
import run_i as RI
import score_i as S1
from hdf.attack import Attack
from hdf.config import load_config
from hdf.llm import LLMClient, LLMResult, ServerManager, extract_json, strip_reasoning
from hdf.store import EvidenceStore
from hdf.util import read_json, atomic_write_json

F, I, V = C1.F, C1.I, C1.V

# SANS Hunt Evil 추상화 프롬프트 (타겟 데이터셋 고유값 기재 절대 금지 - Rule 3 준수)
SANS_SYSTEM_PROMPT = """You are an expert digital forensics investigator following SANS "Hunt Evil" and MITRE ATT&CK standards.
Analyze process execution timelines using objective forensic baselines:
1. Parent-Child Lineage Anomalies (unauthorized or unusual process spawning relationships)
2. Command-Line & Argument Anomalies (abuse of built-in system utilities, unauthorized downloads, or staging)
3. Network & Side-Effect Anomalies (unauthorized outbound connections or suspicious file modifications)"""

SANS_TRIAGE_PROMPT = """{scope}
Events that are identical except for timestamps and record/thread counters are shown at most twice; the verdict applies to all of their copies.
=== EVENTS ===
{lines}
=== END EVENTS ===

Task:
Systematically evaluate whether these events demonstrate adversary activity or normal OS/admin behavior according to the 3 SANS forensic baselines.
1. "analysis": Step-by-step forensic reasoning across the 3 baselines.
2. "verdict": Answer "ATTACK" when the events show concrete or suspected indicators of adversary activity at any stage of an intrusion (execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, exfiltration), including suspicious parent-child lineage or abuse of built-in system utilities. If you are uncertain whether the activity is benign or malicious, answer "ATTACK". Answer "NORMAL" only when the events clearly reflect routine operating system or administrative activity with no suspicious context.

Respond with one JSON object:
{{"analysis": "<step-by-step forensic reasoning>", "verdict": "ATTACK" | "NORMAL"}}"""

TRIAGE_SCOPE_LINEAGE = "The lines below are events of one process lineage tree, sorted chronologically by execution time."
TRIAGE_SCOPE_PASSIVE = ("The lines below are events from processes that have no process-creation, command-line, script or "
                        "network-connection record in this capture. They do not form one lineage tree; they are grouped "
                        "together and sorted chronologically.")

SANS_TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "analysis": {"type": "string"},
        "verdict": {"type": "string", "enum": ["ATTACK", "NORMAL"]}
    },
    "required": ["analysis", "verdict"]
}

# 2-Pass CoT Prompt for Technique Mapping
COT_SELECT = """MITRE ATT&CK Enterprise techniques (version {version}; sub-techniques are not listed), one per line as "<ID> <name>":
=== ATT&CK TECHNIQUES ===
{catalog}
=== END TECHNIQUES ===

{sources}
The lines below were judged to be part of an attack. They are events of processes that are linked to each other by process id, in time order.
=== ATTACK LINES ===
{lines}
=== END ===

Task: Evaluate whether these attack lines demonstrate adversary techniques.
Step 1 ("analysis"): Systematically analyze whether the lines represent routine OS behavior or anomalous intruder activity.
Step 2 ("conclusions"): For confirmed intruder activities, map each to the appropriate MITRE ATT&CK technique from the list.

Respond with one JSON object:
{{"analysis": "<step-by-step reasoning>", "conclusions": [{{"technique": "<ID from list>", "lines": ["L<n>"], "reason": "<short reason>"}}]}}"""

COT_SCHEMA = {
    "type": "object",
    "properties": {
        "analysis": {"type": "string"},
        "conclusions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string", "pattern": C2.TECHNIQUE_ID},
                    "lines": {"type": "array", "minItems": 1, "items": {"type": "string", "pattern": "^L[0-9]+$"}},
                    "reason": {"type": "string"}
                },
                "required": ["technique", "lines", "reason"]
            }
        }
    },
    "required": ["analysis", "conclusions"]
}


class LightweightAttackRetriever:
    """Line-Level Reciprocal Rank Fusion (RRF) TF-IDF Retriever with Parent Aggregation."""
    def __init__(self, cat: dict, stix_path: str | None = None):
        self.techniques = {}
        self.doc_freqs = Counter()
        self.doc_vectors = {}
        self.num_docs = 0

        full_descs = {}
        if stix_path and Path(stix_path).exists():
            bundle = json.load(open(stix_path, encoding="utf-8"))
            for o in bundle.get("objects", []):
                if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
                    continue
                ext = next((r["external_id"] for r in o.get("external_references", [])
                            if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
                if ext:
                    full_descs[ext] = o.get("description", "")

        for tid, tinfo in cat.get("techniques", {}).items():
            name = tinfo.get("name", "")
            desc = full_descs.get(tid) or tinfo.get("description", "")
            tokens = self._tokenize(f"{name} {name} {name} {desc}")
            if not tokens:
                continue
            tf = Counter(tokens)
            sub_tf = {w: 1.0 + math.log(c) for w, c in tf.items()}
            self.techniques[tid] = tinfo
            self.doc_vectors[tid] = sub_tf
            for word in sub_tf:
                self.doc_freqs[word] += 1
            self.num_docs += 1

        self.idf = {w: math.log((self.num_docs + 1) / (df + 1)) + 1.0 for w, df in self.doc_freqs.items()}
        self.doc_norms = {}
        for tid, sub_tf in self.doc_vectors.items():
            norm_sq = sum((wt * self.idf.get(w, 1.0)) ** 2 for w, wt in sub_tf.items())
            self.doc_norms[tid] = math.sqrt(norm_sq) if norm_sq > 0 else 1.0

    def _tokenize(self, text: str) -> list[str]:
        t = re.sub(r"\b[A-Za-z0-9_]+=", " ", text)
        words = re.findall(r"[a-z0-9]+", t.lower())
        stop = {"exe", "dll", "sys", "windows", "system32", "program", "files", "users", "appdata",
                "local", "temp", "microsoft", "true", "false", "null", "none", "info", "information"}
        return [w for w in words if len(w) >= 3 and not w.isdigit() and not re.fullmatch(r"0x[0-9a-f]+", w) and w not in stop]

    def _rank_single(self, q_tokens: list[str]) -> list[tuple[str, float]]:
        if not q_tokens:
            return []
        q_tf = {w: 1.0 + math.log(c) for w, c in Counter(q_tokens).items()}
        q_norm_sq = sum((wt * self.idf.get(w, 1.0)) ** 2 for w, wt in q_tf.items())
        q_norm = math.sqrt(q_norm_sq) if q_norm_sq > 0 else 1.0
        p_scores = {}
        for tid, doc_tf in self.doc_vectors.items():
            dot = sum(q_tf[w] * self.idf.get(w, 1.0) * doc_tf[w] * self.idf.get(w, 1.0) for w in q_tf if w in doc_tf)
            if dot <= 0:
                continue
            sim = dot / (q_norm * self.doc_norms[tid])
            p_tid = tid.split(".")[0]
            if p_tid in self.techniques and sim > p_scores.get(p_tid, -1.0):
                p_scores[p_tid] = sim
        return sorted(p_scores.items(), key=lambda x: x[1], reverse=True)

    def search_top_k(self, query_text_or_lines, k: int = 15) -> list[tuple[str, float]]:
        lines = query_text_or_lines if isinstance(query_text_or_lines, list) else [query_text_or_lines]
        rrf_scores = Counter()
        seen_sigs = set()
        for line in lines:
            toks = self._tokenize(line)
            sig = tuple(sorted(set(toks)))
            if not sig or sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            for rank_idx, (p_tid, sim) in enumerate(self._rank_single(toks)[:10], 1):
                rrf_scores[p_tid] += (1.0 / (rank_idx + 2.0)) + 0.1 * sim
        if not rrf_scores:
            pool = [t for t in self.techniques if "." not in t]
            return [(tid, 0.0) for tid in pool[:k]]
        return rrf_scores.most_common(k)


ACTIVE_INDICATORS = (
    "CommandLine=", "NewProcessId=", "DestinationIp=",
    "ScriptBlockText=", "HostApplication=", "ContextInfo=", "TaskContent="
)


def extract_task_keys(e) -> set[tuple[str, str]]:
    """Extract normalized (host, task_path) keys across Security, TaskScheduler, and Sysmon TaskCache events."""
    keys: set[tuple[str, str]] = set()
    h = (e.fields.get("Hostname") or e.host or "").split(".")[0].lower()
    if e.fields.get("TaskName") and len(str(e.fields.get("TaskName"))) > 2:
        tk = "\\" + str(e.fields["TaskName"]).strip().strip("\\").lower()
        keys.add((h, tk))
    for tk_field in ("TargetFilename", "TargetObject", "Details"):
        tk_val = str(e.fields.get(tk_field) or "")
        # A registry SetValue TargetObject is "<key>\<value name>": use the key itself (schema rule, no value-name list).
        if tk_field == "TargetObject" and str(e.fields.get("EventType") or "") == "SetValue" and "\\" in tk_val:
            tk_val = tk_val.rsplit("\\", 1)[0]
        m_tk = re.search(r"(?:\\system32\\tasks\\|\\taskcache\\tree\\|^\\)([a-zA-Z0-9_\\-]+)$", tk_val.strip(), re.I)
        if m_tk:
            norm_tk = "\\" + m_tk.group(1).strip("\\").lower()
            if len(norm_tk) > 4:
                keys.add((h, norm_tk))
    return keys


def enhanced_lineage_groups(ids: list[int], byid: dict, legacy_hid: bool = False) -> list[list[int]]:
    """Cross-layer process & session tree reconstruction across Sysmon, Security, PowerShell, ESENT, and TaskScheduler."""
    parent: dict = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in ids:
        e = byid[i]
        node = ("ev", i)
        find(node)
        h = (e.fields.get("Hostname") or e.host or "").split(".")[0].lower()
        pids = set()
        for p in (e.actor, e.new, e.parent):
            if p is not None:
                pids.add(p)
        for k in ("ExecutionProcessID", "ClientProcessId", "CreatorProcessId"):
            v = e.fields.get(k)
            if v is not None and str(e.fields.get("Channel", "")) != "Security":
                p = V.norm_pid(v)
                if p is not None and p > 4:
                    pids.add(p)
        msg = str(e.fields.get("Data_2") or e.fields.get("Message") or e.fields.get("ContextInfo") or "")
        if not pids:
            m = re.search(r"\((\d+),[A-Z]+,\d+\)", msg)
            if m:
                pids.add(int(m.group(1)))
        for p in pids:
            parent[find(("p", h, p))] = find(node)
        if legacy_hid:
            m_hid = re.search(r"HostId=([0-9a-fA-F-]{36})", msg)
            m_happ = re.search(r"HostApplication=([^\r\n]+)", msg)
        else:
            full_msg = "\n".join(str(x) for x in (getattr(e, "view", ""), e.fields.get("Data_2"), e.fields.get("Message"), e.fields.get("ContextInfo")) if x)
            m_hid = re.search(r"Host\s*I[dD]\s*=\s*([0-9a-fA-F-]{36})", full_msg)
            m_happ = re.search(r"Host\s*Application\s*=\s*([^\r\n|↵]+)", full_msg)
        if m_hid:
            parent[find(("hid", h, m_hid.group(1).lower()))] = find(node)
        if m_happ:
            cmd_str = m_happ.group(1).strip().lower()
            if len(cmd_str) > 10:
                parent[find(("cmd", h, cmd_str))] = find(node)
        cmd_field = e.fields.get("CommandLine")
        if cmd_field and len(str(cmd_field).strip()) > 10:
            parent[find(("cmd", h, str(cmd_field).strip().lower()))] = find(node)
        for h_tk, norm_tk in extract_task_keys(e):
            parent[find(("s", h_tk, norm_tk))] = find(node)
        src_ip = str(e.fields.get("SourceIp") or e.fields.get("SourceAddress") or e.fields.get("IpAddress") or "").strip()
        src_port = str(e.fields.get("SourcePort") or e.fields.get("IpPort") or "").strip()
        if src_ip and src_port and src_ip not in ("-", "127.0.0.1", "::1", "0.0.0.0") and src_port.isdigit() and int(src_port) > 0:
            parent[find(("net_in", h, src_ip, src_port))] = find(node)

    comps: dict = {}
    for i in ids:
        comps.setdefault(find(("ev", i)), []).append(i)
    groups = [sorted(c, key=lambda i: (byid[i].epoch, i)) for c in comps.values()]
    return sorted(groups, key=lambda g: (byid[g[0]].epoch, g[0]))


# Per-record volatile fields (event record time, record number, thread id). Field-name based schema rule;
# other timestamps inside the event (e.g. CreationUtcTime / PreviousCreationUtcTime) are NOT masked.
_VOLATILE_FIELD = re.compile(
    r"(?:^|(?<= \| ))(?:TimeCreated|@timestamp|UtcTime|EventRecordID|RecordNumber|SourceThreadId|ThreadID|ExecutionThreadID)=[^|]*",
    re.I)
_VOLATILE_MSG_TIME = re.compile(
    r"(?<![A-Za-z])UtcTime:\s*(?:↵\s*)?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?")


def fold_signature(e) -> tuple:
    """Identity of an event for folding: host, actor and the rendered view minus per-record volatile fields."""
    v = getattr(e, "view", "") or ""
    v = _VOLATILE_FIELD.sub("", v)
    v = _VOLATILE_MSG_TIME.sub("UtcTime: <T>", v)
    return (e.host, e.actor, v)


def fold_repetitive_benign(group: list[int], byid: dict) -> tuple[list[int], dict[int, list[int]]]:
    """Fold repeats of events that are identical except for per-record volatile fields: the first two copies are
    shown, later copies are attached to the second one in folded_map (verdicts propagate to them). Events with any
    other difference are never folded, so no event content is hidden from the LLM; every event ID is kept."""
    rep_eids = []
    folded_map: dict[int, list[int]] = {}
    anchors: dict[tuple, int] = {}
    counts: Counter = Counter()
    for eid in group:
        sig = fold_signature(byid[eid])
        counts[sig] += 1
        if counts[sig] > 2:
            folded_map.setdefault(anchors[sig], []).append(eid)
            continue
        rep_eids.append(eid)
        anchors[sig] = eid
    return rep_eids, folded_map


def extract_rag_lines(chunk: list[int], byid: dict) -> list[str]:
    """Extract forensic action lines and command lines for Line-Level RRF retrieval."""
    lines = []
    for i in chunk:
        f = byid[i].fields
        if f.get("EventID") == "7" and f.get("Signed") == "true":
            continue
        if f.get("CommandLine"):
            lines.append(str(f["CommandLine"]))
        lines.append(byid[i].view)
    return lines if lines else [byid[i].view for i in chunk]


def is_gt_match(conclusions: list[str], gt_list: list[str]) -> bool:
    if not gt_list:
        return None
    for c in conclusions:
        if not c:
            continue
        c_base = c.split(".")[0].strip()
        for gt in gt_list:
            gt_base = gt.split(".")[0].strip()
            if c_base == gt_base or gt.startswith(c) or c.startswith(gt):
                return True
    return False


def evaluate_techniques(conclusions: list[str], gt_list: list[str], method_duration: float, method_tokens: int) -> dict:
    unique_concs = sorted(list({c.strip() for c in conclusions if c and c.strip()}))
    gt_set = {g.strip() for g in gt_list if g and g.strip()}
    gt_bases = {g.split(".")[0] for g in gt_set}

    exact_match = any(c in gt_set for c in unique_concs)
    parent_match = any(c.split(".")[0] in gt_bases for c in unique_concs)

    tp_techs = [c for c in unique_concs if c.split(".")[0] in gt_bases]
    fp_techs = [c for c in unique_concs if c.split(".")[0] not in gt_bases]
    matched_gt = [g for g in gt_set if any(c.split(".")[0] == g.split(".")[0] for c in unique_concs)]

    tp_cnt = len(tp_techs)
    fp_cnt = len(fp_techs)
    fn_cnt = len(gt_set) - len(matched_gt)

    prec = (tp_cnt / (tp_cnt + fp_cnt) * 100.0) if (tp_cnt + fp_cnt) > 0 else 0.0
    rec = (len(matched_gt) / len(gt_set) * 100.0) if gt_set else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

    return {
        "conclusions": unique_concs,
        "gt_match": parent_match,
        "exact_match": exact_match,
        "parent_match": parent_match,
        "tp_techniques": tp_techs,
        "fp_techniques": fp_techs,
        "tp_count": tp_cnt,
        "fp_count": fp_cnt,
        "fn_count": fn_cnt,
        "precision_percent": round(prec, 2),
        "recall_percent": round(rec, 2),
        "f1_percent": round(f1, 2),
        "seconds": round(method_duration, 2),
        "tokens": method_tokens,
    }


def grounding_metrics(evidence: list[dict], gt_list: list[str], gt_attack_eids: set[int]) -> dict:
    """Evidence grounding (per chunk-level final conclusion): does the technique cite at least one labelled attack
    event? Cited IDs are the representative events shown to the model (folded copies share their content)."""
    gt_bases = {g.split(".")[0] for g in gt_list if g}
    on_attack = [e for e in evidence if set(e["events"]) & gt_attack_eids]
    gt_hits = [e for e in evidence if e["technique"].split(".")[0] in gt_bases]
    gt_grounded = [e for e in gt_hits if set(e["events"]) & gt_attack_eids]
    total = len(evidence)
    return {
        "conclusions": total,
        "cite_attack_events": len(on_attack),
        "cite_attack_events_percent": round(len(on_attack) / total * 100, 2) if total else 0.0,
        "gt_technique_conclusions": len(gt_hits),
        "gt_technique_grounded": len(gt_grounded),
        "gt_technique_ungrounded": len(gt_hits) - len(gt_grounded),
        "grounded_match": bool(gt_grounded),
        "grounded_techniques": sorted({e["technique"] for e in gt_grounded}),
        "fp_on_attack_events": sum(1 for e in on_attack if e["technique"].split(".")[0] not in gt_bases),
    }


def compute_host_baselines(all_eids: list[int], byid: dict) -> dict[int, str]:
    """Compute Host-Internal Self-Baseline Frequency per event pattern (100% Training-Free)."""
    total_events = max(1, len(all_eids))
    pattern_counts: Counter = Counter()
    ev_keys: dict[int, tuple[str, str, str]] = {}
    for eid in all_eids:
        e = byid[eid]
        f = e.fields
        ch = str(f.get("Channel") or e.src or "").lower()
        ev_id = str(f.get("EventID") or f.get("EventCode") or "")
        raw_img = str(f.get("Image") or f.get("NewProcessName") or f.get("ProcessName") or f.get("Application") or "")
        exe = re.split(r"[\\/]", raw_img.strip())[-1].lower() if raw_img else ""
        k = (ch, ev_id, exe)
        ev_keys[eid] = k
        pattern_counts[k] += 1
    baselines: dict[int, str] = {}
    for eid, k in ev_keys.items():
        cnt = pattern_counts[k]
        ratio = (cnt / total_events) * 100.0
        tag = "RARE_ANOMALY_CANDIDATE" if (cnt <= 3 or ratio < 0.05) else ("MODERATE" if ratio < 1.0 else "FREQUENT_ROUTINE")
        baselines[eid] = f"pattern={k[1]}:{k[2] or 'sys'} freq={cnt}/{total_events} ({ratio:.2f}%, {tag})"
    return baselines


def complete_capped(client, model, system: str, user: str, tag: str, schema=None, max_out: int = 4096):
    """Preserve 16384 context and profile max_output_tokens while verifying exact prompt match on cache reuse."""
    p2_cache = getattr(client, "p2_audit_cache", None)
    expected_prompt = client.formatter(model).format(system, user)
    # Prompt-keyed reuse is scoped per method (and per select/verify stage) so methods never share samples.
    prefix = tag.split("_")[0] + ("_verify" if "_verify" in tag else "")
    aud = None
    if p2_cache:
        aud = p2_cache.get((prefix, expected_prompt)) or p2_cache.get(tag)
    if aud is not None:
        raw = aud.get("output", "")
        prompt_str = aud.get("prompt", "")
        if prompt_str == expected_prompt:
            ans_text, complete = strip_reasoning(raw, prompt_str.rstrip().endswith("<think>"))
            if aud.get("error") is None and aud.get("finish") == "stop" and complete and ans_text:
                client.recovered_p2_seconds = getattr(client, "recovered_p2_seconds", 0.0) + float(aud.get("seconds", 0.0))
                return LLMResult(
                    text=ans_text,
                    raw=raw,
                    prompt_tokens=int(aud.get("prompt_tokens", 0)),
                    output_tokens=int(aud.get("output_tokens", 0)),
                    hit_limit=False,
                    finish="stop",
                )
    fmt = client.formatter(model)
    n_in = fmt.count(fmt.format(system, user))
    min_out = max(model.max_output_tokens, max_out)
    eff_out = max(512, min(16384 - n_in, max(min_out, 16384 - n_in)))
    capped_model = dataclasses.replace(model, max_output_tokens=eff_out)
    return I.complete(client, capped_model, 16384, system, user, tag, schema=schema)


def verify_and_ground_conclusions(
    client, model, ans: dict | None, chunk: list[int], byid: dict,
    src_info: dict, cat: dict, attack_kb: Attack, tag_prefix: str, evidence: list | None = None
) -> tuple[list[str], int]:
    """100% Training-Free Line-ID validation, Active-Event Grounding, and Stage-2 STIX Sub-technique Verification.
    evidence (optional): receives {"technique", "events"} for every final technique (cited event IDs of the chunk)."""
    if not ans:
        return [], 0
    for c_item in (ans.get("conclusions") or []):
        if isinstance(c_item, dict) and isinstance(c_item.get("lines"), list):
            cleaned_lines = [re.sub(r"^\[?(L?\d+)\]?$", lambda m: f"L{m.group(1).lstrip('Ll')}", str(x).strip())
                             for x in c_item["lines"] if str(x).strip() not in ("", "L0", "[L0]", "0")]
            c_item["lines"] = cleaned_lines
    ok, _ = C1.validate(ans, chunk, attack_kb)
    if not ok:
        return [], 0

    # Deterministic Active-Event Grounding Gate: reject picks citing ONLY passive DLL/termination events when active events exist
    passive_eids = {
        eid for eid in chunk
        if str(byid[eid].fields.get("EventID", "")) == "5"
        or (str(byid[eid].fields.get("EventID", "")) == "7" and str(byid[eid].fields.get("Signed", "")).lower() == "true")
    }
    has_non_passive = any(eid not in passive_eids for eid in chunk)
    grounded_ok = [
        c_item for c_item in ok
        if not has_non_passive or any(eid not in passive_eids for eid in c_item.get("events", []))
    ]
    if not grounded_ok:
        return [], 0

    picks = C2.merge_picks(grounded_ok, chunk, cat)
    if not picks:
        if evidence is not None:
            evidence.extend({"technique": c_item["technique"], "events": list(c_item["events"])} for c_item in grounded_ok)
        return [c_item["technique"] for c_item in grounded_ok], 0

    # Stage-2 Contrastive Verification against official STIX descriptions and sub-techniques
    extra_tokens = 0
    fmt = client.formatter(model)
    limit = model.max_input_tokens - C2.PROMPT_MARGIN

    def shown(ps: list[dict]) -> str:
        full_view = C2.render_verify(chunk, byid, src_info, cat, ps)
        if fmt.count(fmt.format(C2.SYSTEM_PROMPT, full_view)) <= limit:
            return full_view
        only_eids = {i for p in ps for i in p["events"]}
        holder = SimpleNamespace(events=[], shortened={})
        tok_fn = lambda h: fmt.count(fmt.format(
            C2.SYSTEM_PROMPT, C2.render_verify(chunk, I.Overlay(byid, h.shortened), src_info, cat, ps, only=only_eids)
        ))
        I.shorten_to_fit(holder, sorted(only_eids), byid, tok_fn, limit)
        return C2.render_verify(chunk, I.Overlay(byid, holder.shortened), src_info, cat, ps, only=only_eids)

    packs = C2.pack_verify(picks, lambda ps: fmt.format(C2.SYSTEM_PROMPT, shown(ps)), fmt.count, limit)
    checks: dict[str, dict] = {}
    for b_idx, sub_picks in enumerate(packs, 1):
        v_tag = f"{tag_prefix}_verify" if len(packs) == 1 else f"{tag_prefix}_verify_{b_idx}"
        v_schema = C2.verify_schema([p["technique"] for p in sub_picks], cat)
        v_res = complete_capped(client, model, C2.SYSTEM_PROMPT, shown(sub_picks), v_tag, schema=v_schema, max_out=4096)
        extra_tokens += v_res.prompt_tokens + v_res.output_tokens
        v_ans = extract_json(v_res.text, "checks", item_key="technique")
        checks.update(C2.parse_checks(v_ans, sub_picks, attack_kb, cat))
    final_list = []
    for p in picks:
        chk = checks.get(p["technique"])
        if chk and chk["verdict"] == "not_shown":
            continue
        tid = C2.final_technique(p, chk, cat)
        final_list.append(tid)
        if evidence is not None:
            evidence.append({"technique": tid, "events": list(p["events"])})
    return final_list, extra_tokens


def _lines_with_root_context(chunk: list[int], group: list[int], byid: dict, baselines: dict[int, str] | None = None) -> str:
    """청크 분할 시 부모 기동 명령이 누락되어 의미가 희석되는 현상을 방지하는 맥락 상속 함수"""
    chunk_end_epoch = byid[chunk[-1]].epoch if chunk else float("inf")
    payload_keys = ("CommandLine=", "TaskContent=", "ScriptBlockText=", "HostApplication=")
    cmd_roots = [i for i in group if byid[i].epoch <= chunk_end_epoch + 1.0 and any(k in getattr(byid[i], "view", "") for k in payload_keys)]
    root_eids = cmd_roots or [
        i for i in group
        if byid[i].epoch <= chunk_end_epoch + 1.0
        and "NewProcessId=" in getattr(byid[i], "view", "")
    ]
    root_id = root_eids[0] if root_eids else (chunk[0] if chunk else group[0])
    
    context_header = ""
    if baselines and chunk:
        b_info = baselines.get(chunk[0]) or baselines.get(root_id)
        if b_info:
            context_header += f"=== HOST SELF-BASELINE (Internal Frequency on This Host) ===\n[BASELINE] Root/Trigger {b_info}\n=== END BASELINE ===\n\n"
    body = C2._lines(chunk, byid)
    if root_eids and root_id not in chunk:
        ref_line = re.sub(r"^\[L0\]\s*", "", C2.V.line_text(byid[root_id], 0))
        if len(body) + len(ref_line) <= 12000:
            context_header += f"=== CONTEXT: Root Trigger Event of this Lineage Tree (For reference only) ===\n[REF] {ref_line}\n=== END CONTEXT ===\n\n"
    
    return context_header + body



def run_benchmark_for_model(profile_path: Path, run_dir: Path, dataset_name: str = "win_bitsadmin_download") -> dict:
    """Run Phase 1 (SANS Triage & Recall/FP) + Phase 2 (5-Method ATT&CK) for a single model."""
    cfg = load_config(str(profile_path))
    model = cfg.model("triage")
    stix_path = cfg.get("paths", "attack_stix")
    cat = C2.load_catalog(stix_path)
    cat_text = C2.catalog_block(cat)
    retriever = LightweightAttackRetriever(cat, stix_path)
    attack_kb = Attack.load(stix_path)

    # Dynamic Ground Truth resolution
    labels_file = FORENSICS_ROOT / "proposals" / "2026-10-10" / "exp_h" / "labels" / f"{dataset_name}.json"
    if not labels_file.exists():
        labels_file = EXP_I_DIR / "labels" / f"{dataset_name}.json"
    
    gt_attack_eids = set()
    if labels_file.exists():
        label_data = read_json(labels_file)
        gt_attack_eids = {int(k) for k in label_data.get("labels", {})}

    gt_techniques = sorted(S1.technique_truth(dataset_name))
    manifest_file = FORENSICS_ROOT / "data" / "eval" / dataset_name / "manifest.json"
    if not gt_techniques and manifest_file.exists():
        manifest_data = read_json(manifest_file)
        gt_techniques = manifest_data.get("ground_truth", {}).get("techniques", [])
    gt_techniques = sorted(list({
        (attack_kb.canonical(t) or t).strip()
        for t in gt_techniques if t and t.strip()
    }))

    # Load events directly from DB
    db_file = run_dir / "evidence.db"
    if not db_file.exists():
        db_file = FORENSICS_ROOT / "proposals" / "2026-10-10" / "exp_h" / "data" / dataset_name / "evidence.db"
    
    store = EvidenceStore(db_file)
    evs = V.load_events(store)
    restored = I.restore_views(store, evs)
    byid = {e.id: e for e in evs}
    src_info = {s: V.source_constants(store, s) for s in {e.src for e in evs}}
    store.close()

    # Phase 1: Reconstruct Process Trees (PPID-PID) and Sort Chronologically (ts_epoch)
    all_eids = list(byid.keys())
    host_baselines = compute_host_baselines(all_eids, byid)
    groups = enhanced_lineage_groups(all_eids, byid, legacy_hid=False)

    # Distinguish active groups from static background services
    active_groups = []
    passive_groups = []
    for g in groups:
        is_active = any(any(k in getattr(byid[eid], "view", "") for k in ACTIVE_INDICATORS) for eid in g)
        if is_active:
            active_groups.append(g)
        else:
            passive_groups.append(g)

    print(f"\n=======================================================")
    print(f"▶ Benchmark Target: {model.name} on {dataset_name}")
    print(f"▶ Total Events: {len(all_eids)}, Total Groups: {len(groups)}")
    print(f"▶ Active Groups: {len(active_groups)}, Passive (Static) Groups: {len(passive_groups)}")
    print(f"▶ Ground Truth: {len(gt_attack_eids)} attack events, Techniques: {gt_techniques}")
    print(f"=======================================================\n")

    run_dir.mkdir(parents=True, exist_ok=True)
    server = ServerManager(cfg, run_dir)
    server.ensure(model)

    try:
        audit_dir = run_dir / "audit" / f"sans_bench_{model.name}"
        client = LLMClient(cfg, server, audit_dir)
        fmt = client.formatter(model)

        # ----------------------------------------------------
        # Phase 1: Experiment I Process-Instance Triage (PID + Creation Time 1-Pass)
        # ----------------------------------------------------
        sample_file = S1.sample_path(dataset_name)
        sample_judged = set(read_json(sample_file)["judged"])
        hz = I.harness_from(cfg)
        triage_fingerprint = I.profile_fingerprint(cfg)
        context_tokens = int(cfg.get("budget", "context_tokens"))
        limits = {"max_input": model.max_input_tokens - RI.PROMPT_MARGIN, "context": context_tokens}

        def overhead_of(req, recheck: bool = False) -> int:
            empty = I.sub_request(req, [])
            user = I.render(empty, byid, *src_info[byid[req.events[0]].src], attack_ids=[] if recheck else None,
                            context_position=hz.context_position)
            return fmt.count(fmt.format(RI.SYSTEM_PROMPT, user))

        def build_process_instance_requests(full: list, sub: list, count_tok, hz_cfg: I.Harness,
                                            overhead_fn, *, max_input: int, context: int) -> tuple[list[V.Request], dict[tuple, list]]:
            from collections import defaultdict
            proc_starts: dict[tuple[str, int], list[float]] = defaultdict(list)
            for e in full:
                if e.new is not None:
                    proc_starts[(e.host, e.new)].append(e.epoch)
                elif e.actor is not None and V.first(e.fields, V.CMD_FIELDS) and e.parent is not None:
                    proc_starts[(e.host, e.actor)].append(e.epoch)
            for k in proc_starts:
                dedup: list[float] = []
                for t in sorted(proc_starts[k]):
                    if not dedup or (t - dedup[-1]) > 1.0:
                        dedup.append(t)
                proc_starts[k] = dedup

            def get_inst_idx(host: str, pid: int | None, epoch: float) -> int:
                if pid is None:
                    return 0
                starts = proc_starts.get((host, pid), [])
                return sum(1 for st in starts if epoch >= st - 0.05)

            raw_groups: dict[tuple[str, int], list] = defaultdict(list)
            pid_insts: dict[tuple[str, int], set[int]] = defaultdict(set)
            for e in sub:
                inst = get_inst_idx(e.host, e.actor, e.epoch)
                if e.actor is not None:
                    pid_insts[(e.host, e.actor)].add(inst)
                gkey = f"{V.group_key(e)}|inst={inst}" if e.actor is not None else V.group_key(e)
                raw_groups[(gkey, inst)].append(e)

            def inst_creation_records(evs_all: list, host: str, pid: int, inst: int) -> list:
                all_c = [e for e in evs_all if e.host == host and (
                    e.new == pid or (e.actor == pid and V.first(e.fields, V.CMD_FIELDS) and e.parent is not None))]
                if inst > 0:
                    filtered = [e for e in all_c if get_inst_idx(host, pid, e.epoch) == inst]
                    if filtered:
                        all_c = filtered
                return all_c[:3]

            def inst_parent_of(evs_all: list, host: str, pid: int, inst: int) -> int | None:
                for e in evs_all:
                    if e.host != host:
                        continue
                    if inst > 0 and get_inst_idx(host, pid, e.epoch) != inst:
                        continue
                    if e.new == pid and e.actor is not None:
                        return e.actor
                    if e.actor == pid and e.parent is not None:
                        return e.parent
                return V.parent_of(evs_all, host, pid)

            req_groups: list[V.Request] = []
            inst_map: dict[tuple, list] = {}
            for (gkey, inst), members in sorted(raw_groups.items(), key=lambda kv: (kv[1][0].epoch, kv[1][0].id)):
                host, actor = members[0].host, members[0].actor
                multi_inst = len(pid_insts.get((host, actor), set())) > 1 if actor is not None else False
                req_key = gkey if multi_inst else V.group_key(members[0])
                ctx: list[int] = []
                if actor is None:
                    title = "The lines below are events without a process id, in time order."
                else:
                    images = Counter(V.first(m.fields, V.IMAGE_FIELDS) for m in members if V.first(m.fields, V.IMAGE_FIELDS))
                    image = images.most_common(1)[0][0] if images else "(image not recorded)"
                    title = (f"The lines below are all events whose acting process is process id {actor} "
                             f"({image}) on host {host or '-'}, in time order.")
                    own = {m.id for m in members}
                    ctx = [c.id for c in inst_creation_records(full, host, actor, inst) if c.id not in own]
                    par = inst_parent_of(full, host, actor, inst)
                    if par is not None:
                        par_inst = get_inst_idx(host, par, members[0].epoch)
                        ctx += [c.id for c in inst_creation_records(full, host, par, par_inst)
                                if c.id not in own and c.id not in ctx]
                req_groups.append(V.Request(req_key, 1, title, [m.id for m in members], ctx))
                inst_map[(host, actor, inst, req_key)] = members

            count_of = (lambda i: count_tok(V.line_text(byid[i], 1)) + 1) if count_tok else None
            out_reqs: list[V.Request] = []
            for g in req_groups:
                if overhead_fn and count_tok and g.context:
                    longest = max(count_of(i) for i in g.events)
                    budget_ctx = min(max_input, context - hz_cfg.output_base - hz_cfg.output_per_line) - longest
                    if overhead_fn(g) > budget_ctx:
                        I.shorten_to_fit(g, g.context, byid, overhead_fn, budget_ctx)
                oh = overhead_fn(g) if (overhead_fn and count_tok) else 0
                for part, ids in enumerate(I.pack(g.events, count_of, oh, hz_cfg, max_input, context), 1):
                    r = I.sub_request(g, ids)
                    r.part = part
                    out_reqs.append(r)
            return out_reqs, inst_map

        reqs, proc_inst_groups = build_process_instance_requests(
            evs, [e for e in evs if e.id in sample_judged], fmt.count, hz, overhead_of, **limits
        )

        def fit(req, attack_ids) -> int:
            src = src_info[byid[req.events[0]].src]
            budget_p1 = min(limits["max_input"], context_tokens - hz.output_base - hz.output_per_line * len(req.events))
            tok = lambda r: fmt.count(fmt.format(RI.SYSTEM_PROMPT, I.render(r, byid, *src, attack_ids=attack_ids,
                                                                            context_position=hz.context_position)))
            return I.shorten_to_fit(req, list(attack_ids or []) + list(req.context), byid, tok, budget_p1)

        res_dir = run_dir / "results"
        res_dir.mkdir(exist_ok=True)
        atomic_write_json(run_dir / "profile.json", {
            "config": str(Path(profile_path).resolve()),
            "fingerprint": triage_fingerprint,
            "model": model.name,
            "enable_thinking": model.enable_thinking,
            "sampling": model.sampling,
            "structured_after": model.structured_after,
            "max_output_tokens": model.max_output_tokens,
            "harness": dataclasses.asdict(hz),
            "views_restored": restored,
        })

        print(f"\n--- Phase 1: Experiment I Process-Instance Triage (sample={sample_file.name}, "
              f"judged={len(sample_judged)}, pass1_reqs={len(reqs)}, fp={triage_fingerprint}) ---")
        asker = RI.Asker(client, model, byid, src_info, res_dir, hz, triage_fingerprint)
        asker.context_tokens = context_tokens
        asker.fit = fit

        used_req_records: list[dict] = []
        _orig_once = asker.once

        def _tracked_once(req, tag, attack_ids=None):
            out, rej = _orig_once(req, tag, attack_ids)
            src = src_info[byid[req.events[0]].src]
            user = I.render(req, byid, *src, attack_ids=attack_ids, context_position=hz.context_position)
            h = V.request_hash(model.name, f"exp-i|{triage_fingerprint}|{tag}|{user}")
            rec = read_json(res_dir / f"{h}.json")
            if rec:
                used_req_records.append(rec)
            return out, rej

        asker.once = _tracked_once
        pass1_verdicts: dict[int, dict] = {}
        for n, r in enumerate(reqs, 1):
            got = asker.full(r, f"f_{n:02d}")
            pass1_verdicts.update(got)
            c_stat = {x: sum(got[i]["verdict"] == x for i in r.events) for x in ("attack", "normal", "no_verdict")}
            print(f"  [pass1 {n}/{len(reqs)}] {r.key} part {r.part} ({len(r.events)} lines) -> {c_stat}", flush=True)
        atomic_write_json(run_dir / "pass1.json", {str(k): v for k, v in sorted(pass1_verdicts.items())})

        final_verdicts: dict[int, dict] = {k: {**v, "pass": 1} for k, v in pass1_verdicts.items()}
        rounds: list[dict] = []
        atomic_write_json(run_dir / "rounds.json", rounds)
        atomic_write_json(run_dir / "verdicts.json", {str(k): v for k, v in sorted(final_verdicts.items())})

        # Score Phase 1 using official score_i.py sample classes (attack, benign_aw, benign_bw, excluded)
        cls_map = S1.classes(dataset_name)
        score_i_summary = S1.score_run(run_dir, dataset_name)
        score_i_summary["requests"] = len(used_req_records)
        score_i_summary["gen_seconds"] = round(sum(float(q.get("seconds", 0.0)) for q in used_req_records))
        score_i_summary["finish"] = dict(Counter(q.get("finish") for q in used_req_records))
        score_i_summary["hit_limit"] = sum(1 for q in used_req_records if q.get("hit_limit") is True)
        score_i_summary["rejected_quotes"] = sum(len(q.get("rejected", [])) for q in used_req_records)
        score_i_summary["max_prompt_tokens"] = max((int(q.get("prompt_tokens", 0)) for q in used_req_records), default=0)
        sample_attack_eids = {eid for eid, ck in cls_map.items() if ck == "attack"}
        sample_benign_eids = {eid for eid, ck in cls_map.items() if ck in ("benign_aw", "benign_bw")}

        llm_direct_attack_eids = {eid for eid, v in pass1_verdicts.items() if v.get("verdict") == "attack"}
        final_attack_only_eids = {eid for eid, v in final_verdicts.items() if v.get("verdict") == "attack"}
        propagated_attack_eids = final_attack_only_eids - llm_direct_attack_eids
        no_verdict_eids = {eid for eid, v in final_verdicts.items() if v.get("verdict") == "no_verdict"}
        # Match conclude_v2.py L318: pass both "attack" and "no_verdict" lines to Phase 2
        classified_attack_eids = final_attack_only_eids | no_verdict_eids

        tp = len(final_attack_only_eids & sample_attack_eids)
        tp_llm_direct = len(llm_direct_attack_eids & sample_attack_eids)
        tp_propagated = len(propagated_attack_eids & sample_attack_eids)
        fn = len(sample_attack_eids - final_attack_only_eids)
        fp = len(final_attack_only_eids & sample_benign_eids)
        fp_llm_direct = len(llm_direct_attack_eids & sample_benign_eids)
        fp_propagated = len(propagated_attack_eids & sample_benign_eids)
        tn = len(sample_benign_eids - final_attack_only_eids)

        recall = (tp / len(sample_attack_eids) * 100.0) if sample_attack_eids else 0.0
        recall_llm_direct = (tp_llm_direct / len(sample_attack_eids) * 100.0) if sample_attack_eids else 0.0
        fp_rate = (fp / (fp + tn) * 100.0) if (fp + tn) else 0.0
        precision = (tp / (tp + fp) * 100.0) if (tp + fp) else 0.0
        f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        phase1_duration = sum(float(q.get("seconds", 0.0)) for q in used_req_records)
        triage_tokens = sum(int(q.get("prompt_tokens", 0)) + int(q.get("output_tokens", 0)) for q in used_req_records)

        print(f"\n[Phase 1 Result (score_i sample evaluation: {len(sample_judged)} judged lines)]")
        print(f"  Attack Recall: {recall:.1f}% ({tp}/{len(sample_attack_eids)} sample attack lines) | "
              f"Pass-1 {tp_llm_direct} ({recall_llm_direct:.1f}%) + InstProp {tp_propagated}")
        print(f"  False Positives: {fp}/{len(sample_benign_eids)} benign lines (Pass-1 {fp_llm_direct}, "
              f"InstProp {fp_propagated}; FP Rate: {fp_rate:.2f}%, Precision: {precision:.2f}%, F1: {f1_score:.2f}%) | "
              f"no_verdict: {len(no_verdict_eids)}")
        print(f"  Triage Duration: {phase1_duration:.2f}s | Tokens: {triage_tokens} | Requests: {len(used_req_records)}")

        # ----------------------------------------------------
        # Phase 2: 5 Methods for ATT&CK Technique Attribution
        # ----------------------------------------------------
        print("\n--- Phase 2: MITRE ATT&CK Attribution (5 Methods Comparison) ---")

        target_eids = set(classified_attack_eids) if classified_attack_eids else (sample_judged & {eid for g in active_groups for eid in g})

        # Calculate safe evidence token budget under 12,288 input limit
        fixed_base = fmt.count(fmt.format(C2.SYSTEM_PROMPT, C2.SELECT.format(version=cat["version"], catalog=cat_text, sources="", lines="")))
        budget = min(model.max_input_tokens - fixed_base - 200, int(cfg.get("harness", "evidence_tokens", default=3500)))

        client.p2_audit_cache = {}
        if audit_dir.exists():
            for ap in sorted(audit_dir.glob("*.json")):
                try:
                    ad = read_json(ap)
                    t_name = ad.get("tag", "")
                    if t_name.startswith(("m1_", "m2_", "m3_", "m4_", "m5_")) and ad.get("error") is None and ad.get("finish") == "stop":
                        client.p2_audit_cache[t_name] = ad
                        p_key = t_name.split("_")[0] + ("_verify" if "_verify" in t_name else "")
                        if ad.get("prompt"):
                            client.p2_audit_cache[(p_key, ad["prompt"])] = ad
                except Exception:
                    pass

        attack_chunks = []
        active_attack_chunks = []
        for g in active_groups:
            sub_attack = [eid for eid in g if eid in target_eids]
            if sub_attack:
                rep_sub, _ = fold_repetitive_benign(sub_attack, byid)
                for c in C1.F.split(rep_sub, byid, fmt.count, C1.NO_LINE_CAP, budget):
                    attack_chunks.append((g, c))
                    active_attack_chunks.append((g, c))

        isolated_eids = []
        for g in passive_groups:
            sub_attack = [eid for eid in g if eid in target_eids]
            if sub_attack:
                rep_sub, _ = fold_repetitive_benign(sub_attack, byid)
                isolated_eids.extend(rep_sub)
        if isolated_eids:
            for c in C1.F.split(isolated_eids, byid, fmt.count, C1.NO_LINE_CAP, budget):
                attack_chunks.append((c, c))

        print(f"Divided attack events into {len(attack_chunks)} context-preserved chunks across relevant trees (budget={budget}).")

        active_attack_chunks = active_attack_chunks or list(attack_chunks)
        method_results = {}

        # ----------------------------------------------------
        # Method 1 (Baseline): 222 Parents Direct Prompt
        # ----------------------------------------------------
        t0 = time.time()
        client.recovered_p2_seconds = 0.0
        m1_conclusions = []
        m1_tokens = 0
        m1_evidence = []
        for c_idx, (g, c) in enumerate(attack_chunks, 1):
            prompt_text = C2.SELECT.format(version=cat["version"], catalog=cat_text,
                                          sources=C2._sources(c, byid, src_info),
                                          lines=_lines_with_root_context(c, g, byid, host_baselines))
            schema = C2.select_schema()
            res = complete_capped(client, model, C2.SYSTEM_PROMPT, prompt_text, f"m1_base_{c_idx}", schema=schema, max_out=4096)
            m1_tokens += res.prompt_tokens + res.output_tokens
            ans = extract_json(res.text, "conclusions", item_key="technique")
            verified_tids, v_toks = verify_and_ground_conclusions(client, model, ans, c, byid, src_info, cat, attack_kb, f"m1_base_{c_idx}", evidence=m1_evidence)
            m1_tokens += v_toks
            m1_conclusions.extend(verified_tids)
        m1_dur = (time.time() - t0) + client.recovered_p2_seconds
        method_results["Method 1 (Baseline)"] = evaluate_techniques(m1_conclusions, gt_techniques, m1_dur, m1_tokens)
        method_results["Method 1 (Baseline)"]["grounding"] = grounding_metrics(m1_evidence, gt_techniques, gt_attack_eids)
        print(f"  ✔ Method 1 (Baseline): {method_results['Method 1 (Baseline)']['conclusions']} (Exact: {method_results['Method 1 (Baseline)']['exact_match']}, FP: {method_results['Method 1 (Baseline)']['fp_count']}, F1: {method_results['Method 1 (Baseline)']['f1_percent']}%) in {m1_dur:.2f}s")

        # ----------------------------------------------------
        # Method 2 (Track 1): Active Filter + Top-15 Semantic RAG
        # ----------------------------------------------------
        t0 = time.time()
        client.recovered_p2_seconds = 0.0
        m2_conclusions = []
        m2_tokens = 0
        m2_evidence = []
        for c_idx, (g, c) in enumerate(active_attack_chunks, 1):
            rag_lines = extract_rag_lines(c, byid)
            top_k_techs = retriever.search_top_k(rag_lines, k=15)
            top_k_block = "\n".join([f"{tid} {cat['techniques'][tid]['name']}" for tid, _ in top_k_techs])

            prompt_text = C2.SELECT.format(version=cat["version"], catalog=top_k_block,
                                          sources=C2._sources(c, byid, src_info),
                                          lines=_lines_with_root_context(c, g, byid, host_baselines))
            schema = C2.select_schema()
            res = complete_capped(client, model, C2.SYSTEM_PROMPT, prompt_text, f"m2_rag_{c_idx}", schema=schema, max_out=4096)
            m2_tokens += res.prompt_tokens + res.output_tokens
            ans = extract_json(res.text, "conclusions", item_key="technique")
            verified_tids, v_toks = verify_and_ground_conclusions(client, model, ans, c, byid, src_info, cat, attack_kb, f"m2_rag_{c_idx}", evidence=m2_evidence)
            m2_tokens += v_toks
            m2_conclusions.extend(verified_tids)
        m2_dur = (time.time() - t0) + client.recovered_p2_seconds
        method_results["Method 2 (Track 1 RAG)"] = evaluate_techniques(m2_conclusions, gt_techniques, m2_dur, m2_tokens)
        method_results["Method 2 (Track 1 RAG)"]["grounding"] = grounding_metrics(m2_evidence, gt_techniques, gt_attack_eids)
        print(f"  ✔ Method 2 (Track 1 RAG): {method_results['Method 2 (Track 1 RAG)']['conclusions']} (Exact: {method_results['Method 2 (Track 1 RAG)']['exact_match']}, FP: {method_results['Method 2 (Track 1 RAG)']['fp_count']}, F1: {method_results['Method 2 (Track 1 RAG)']['f1_percent']}%) in {m2_dur:.2f}s")

        # ----------------------------------------------------
        # Method 3 (Track 2: All Groups CoT)
        # ----------------------------------------------------
        t0 = time.time()
        client.recovered_p2_seconds = 0.0
        m3_conclusions = []
        m3_tokens = 0
        m3_evidence = []
        m3_chunk_map = {}
        for c_idx, (g, c) in enumerate(attack_chunks, 1):
            c_t0 = time.time()
            c_rec0 = client.recovered_p2_seconds
            prompt_text = COT_SELECT.format(version=cat["version"], catalog=cat_text,
                                            sources=C2._sources(c, byid, src_info),
                                            lines=_lines_with_root_context(c, g, byid, host_baselines))
            res = complete_capped(client, model, C2.SYSTEM_PROMPT, prompt_text, f"m3_cot_all_{c_idx}", schema=COT_SCHEMA, max_out=4096)
            chunk_toks = res.prompt_tokens + res.output_tokens
            ans = extract_json(res.text, "conclusions", item_key="technique")
            chunk_ev = []
            verified_tids, v_toks = verify_and_ground_conclusions(client, model, ans, c, byid, src_info, cat, attack_kb, f"m3_cot_all_{c_idx}", evidence=chunk_ev)
            chunk_toks += v_toks
            chunk_dur = (time.time() - c_t0) + (client.recovered_p2_seconds - c_rec0)
            m3_tokens += chunk_toks
            m3_conclusions.extend(verified_tids)
            m3_evidence.extend(chunk_ev)
            m3_chunk_map[(tuple(g), tuple(c))] = (verified_tids, chunk_toks, chunk_dur, chunk_ev)
        m3_dur = (time.time() - t0) + client.recovered_p2_seconds
        method_results["Method 3 (Track 2 All CoT)"] = evaluate_techniques(m3_conclusions, gt_techniques, m3_dur, m3_tokens)
        method_results["Method 3 (Track 2 All CoT)"]["grounding"] = grounding_metrics(m3_evidence, gt_techniques, gt_attack_eids)
        print(f"  ✔ Method 3 (Track 2 All CoT): {method_results['Method 3 (Track 2 All CoT)']['conclusions']} (Exact: {method_results['Method 3 (Track 2 All CoT)']['exact_match']}, FP: {method_results['Method 3 (Track 2 All CoT)']['fp_count']}, F1: {method_results['Method 3 (Track 2 All CoT)']['f1_percent']}%) in {m3_dur:.2f}s")

        # ----------------------------------------------------
        # Method 4 (Track 2: Active Only CoT)
        # ----------------------------------------------------
        t0 = time.time()
        client.recovered_p2_seconds = 0.0
        m4_conclusions = []
        m4_tokens = 0
        m4_evidence = []
        m4_reused_dur = 0.0
        m4_reused_tokens = 0
        m4_reused_chunks = 0
        for c_idx, (g, c) in enumerate(active_attack_chunks, 1):
            key = (tuple(g), tuple(c))
            if key in m3_chunk_map:
                verified_tids, chunk_toks, chunk_dur, chunk_ev = m3_chunk_map[key]
                m4_conclusions.extend(verified_tids)
                m4_evidence.extend(chunk_ev)
                m4_tokens += chunk_toks
                m4_reused_dur += chunk_dur
                m4_reused_tokens += chunk_toks
                m4_reused_chunks += 1
            else:
                prompt_text = COT_SELECT.format(version=cat["version"], catalog=cat_text,
                                                sources=C2._sources(c, byid, src_info),
                                                lines=_lines_with_root_context(c, g, byid, host_baselines))
                res = complete_capped(client, model, C2.SYSTEM_PROMPT, prompt_text, f"m4_cot_act_{c_idx}", schema=COT_SCHEMA, max_out=4096)
                m4_tokens += res.prompt_tokens + res.output_tokens
                ans = extract_json(res.text, "conclusions", item_key="technique")
                verified_tids, v_toks = verify_and_ground_conclusions(client, model, ans, c, byid, src_info, cat, attack_kb, f"m4_cot_act_{c_idx}", evidence=m4_evidence)
                m4_tokens += v_toks
                m4_conclusions.extend(verified_tids)
        m4_dur = (time.time() - t0) + client.recovered_p2_seconds + m4_reused_dur
        method_results["Method 4 (Track 2 Active CoT)"] = evaluate_techniques(m4_conclusions, gt_techniques, m4_dur, m4_tokens)
        method_results["Method 4 (Track 2 Active CoT)"]["grounding"] = grounding_metrics(m4_evidence, gt_techniques, gt_attack_eids)
        # Method 4's seconds/tokens are equivalent per-method costs; the part reused from Method 3 is not re-spent.
        method_results["Method 4 (Track 2 Active CoT)"]["reused_from_method3"] = {
            "chunks": m4_reused_chunks, "of_chunks": len(active_attack_chunks),
            "tokens": m4_reused_tokens, "seconds": round(m4_reused_dur, 2),
        }
        print(f"  ✔ Method 4 (Track 2 Active CoT): {method_results['Method 4 (Track 2 Active CoT)']['conclusions']} (Exact: {method_results['Method 4 (Track 2 Active CoT)']['exact_match']}, FP: {method_results['Method 4 (Track 2 Active CoT)']['fp_count']}, F1: {method_results['Method 4 (Track 2 Active CoT)']['f1_percent']}%) in {m4_dur:.2f}s")

        # ----------------------------------------------------
        # Method 5 (Track 3: Hybrid RAG + CoT)
        # ----------------------------------------------------
        t0 = time.time()
        client.recovered_p2_seconds = 0.0
        m5_conclusions = []
        m5_tokens = 0
        m5_evidence = []
        for c_idx, (g, c) in enumerate(active_attack_chunks, 1):
            rag_lines = extract_rag_lines(c, byid)
            top_k_techs = retriever.search_top_k(rag_lines, k=15)
            top_k_block = "\n".join([f"{tid} {cat['techniques'][tid]['name']}" for tid, _ in top_k_techs])

            prompt_text = COT_SELECT.format(version=cat["version"], catalog=top_k_block,
                                            sources=C2._sources(c, byid, src_info),
                                            lines=_lines_with_root_context(c, g, byid, host_baselines))
            res = complete_capped(client, model, C2.SYSTEM_PROMPT, prompt_text, f"m5_hybrid_{c_idx}", schema=COT_SCHEMA, max_out=4096)
            m5_tokens += res.prompt_tokens + res.output_tokens
            ans = extract_json(res.text, "conclusions", item_key="technique")
            verified_tids, v_toks = verify_and_ground_conclusions(client, model, ans, c, byid, src_info, cat, attack_kb, f"m5_hybrid_{c_idx}", evidence=m5_evidence)
            m5_tokens += v_toks
            m5_conclusions.extend(verified_tids)
        m5_dur = (time.time() - t0) + client.recovered_p2_seconds
        method_results["Method 5 (Track 3 Hybrid)"] = evaluate_techniques(m5_conclusions, gt_techniques, m5_dur, m5_tokens)
        method_results["Method 5 (Track 3 Hybrid)"]["grounding"] = grounding_metrics(m5_evidence, gt_techniques, gt_attack_eids)
        print(f"  ✔ Method 5 (Track 3 Hybrid): {method_results['Method 5 (Track 3 Hybrid)']['conclusions']} (Exact: {method_results['Method 5 (Track 3 Hybrid)']['exact_match']}, FP: {method_results['Method 5 (Track 3 Hybrid)']['fp_count']}, F1: {method_results['Method 5 (Track 3 Hybrid)']['f1_percent']}%) in {m5_dur:.2f}s")

        # Compile final summary
        summary = {
            "model": model.name,
            "dataset": dataset_name,
            "ground_truth_techniques": gt_techniques,
            "ground_truth_attack_events": len(sample_attack_eids),
            "full_dataset_attack_events": len(gt_attack_eids),
            "sample_judged_events": len(sample_judged),
            "phase1_triage": {
                "recall_percent": round(recall, 2),
                "recall_llm_direct_percent": round(recall_llm_direct, 2),
                "precision_percent": round(precision, 2),
                "f1_percent": round(f1_score, 2),
                "tp_events": tp,
                "tp_llm_direct_events": tp_llm_direct,
                "tp_propagated_events": tp_propagated,
                "fn_events": fn,
                "fp_events": fp,
                "fp_llm_direct_events": fp_llm_direct,
                "fp_propagated_events": fp_propagated,
                "no_verdict_events": len(no_verdict_eids),
                "tn_events": tn,
                "fp_rate_percent": round(fp_rate, 2),
                "seconds": round(phase1_duration, 2),
                "tokens": triage_tokens,
                "cache_fingerprint": triage_fingerprint,
                "score_i": score_i_summary,
            },
            "phase2_methods": method_results,
            # Totals count actually spent work: Method 4's reuse of Method 3 results is subtracted once.
            "total_seconds": round(phase1_duration + m1_dur + m2_dur + m3_dur + (m4_dur - m4_reused_dur) + m5_dur, 2),
            "total_tokens": triage_tokens + m1_tokens + m2_tokens + m3_tokens + (m4_tokens - m4_reused_tokens) + m5_tokens,
            "harness_sha256": hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest(),
        }

        out_path = run_dir / f"sans_benchmark_{model.name}.json"
        atomic_write_json(out_path, summary)
        print(f"\n[BENCHMARK FINISHED] Summary saved to: {out_path}")
        return summary

    finally:
        server.stop()


def main():
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    # SIGTERM (incl. parent-death signal from the orchestrator) -> SystemExit, so `finally: server.stop()` runs.
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(143))
    parser = argparse.ArgumentParser(description="SANS Hunt Evil Benchmark Harness")
    parser.add_argument("--profile", type=str, default="profiles/final_fsec.toml", help="Path to profile TOML")
    parser.add_argument("--dataset", type=str, default="win_bitsadmin_download", help="Target dataset name")
    parser.add_argument("--models", type=str, default="all", help="'all' or comma-separated profile names: final_fsec,final_gemma,final_qwen")
    args = parser.parse_args()

    profiles_dir = SCRIPT_DIR.parent / "profiles"
    runs_dir = SCRIPT_DIR.parent / "runs"
    profile_display_names = {
        "final_fsec": "FoundationSec-8B",
        "final_gemma": "Gemma-4-26B",
        "final_qwen": "Qwen3.8-27B",
    }

    if args.models == "all":
        target_profiles = [
            ("FoundationSec-8B", profiles_dir / "final_fsec.toml", runs_dir / "final_fsec" / args.dataset),
            ("Gemma-4-26B", profiles_dir / "final_gemma.toml", runs_dir / "final_gemma" / args.dataset),
            ("Qwen3.8-27B", profiles_dir / "final_qwen.toml", runs_dir / "final_qwen" / args.dataset),
        ]
    else:
        profile_names = [p.strip() for p in args.models.split(",")]
        target_profiles = []
        for pname in profile_names:
            stem = pname.replace(".toml", "")
            pfile = profiles_dir / f"{pname}.toml" if not pname.endswith(".toml") else Path(pname)
            rdir = runs_dir / stem / args.dataset
            disp_name = profile_display_names.get(stem, stem)
            target_profiles.append((disp_name, pfile, rdir))

    all_results = {}
    for name, ppath, rdir in target_profiles:
        print(f"\n>>> Starting evaluation for: {name} ({ppath.name}) <<<")
        rdir.mkdir(parents=True, exist_ok=True)
        res = run_benchmark_for_model(ppath, rdir, args.dataset)
        all_results[name] = res

        # Run process lifecycle cleanup after each model
        clean_sh = WORKSPACE_ROOT / ".agents" / "skills" / "mind2-verified-ops" / "scripts" / "clean_lifecycle.sh"
        if clean_sh.exists():
            os.system(f"bash {clean_sh} > /dev/null 2>&1")

    # Final Combined Benchmark Table
    print("\n" + "=" * 95)
    print("FINAL CROSS-MODEL & 5-METHODS BENCHMARK COMPARISON TABLE")
    print("=" * 95)
    print(f"{'Model':<18} | {'Recall(D/T)':<13} | {'FP':<5} | {'M1 Base':<9} | {'M2 RAG':<9} | {'M3 AllCoT':<9} | {'M4 ActCoT':<9} | {'M5 Hyb':<9} | {'Time(s)':<8}")
    print("-" * 95)
    for name, r in all_results.items():
        p1 = r["phase1_triage"]
        p2 = r["phase2_methods"]
        rec = f"{p1.get('recall_llm_direct_percent', '-')}/{p1['recall_percent']}%"
        fp = f"{p1['fp_events']}"

        def _m_tag(md: dict) -> str:
            return "EXACT" if md.get("exact_match") else ("PARENT" if md.get("parent_match") else "MISS")
        m1 = _m_tag(p2.get("Method 1 (Baseline)", {}))
        m2 = _m_tag(p2.get("Method 2 (Track 1 RAG)", {}))
        m3 = _m_tag(p2.get("Method 3 (Track 2 All CoT)", {}))
        m4 = _m_tag(p2.get("Method 4 (Track 2 Active CoT)", {}))
        m5 = _m_tag(p2.get("Method 5 (Track 3 Hybrid)", {}))
        dur = f"{r['total_seconds']}s"
        print(f"{name:<18} | {rec:<13} | {fp:<5} | {m1:<9} | {m2:<9} | {m3:<9} | {m4:<9} | {m5:<9} | {dur:<8}")
    print("=" * 95 + "\n")

    combined_out = runs_dir / f"sans_benchmark_combined_{args.dataset}.json"
    merged_results = {}
    if combined_out.exists():
        try:
            merged_results = read_json(combined_out) or {}
        except Exception:
            merged_results = {}
    merged_results.update(all_results)
    atomic_write_json(combined_out, merged_results)
    print(f"[COMBINED SUMMARY SAVED] {combined_out}")


if __name__ == "__main__":
    main()
