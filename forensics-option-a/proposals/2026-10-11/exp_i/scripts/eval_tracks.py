#!/usr/bin/env python3
"""
Comparison Benchmark Harness for 3 Tracks:
- Baseline: Existing conclude_v2 (Full 222 Parent Catalog + Direct Greedy Extraction)
- Track 1: Active Lineage Filter (Method B) + Lightweight Semantic Top-15 RAG (Method C)
- Track 2: Two-Pass Chain-of-Thought (Method D: Analysis then Attribution across All Groups & Active Group)

Target Dataset: win_bitsadmin_download (Truth: T1197 BITS Jobs)
Target Device: Khadas Mind 2 (Intel Arc Xe2 GPU via OpenVINO GenAI)
"""
import os
import sys
import json
import time
import re
import math
from pathlib import Path
from collections import Counter

# Add parent script paths
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import conclude as C1
import conclude_v2 as C2
from hdf.attack import Attack
from hdf.config import load_config
from hdf.llm import LLMClient, ServerManager, extract_json
from hdf.store import EvidenceStore
from hdf.util import read_json, atomic_write_json

F, I, V = C1.F, C1.I, C1.V

# Lightweight TF-IDF Semantic Retriever for ATT&CK Techniques (Pure Python)
class LightweightAttackRetriever:
    def __init__(self, cat: dict):
        self.techniques = {}
        self.doc_freqs = Counter()
        self.doc_vectors = {}
        self.num_docs = 0

        # Build corpus from 919 techniques and parent names/descriptions
        for tid, tinfo in cat.get("techniques", {}).items():
            name = tinfo.get("name", "")
            desc = tinfo.get("description", "")
            tokens = self._tokenize(f"{name} {name} {desc}")
            if not tokens:
                continue
            tf = Counter(tokens)
            self.techniques[tid] = tinfo
            self.doc_vectors[tid] = tf
            for word in tf:
                self.doc_freqs[word] += 1
            self.num_docs += 1

        # Calculate IDF and document norms
        self.idf = {word: math.log((self.num_docs + 1) / (df + 1)) + 1.0 for word, df in self.doc_freqs.items()}
        self.doc_norms = {}
        for tid, tf in self.doc_vectors.items():
            norm_sq = sum((count * self.idf.get(w, 1.0)) ** 2 for w, count in tf.items())
            self.doc_norms[tid] = math.sqrt(norm_sq) if norm_sq > 0 else 1.0

    def _tokenize(self, text: str) -> list[str]:
        # Split words on alphanumeric tokens to cleanly match executables and techniques
        words = re.findall(r"[a-z0-9]+", text.lower())
        return [w for w in words if len(w) >= 3 and not w.isdigit()]

    def search_top_k(self, query_text: str, k: int = 15) -> list[tuple[str, float]]:
        q_tokens = self._tokenize(query_text)
        if not q_tokens:
            return [(tid, 0.0) for tid in list(self.techniques.keys())[:k]]
        q_tf = Counter(q_tokens)
        q_norm_sq = sum((count * self.idf.get(w, 1.0)) ** 2 for w, count in q_tf.items())
        q_norm = math.sqrt(q_norm_sq) if q_norm_sq > 0 else 1.0

        scores = []
        for tid, doc_tf in self.doc_vectors.items():
            dot = sum(q_tf[w] * self.idf.get(w, 1.0) * doc_tf[w] * self.idf.get(w, 1.0) for w in q_tf if w in doc_tf)
            sim = dot / (q_norm * self.doc_norms[tid])
            scores.append((tid, sim))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:k]


def filter_active_lineage_groups(groups: list[list[int]], byid: dict) -> list[list[int]]:
    """Method B: Distinguish active actor processes from passive target processes."""
    active_groups = []
    for g in groups:
        is_active = False
        for eid in g:
            ev = byid[eid]
            view = getattr(ev, "view", "")
            # Check for active execution indicators (CommandLine, Process Creation, Network)
            if "CommandLine=" in view or "NewProcessId=" in view or "DestinationIp=" in view:
                is_active = True
                break
        if is_active:
            active_groups.append(g)
    return active_groups if active_groups else groups


def is_gt_match(conclusions: list[str], gt_list: list[str]) -> bool:
    if not gt_list:
        return None
    for c in conclusions:
        c_base = c.split(".")[0].strip()
        for gt in gt_list:
            gt_base = gt.split(".")[0].strip()
            if c_base == gt_base or gt.startswith(c) or c.startswith(gt):
                return True
    return False


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Multi-track forensic benchmark harness")
    parser.add_argument("profile_path", type=str, help="Path to profile TOML")
    parser.add_argument("run_dir", type=str, help="Path to run directory")
    parser.add_argument("--tracks", type=str, default="all", help="Tracks to run: 'all', '0', '1', '2', '3' or comma-separated")
    parser.add_argument("--force", action="store_true", help="Force re-run and ignore cached summary")
    args = parser.parse_args()

    profile_path = Path(args.profile_path).resolve()
    run_dir = Path(args.run_dir).resolve()
    selected_tracks = [t.strip() for t in args.tracks.split(",")] if args.tracks != "all" else ["0", "1", "2", "3"]

    cfg = load_config(str(profile_path))
    model = cfg.model("triage")
    cat = C2.load_catalog(cfg.get("paths", "attack_stix"))
    retriever = LightweightAttackRetriever(cat)

    # Dynamic Ground Truth resolution from dataset manifest
    dataset_name = run_dir.name
    manifest_path = Path(f"/home/ubuntu/forensics-option-a/data/eval/{dataset_name}/manifest.json")
    gt_techniques = []
    if manifest_path.exists():
        manifest_data = read_json(manifest_path)
        gt_techniques = manifest_data.get("ground_truth", {}).get("techniques", [])

    store = EvidenceStore(run_dir / "evidence.db")
    evs = V.load_events(store)
    restored = I.restore_views(store, evs)
    byid = {e.id: e for e in evs}
    src_info = {s: V.source_constants(store, s) for s in {e.src for e in evs}}
    store.close()

    # Load all lineage groups from full evidence DB to prevent 70-98% attack evidence loss
    all_eids = list(byid.keys())
    groups = C2.lineage_groups(all_eids, byid)

    server = ServerManager(cfg, run_dir)
    server.ensure(model)
    try:
        client = LLMClient(cfg, server, run_dir / "audit" / f"eval_tracks_{model.name}")
        fmt = client.formatter(model)

        print(f"\n=======================================================")
        print(f"▶ Benchmark Target: {model.name} on {dataset_name} (GT: {gt_techniques})")
        print(f"▶ Total Events: {len(all_eids)}, Total Groups: {len(groups)}")
        print(f"▶ Selected Tracks: {selected_tracks}")
        print(f"=======================================================\n")

        out_file = run_dir / f"eval_tracks_summary_{model.name}.json"
        results_summary = {} if args.force else (read_json(out_file) if out_file.exists() else {})

        # Calculate safe evidence token budget under 12,288 input limit
        cat_text = C2.catalog_block(cat)
        fixed_base = fmt.count(fmt.format(C2.SYSTEM_PROMPT, C2.SELECT.format(version=cat["version"], catalog=cat_text, sources="", lines="")))
        budget = min(model.max_input_tokens - fixed_base - 200, int(cfg.get("harness", "evidence_tokens", default=4000)))

        # Pack groups into chunks adhering to budget (15 chunks across 9 groups)
        all_chunks = []
        for g in groups:
            for c in C1.F.split(g, byid, fmt.count, C1.NO_LINE_CAP, budget):
                all_chunks.append((g, c))
        print(f"Packed {len(groups)} lineage groups into {len(all_chunks)} safe evidence chunks (budget={budget}).")

        # ----------------------------------------------------
        # Track 0: Baseline (Full 222 Catalog, All Chunks)
        # ----------------------------------------------------
        if "0" in selected_tracks and "Baseline" not in results_summary:
            print("\nExecuting Baseline (Existing Method: 222 Parents)...")
            t0 = time.time()
            baseline_conclusions = []
            baseline_tokens = 0

            for c_idx, (g, c) in enumerate(all_chunks, 1):
                prompt_text = C2.SELECT.format(version=cat["version"], catalog=cat_text,
                                              sources=C2._sources(c, byid, src_info),
                                              lines=C2._lines(c, byid))
                schema = C2.select_schema()
                res = I.complete(client, model, 16384, C2.SYSTEM_PROMPT, prompt_text, f"base_{c_idx}", schema=schema)
                baseline_tokens += res.prompt_tokens + res.output_tokens
                ans = extract_json(res.text, "conclusions", item_key="technique")
                for c_item in (ans.get("conclusions", []) if ans else []):
                    baseline_conclusions.append(c_item.get("technique"))
            base_dur = time.time() - t0
            results_summary["Baseline"] = {
                "conclusions": sorted(list(set(baseline_conclusions))),
                "ground_truth": gt_techniques,
                "ground_truth_found": is_gt_match(baseline_conclusions, gt_techniques),
                "seconds": round(base_dur, 2),
                "tokens": baseline_tokens
            }
            print(f"✔ Baseline Done in {base_dur:.2f}s | Found: {results_summary['Baseline']['conclusions']}")
        elif "Baseline" in results_summary:
            print(f"✔ Baseline Loaded from cache: {results_summary['Baseline']['conclusions']}")

        # ----------------------------------------------------
        # Track 1: Active Lineage Filter + Semantic Top-15 RAG
        # ----------------------------------------------------
        active_groups = filter_active_lineage_groups(groups, byid)
        active_chunks = [(g, c) for (g, c) in all_chunks if g in active_groups]

        if "1" in selected_tracks and "Track 1 (B+C)" not in results_summary:
            print("\nExecuting Track 1 (Method B Active Filter + Method C Top-15 RAG)...")
            t0 = time.time()
            t1_conclusions = []
            t1_tokens = 0

            for c_idx, (g, c) in enumerate(active_chunks, 1):
                # Query semantic retriever prioritizing active execution events to avoid DLL noise dilution
                cmd_views = [byid[i].view for i in c if "CommandLine=" in byid[i].view or "NewProcessId=" in byid[i].view]
                evidence_text = " ".join(cmd_views) if cmd_views else " ".join([byid[i].view for i in c])
                top_k_techs = retriever.search_top_k(evidence_text, k=15)
                top_k_block = "\n".join([f"{tid} {cat['techniques'][tid]['name']}" for tid, _ in top_k_techs])

                prompt_text = C2.SELECT.format(version=cat["version"], catalog=top_k_block,
                                              sources=C2._sources(c, byid, src_info),
                                              lines=C2._lines(c, byid))
                schema = C2.select_schema()
                res = I.complete(client, model, 16384, C2.SYSTEM_PROMPT, prompt_text, f"track1_{c_idx}", schema=schema)
                t1_tokens += res.prompt_tokens + res.output_tokens
                ans = extract_json(res.text, "conclusions", item_key="technique")
                for c_item in (ans.get("conclusions", []) if ans else []):
                    t1_conclusions.append(c_item.get("technique"))
            t1_dur = time.time() - t0
            results_summary["Track 1 (B+C)"] = {
                "conclusions": sorted(list(set(t1_conclusions))),
                "ground_truth": gt_techniques,
                "ground_truth_found": is_gt_match(t1_conclusions, gt_techniques),
                "seconds": round(t1_dur, 2),
                "tokens": t1_tokens
            }
            print(f"✔ Track 1 Done in {t1_dur:.2f}s | Found: {results_summary['Track 1 (B+C)']['conclusions']}")
        elif "Track 1 (B+C)" in results_summary:
            print(f"✔ Track 1 Loaded from cache: {results_summary['Track 1 (B+C)']['conclusions']}")

        # ----------------------------------------------------
        # Track 2: Two-Pass Chain-of-Thought (Method D)
        # ----------------------------------------------------
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

        cot_schema = {
            "type": "object",
            "properties": {
                "analysis": {"type": "string"},
                "conclusions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "technique": {"type": "string", "pattern": C2.TECHNIQUE_ID},
                            "lines": {"type": "array", "items": {"type": "string"}},
                            "reason": {"type": "string"}
                        },
                        "required": ["technique", "lines", "reason"]
                    }
                }
            },
            "required": ["analysis", "conclusions"]
        }

        if "2" in selected_tracks and "Track 2 (D: All Groups)" not in results_summary:
            print("\nExecuting Track 2 (Method D: Two-Pass CoT)...")
            t0 = time.time()
            t2_conclusions = []
            t2_active_conclusions = []
            t2_tokens = 0
            for c_idx, (g, c) in enumerate(all_chunks, 1):
                prompt_text = COT_SELECT.format(version=cat["version"], catalog=cat_text,
                                                sources=C2._sources(c, byid, src_info),
                                                lines=C2._lines(c, byid))
                res = I.complete(client, model, 16384, C2.SYSTEM_PROMPT, prompt_text, f"track2_{c_idx}", schema=cot_schema)
                t2_tokens += res.prompt_tokens + res.output_tokens
                ans = extract_json(res.text, "conclusions", item_key="technique")
                for c_item in (ans.get("conclusions", []) if ans else []):
                    tech = c_item.get("technique")
                    t2_conclusions.append(tech)
                    if g in active_groups:
                        t2_active_conclusions.append(tech)
            t2_dur = time.time() - t0
            results_summary["Track 2 (D: All Groups)"] = {
                "conclusions": sorted(list(set(t2_conclusions))),
                "ground_truth": gt_techniques,
                "ground_truth_found": is_gt_match(t2_conclusions, gt_techniques),
                "seconds": round(t2_dur, 2),
                "tokens": t2_tokens
            }
            results_summary["Track 2 (B+D: Active Only)"] = {
                "conclusions": sorted(list(set(t2_active_conclusions))),
                "ground_truth": gt_techniques,
                "ground_truth_found": is_gt_match(t2_active_conclusions, gt_techniques),
                "seconds": round(t2_dur, 2),
                "tokens": t2_tokens
            }
            print(f"✔ Track 2 Done in {t2_dur:.2f}s | All: {results_summary['Track 2 (D: All Groups)']['conclusions']} | Active: {results_summary['Track 2 (B+D: Active Only)']['conclusions']}")
        elif "Track 2 (D: All Groups)" in results_summary:
            print(f"✔ Track 2 Loaded from cache: Active={results_summary.get('Track 2 (B+D: Active Only)', {}).get('conclusions')}")

        # ----------------------------------------------------
        # Track 3: Hybrid (Method B Active + Method C Top-15 RAG + Method D Two-Pass CoT)
        # ----------------------------------------------------
        if "3" in selected_tracks and "Track 3 (B+C+D)" not in results_summary:
            print("\nExecuting Track 3 (Hybrid: Method B Active + Method C Top-15 RAG + Method D Two-Pass CoT)...")
            t0 = time.time()
            t3_conclusions = []
            t3_tokens = 0
            for c_idx, (g, c) in enumerate(active_chunks, 1):
                cmd_views = [byid[i].view for i in c if "CommandLine=" in byid[i].view or "NewProcessId=" in byid[i].view]
                evidence_text = " ".join(cmd_views) if cmd_views else " ".join([byid[i].view for i in c])
                top_k_techs = retriever.search_top_k(evidence_text, k=15)
                top_k_block = "\n".join([f"{tid} {cat['techniques'][tid]['name']}" for tid, _ in top_k_techs])

                prompt_text = COT_SELECT.format(version=cat["version"], catalog=top_k_block,
                                                sources=C2._sources(c, byid, src_info),
                                                lines=C2._lines(c, byid))
                res = I.complete(client, model, 16384, C2.SYSTEM_PROMPT, prompt_text, f"track3_{c_idx}", schema=cot_schema)
                t3_tokens += res.prompt_tokens + res.output_tokens
                ans = extract_json(res.text, "conclusions", item_key="technique")
                for c_item in (ans.get("conclusions", []) if ans else []):
                    t3_conclusions.append(c_item.get("technique"))
            t3_dur = time.time() - t0
            results_summary["Track 3 (B+C+D)"] = {
                "conclusions": sorted(list(set(t3_conclusions))),
                "ground_truth": gt_techniques,
                "ground_truth_found": is_gt_match(t3_conclusions, gt_techniques),
                "seconds": round(t3_dur, 2),
                "tokens": t3_tokens
            }
            print(f"✔ Track 3 Done in {t3_dur:.2f}s | Found: {results_summary['Track 3 (B+C+D)']['conclusions']}")
        elif "Track 3 (B+C+D)" in results_summary:
            print(f"✔ Track 3 Loaded from cache: {results_summary['Track 3 (B+C+D)']['conclusions']}")

        # Output JSON summary
        atomic_write_json(out_file, results_summary)
        print(f"\n[SUMMARY SAVED] {out_file}")
        return 0
    finally:
        server.stop()


if __name__ == "__main__":
    sys.exit(main())
