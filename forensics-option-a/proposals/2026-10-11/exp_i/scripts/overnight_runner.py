#!/usr/bin/env python3
"""
Overnight Autonomous Benchmark Runner across 3 Datasets & 3 Models.
Ensures session persistence, sequential execution, lifecycle cleanup,
and automatic generation of OVERNIGHT_BENCHMARK_REPORT.md upon completion.
"""
import os
import sys
import time
import json
import ctypes
import signal
import hashlib
import subprocess
from pathlib import Path

signal.signal(signal.SIGHUP, signal.SIG_IGN)

SCRIPT_DIR = Path(__file__).resolve().parent
EXP_I_DIR = SCRIPT_DIR.parent
FORENSICS_ROOT = EXP_I_DIR.parents[2]
WORKSPACE_ROOT = FORENSICS_ROOT.parent
RUNS_DIR = EXP_I_DIR / "runs"
VENV_PYTHON = FORENSICS_ROOT / "venv" / "bin" / "python3"
BENCHMARK_SCRIPT = SCRIPT_DIR / "run_sans_benchmark.py"
CLEAN_SCRIPT = WORKSPACE_ROOT / ".agents" / "skills" / "mind2-verified-ops" / "scripts" / "clean_lifecycle.sh"
VERIFY_SCRIPT = WORKSPACE_ROOT / ".agents" / "skills" / "mind2-verified-ops" / "scripts" / "verify_constraints.py"
REPORT_PATH = EXP_I_DIR / "OVERNIGHT_BENCHMARK_REPORT.md"
STATUS_PATH = EXP_I_DIR / "overnight_status.json"

DEFAULT_DATASETS = [
    "win_bitsadmin_download",
    "win_remote_schtask",
    "win_auditpol_disable",
]
TARGET_DATASETS = (
    [d.strip() for d in os.environ["DATASETS"].split() if d.strip()]
    if os.environ.get("DATASETS")
    else DEFAULT_DATASETS
)

TARGET_MODELS = [
    ("FoundationSec-8B", "final_fsec"),
    ("Gemma-4-26B", "final_gemma"),
    ("Qwen3.8-27B", "final_qwen")
]


def log(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)


def update_status(stage: str, current_dataset: str = None, current_model: str = None, progress: str = ""):
    data = {
        "stage": stage,
        "current_dataset": current_dataset,
        "current_model": current_model,
        "progress": progress,
        "timestamp": time.time(),
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    STATUS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def wait_for_existing_benchmark():
    """If an existing run_sans_benchmark is currently running, wait for it to finish."""
    log("Checking if an existing benchmark is running...")
    while True:
        try:
            res = subprocess.run(["pgrep", "-f", "run_sans_benchmark.py"], stdout=subprocess.PIPE, text=True)
            pids = [int(p) for p in res.stdout.strip().split() if p and int(p) != os.getpid()]
            if not pids:
                log("No competing benchmark processes running. Ready to proceed.")
                break
            log(f"Waiting for active benchmark PID(s) {pids} to complete...")
            time.sleep(30)
        except Exception as e:
            log(f"Error checking competing processes: {e}")
            break


def run_clean_lifecycle():
    log("Executing clean_lifecycle.sh for full process & memory recovery...")
    try:
        subprocess.run(["bash", str(CLEAN_SCRIPT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    except Exception as e:
        log(f"Warning: lifecycle cleanup failed: {e}")


def _die_with_parent():
    """preexec_fn for benchmark children: PR_SET_PDEATHSIG=SIGTERM, so a child started in its own session
    (start_new_session=True, kept for SIGHUP isolation) is terminated when the orchestrator dies."""
    ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGTERM)


def _summary_sha(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("harness_sha256")
    except Exception:
        return None


def current_summaries(model_key: str, dataset: str) -> list[Path]:
    """Summaries produced by the current run_sans_benchmark.py only (stale-version summaries are ignored)."""
    target_dir = RUNS_DIR / model_key / dataset
    if not target_dir.exists():
        return []
    cur = hashlib.sha256(BENCHMARK_SCRIPT.read_bytes()).hexdigest()
    return [s for s in sorted(target_dir.glob("sans_benchmark_*.json")) if _summary_sha(s) == cur]


def has_completed_summary(model_key: str, dataset: str) -> bool:
    return len(current_summaries(model_key, dataset)) > 0


def generate_final_report():
    log("Compiling final cross-model, multi-dataset benchmark report...")
    lines = []
    lines.append("# Overnight Multi-Dataset & Cross-Model Benchmark Final Report")
    lines.append(f"**Execution Timestamp**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append("## 1. Executive Summary")
    lines.append("- **Target Hardware**: Khadas Mind 2 (Intel Core Ultra 7 258V, 32GB LPDDR5X, Arc Xe2 GPU via OpenVINO)")
    lines.append(f"- **Evaluated Datasets**: {len(TARGET_DATASETS)} Windows Attack Scenarios")
    lines.append(f"- **Evaluated Models**: FoundationSec-8B, Gemma-4-26B, Qwen3.8-27B")
    lines.append("- **Attribution Methods**: 5 Methods (Method 1 Baseline, Method 2 RAG, Method 3 All CoT, Method 4 Active CoT, Method 5 Hybrid)\n")

    for ds in TARGET_DATASETS:
        lines.append(f"### Dataset: `{ds}`")
        lines.append("| Model | P1 Recall (LLM direct / total) | P1 FP (FPR) | P1 F1 | M1 (Match/Grounding) | M2 (Match/Grounding) | M3 (Match/Grounding) | M4 (Match/Grounding) | M5 (Match/Grounding) | Duration |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

        for m_name, m_key in TARGET_MODELS:
            summaries = current_summaries(m_key, ds)
            if not summaries:
                lines.append(f"| {m_name} | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | Not Found |")
                continue

            try:
                data = json.loads(summaries[0].read_text())
                p1 = data.get("phase1_triage", {})
                rec = (f"{p1.get('recall_llm_direct_percent', 'N/A')}% / {p1.get('recall_percent', 0.0)}% "
                       f"(no_verdict {p1.get('no_verdict_events', 'N/A')})")
                fp = f"{p1.get('fp_events', 0)} ({p1.get('fp_rate_percent', 0.0)}%)"
                p1_f1 = f"{p1.get('f1_percent', 0.0)}%"

                p2 = data.get("phase2_methods", {})
                def fmt_m(m_dict):
                    if not m_dict:
                        return "N/A"
                    tag = "EXACT" if m_dict.get("exact_match") else ("PARENT" if m_dict.get("parent_match") else "MISS")
                    gr = m_dict.get("grounding", {})
                    g_tag = "GROUNDED" if gr.get("grounded_match") else "UNGROUNDED"
                    return (f"{tag}/{g_tag} (FP:{m_dict.get('fp_count', 0)}, F1:{m_dict.get('f1_percent', 0.0)}%, "
                            f"cite-attack:{gr.get('cite_attack_events_percent', 'N/A')}%)")

                m1 = fmt_m(p2.get("Method 1 (Baseline)"))
                m2 = fmt_m(p2.get("Method 2 (Track 1 RAG)"))
                m3 = fmt_m(p2.get("Method 3 (Track 2 All CoT)"))
                m4 = fmt_m(p2.get("Method 4 (Track 2 Active CoT)"))
                m5 = fmt_m(p2.get("Method 5 (Track 3 Hybrid)"))

                dur = f"{data.get('total_seconds', 0.0)}s"
                lines.append(f"| **{m_name}** | {rec} | {fp} | {p1_f1} | {m1} | {m2} | {m3} | {m4} | {m5} | {dur} |")
            except Exception as e:
                lines.append(f"| {m_name} | ERROR | ERROR | - | - | - | - | - | - | {e} |")

        lines.append("")

    report_content = "\n".join(lines)
    REPORT_PATH.write_text(report_content, encoding="utf-8")
    log(f"Final report saved to: {REPORT_PATH}")


def main():
    log("=== STARTING OVERNIGHT AUTONOMOUS BENCHMARK ORCHESTRATOR ===")
    update_status("INITIALIZING", progress="Starting up orchestrator")
    subprocess.run(["python3", str(VERIFY_SCRIPT), "--context-length", "16384", "--device", "GPU"], check=True)

    # Step 1: Wait for any currently running benchmark (e.g. task-337 on win_bitsadmin_download)
    wait_for_existing_benchmark()
    run_clean_lifecycle()

    total_tasks = len(TARGET_DATASETS) * len(TARGET_MODELS)

    # Step 2: Iterate across all datasets and models with up to 3 autonomous retry passes
    for pass_num in range(1, 4):
        missing_before = [
            (ds, m_name, m_key)
            for ds in TARGET_DATASETS
            for m_name, m_key in TARGET_MODELS
            if not has_completed_summary(m_key, ds)
        ]
        if not missing_before:
            log(f"All {total_tasks} dataset-model pairs have completed summaries!")
            break

        log(f"\n=== [ORCHESTRATOR PASS {pass_num}/3] Remaining tasks: {len(missing_before)}/{total_tasks} ===")
        completed_count = 0

        for ds_idx, dataset in enumerate(TARGET_DATASETS, 1):
            log(f"\n=======================================================")
            log(f">>> [Pass {pass_num} | Dataset {ds_idx}/{len(TARGET_DATASETS)}] {dataset} <<<")
            log(f"=======================================================")

            for m_idx, (m_name, m_key) in enumerate(TARGET_MODELS, 1):
                completed_count += 1
                progress_str = f"Pass {pass_num} | Dataset {ds_idx}/{len(TARGET_DATASETS)} ({dataset}), Model {m_idx}/3 ({m_name}) [{completed_count}/{total_tasks}]"
                update_status("RUNNING", current_dataset=dataset, current_model=m_name, progress=progress_str)

                if has_completed_summary(m_key, dataset):
                    log(f"[SKIP] {m_name} on {dataset} already completed. Moving to next.")
                    continue

                subprocess.run(["python3", str(VERIFY_SCRIPT), "--context-length", "16384", "--device", "GPU"], check=True)
                log(f"▶ Launching {m_name} on {dataset}...")
                cmd = [
                    str(VENV_PYTHON),
                    str(BENCHMARK_SCRIPT),
                    "--dataset", dataset,
                    "--models", m_key
                ]

                try:
                    ret = subprocess.run(cmd, cwd=str(EXP_I_DIR), timeout=None, start_new_session=True,
                                         preexec_fn=_die_with_parent)
                    if ret.returncode != 0:
                        log(f"✖ Warning: Benchmark exited with code {ret.returncode} for {m_name} on {dataset}")
                    else:
                        log(f"✔ Completed successfully: {m_name} on {dataset}")
                except subprocess.TimeoutExpired:
                    log(f"✖ Timeout (2h) expired for {m_name} on {dataset}")
                except Exception as e:
                    log(f"✖ Exception during benchmark execution: {e}")
                finally:
                    run_clean_lifecycle()
                    time.sleep(5)

    # Step 3: Compile final report
    update_status("COMPILING_REPORT", progress="Generating final markdown summary")
    generate_final_report()
    remaining = [
        (ds, m_name)
        for ds in TARGET_DATASETS
        for m_name, m_key in TARGET_MODELS
        if not has_completed_summary(m_key, ds)
    ]
    if remaining:
        update_status("INCOMPLETE", progress=f"Missing {len(remaining)}/{total_tasks}: {remaining}")
        log(f"✖ OVERNIGHT BENCHMARK INCOMPLETE: missing {remaining}")
        sys.exit(1)
    update_status("COMPLETED", progress=f"All {len(TARGET_DATASETS)} datasets and {len(TARGET_MODELS)} models benchmarked successfully")
    log("=== OVERNIGHT BENCHMARK ORCHESTRATOR COMPLETED SUCCESSFULLY ===")


if __name__ == "__main__":
    main()

