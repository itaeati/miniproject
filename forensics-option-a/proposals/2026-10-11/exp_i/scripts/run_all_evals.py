#!/usr/bin/env python3
"""
Batch benchmark orchestrator across all datasets and 3 models for 5 tracks.
Ensures process isolation, memory lifecycle cleanup, and resumable execution.
"""
import os
import sys
import json
import time
import subprocess
from pathlib import Path

BASE_DIR = Path("/home/ubuntu/forensics-option-a/proposals/2026-10-11/exp_i")
PYTHON = "/home/ubuntu/forensics-option-a/venv_ov2604/bin/python3"
EVAL_SCRIPT = BASE_DIR / "scripts" / "eval_tracks.py"
CLEAN_SCRIPT = "/home/ubuntu/.agents/skills/mind2-verified-ops/scripts/clean_lifecycle.sh"

DATASETS = [
    "win_auditpol_disable",
    "win_ntds_ntdsutil",
    "win_psremoting",
    "win_remote_schtask",
    "win_uac_fodhelper"
]

MODELS = [
    ("Gemma-4-26B-OV-INT4", BASE_DIR / "profiles" / "final_gemma.toml"),
    ("FoundationSec-8B-Reasoning-OV-INT8", BASE_DIR / "profiles" / "final_fsec.toml"),
    ("Qwen3.8-27B-OV-INT4", BASE_DIR / "profiles" / "final_qwen.toml"),
]


def clean_memory():
    try:
        subprocess.run(["bash", CLEAN_SCRIPT], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
    except Exception as e:
        print(f"[WARN] clean_memory failed: {e}")


def is_already_done(run_dir: Path, model_name: str) -> bool:
    summary_file = run_dir / f"eval_tracks_summary_{model_name}.json"
    if not summary_file.exists():
        return False
    try:
        data = json.loads(summary_file.read_text())
        required_keys = ["Baseline", "Track 1 (B+C)", "Track 2 (D: All Groups)", "Track 3 (B+C+D)"]
        return all(k in data for k in required_keys)
    except Exception:
        return False


def main():
    print("=================================================================")
    print("▶ Starting Comprehensive All-Datasets 3-Model 5-Track Benchmark")
    print(f"▶ Datasets: {DATASETS}")
    print(f"▶ Models: {[m[0] for m in MODELS]}")
    print("=================================================================\n")

    total_tasks = len(DATASETS) * len(MODELS)
    current_idx = 0

    for d in DATASETS:
        run_dir = BASE_DIR / "runs" / "final_gemma" / d
        if not run_dir.exists():
            print(f"[SKIP] Directory not found: {run_dir}")
            continue

        for model_name, profile_path in MODELS:
            current_idx += 1
            print(f"\n-------------------------------------------------------------")
            print(f"[{current_idx}/{total_tasks}] Processing {d} with {model_name}")
            print(f"-------------------------------------------------------------")

            if is_already_done(run_dir, model_name):
                print(f"✔ Already completed. Skipping: {run_dir.name} - {model_name}")
                continue

            # Ensure clean memory before model execution
            clean_memory()

            cmd = [
                PYTHON, "-u", str(EVAL_SCRIPT),
                str(profile_path), str(run_dir),
                "--tracks", "all"
            ]

            t0 = time.time()
            try:
                proc = subprocess.run(cmd, cwd=str(BASE_DIR), check=True)
                dur = time.time() - t0
                print(f"✔ Completed {d} with {model_name} in {dur:.2f}s")
            except subprocess.CalledProcessError as e:
                print(f"✖ Failed {d} with {model_name} (exit code {e.returncode})")
            except Exception as e:
                print(f"✖ Exception during {d} with {model_name}: {e}")
            finally:
                clean_memory()

    print("\n=================================================================")
    print("✔ All batch benchmark tasks completed.")
    print("=================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
