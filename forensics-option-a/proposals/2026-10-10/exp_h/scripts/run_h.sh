#!/bin/bash
# Experiment H chain: per dataset (in DATASETS order) run Gemma -> Qwen -> FoundationSec with the
# experiment F method on the sampled lines, score after every run. Dataset-major, so a stopped
# chain still leaves complete three-model comparisons for the finished datasets.
# Stops on: checksum mismatch (frozen inputs changed), memory guard (exit 5), a signal, new xe GPU
# errors in the kernel log, a failed environment preflight (exit 12), or exit 1 from a run that wrote
# no request result (startup/environment failure, exit 13). Exit 4 (lines without a verdict) and
# exit 1 after at least one request result (LLM error mid-run) are recorded and the chain continues.
# A finished run is skipped on restart (results are cached per request anyway).
# usage: [MODELS="gemma"] run_h.sh [DATASET ...]   (default: all six datasets, models gemma qwen fsec)
set -u
H=/home/ubuntu/forensics-option-a/proposals/2026-10-10/exp_h
PY=/home/ubuntu/forensics-option-a/venv/bin/python3
cd $H
sha256sum --quiet -c FROZEN.sha256 || { echo "ABORT: frozen inputs changed"; exit 11; }
MODELS=${MODELS:-gemma qwen fsec}
# Preflight: the runner python and every selected model's server python import their packages and
# see the GPU (an OS upgrade once repointed the venvs' interpreter and the whole chain failed in 1 s).
$PY -I -c "import transformers, openvino" || { echo "ABORT: runner python preflight failed"; exit 12; }
for m in $MODELS; do
  spy=$(sed -n 's/^python = "\(.*\)"/\1/p' $H/configs/${m}_p1.toml)
  $spy -I -c "import openvino as ov, openvino_genai; assert 'GPU' in ov.Core().available_devices" 2>/dev/null \
    || { echo "ABORT: server python preflight failed for $m ($spy)"; exit 12; }
done
echo "== preflight OK: $MODELS"
DATASETS=${*:-"win_bitsadmin_download win_auditpol_disable win_remote_schtask win_ntds_ntdsutil win_psremoting win_uac_fodhelper"}
for d in $DATASETS; do
  for m in $MODELS; do
    run=$H/runs/$m/$d
    if [ -f $run/DONE ]; then echo "== skip $m $d (DONE)"; continue; fi
    start=$(date '+%Y-%m-%d %H:%M:%S')
    echo "== $m $d start $start avail_mb=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)"
    $PY -I $H/scripts/run_h.py $H/configs/${m}_p1.toml $H/data/$d/evidence.db $run --judge $H/samples/$d.json
    rc=$?
    echo "== $m $d exit=$rc end $(date +%T) avail_mb=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)"
    [ $rc -eq 0 -o $rc -eq 4 ] && echo "$rc $(date +%F_%T)" > $run/DONE
    gpu=$(journalctl -k --since "$start" --no-pager 2>/dev/null | grep -E "xe " | grep -iE "fault|reset|wedged|banned|hang|timedout")
    if [ -n "$gpu" ]; then echo "== GPU kernel errors after $m $d:"; echo "$gpu" | tail -5; echo "ABORT chain"; exit 10; fi
    if [ $rc -eq 1 ] && [ -z "$(ls -A $run/results 2>/dev/null)" ]; then
      echo "ABORT chain: $m $d exit 1 with no request result (startup/environment failure)"; exit 13; fi
    if [ $rc -ge 5 ]; then echo "ABORT chain (exit $rc)"; exit $rc; fi
  done
  $PY -I $H/scripts/score_h.py $H/runs | tail -4 && echo "== scored after $d"
done
echo "ALL DONE $(date +%T)"
