#!/bin/bash
# Experiment I chain: per dataset (in DATASETS order) and per profile (in MODELS order) run the per-line
# verdicts (run_i.py) and then the final conclusion step (conclude_v2.py: ATT&CK catalog + description check;
# conclude.py = v1 without the catalog, kept as the baseline), score after every dataset.
# Same stop rules as experiment H (exp_h/scripts/run_h.sh): frozen-input checksum mismatch (11), memory
# guard (exit 5), a signal, new xe GPU errors in the kernel log (10), a failed environment preflight (12),
# exit 1 from a step that wrote no request result (startup/environment failure, 13). Exit 4 (lines without
# a verdict) and exit 1 after at least one request result are recorded and the chain continues.
# A finished step is skipped on restart (DONE / CONCLUDED files; answers are cached per request anyway).
# usage: MODELS="gemma ..." DATASETS="win_lsass_comsvcs ..." run_i.sh
#   MODELS   = profile names (profiles/<name>.toml), default: gemma
#   DATASETS = experiment H dataset names, default: win_lsass_comsvcs (development data)
set -u
I=/home/ubuntu/forensics-option-a/proposals/2026-10-11/exp_i
H=/home/ubuntu/forensics-option-a/proposals/2026-10-10/exp_h
PY=/home/ubuntu/forensics-option-a/venv/bin/python3
cd $H && { sha256sum --quiet -c FROZEN.sha256 || { echo "ABORT: experiment H inputs changed"; exit 11; }; }
cd $I
if [ -f $I/FROZEN.sha256 ]; then sha256sum --quiet -c FROZEN.sha256 || { echo "ABORT: experiment I frozen files changed"; exit 11; }; fi
MODELS=${MODELS:-gemma}
DATASETS=${DATASETS:-win_lsass_comsvcs}
$PY -I -c "import transformers, openvino, yaml" || { echo "ABORT: runner python preflight failed"; exit 12; }
for m in $MODELS; do
  [ -f $I/profiles/$m.toml ] || { echo "ABORT: no profile $m"; exit 12; }
  spy=$(sed -n 's/^python = "\(.*\)"/\1/p' $I/profiles/$m.toml)
  $spy -I -c "import openvino as ov, openvino_genai; assert 'GPU' in ov.Core().available_devices" 2>/dev/null \
    || { echo "ABORT: server python preflight failed for $m ($spy)"; exit 12; }
done
for d in $DATASETS; do
  [ -f $H/data/$d/evidence.db ] || { echo "ABORT: no dataset $d"; exit 12; }
  [ -f $I/samples/$d.json ] || [ -f $H/samples/$d.json ] || { echo "ABORT: no sample for $d"; exit 12; }
done
echo "== preflight OK: models [$MODELS] datasets [$DATASETS]"

gpu_check() {   # $1 = start time; exits the chain on new xe errors
  local gpu
  gpu=$(journalctl -k --since "$1" --no-pager 2>/dev/null | grep -E "xe " | grep -iE "fault|reset|wedged|banned|hang|timedout")
  if [ -n "$gpu" ]; then echo "== GPU kernel errors after $2:"; echo "$gpu" | tail -5; echo "ABORT chain"; exit 10; fi
}

for d in $DATASETS; do
  sample=$I/samples/$d.json; [ -f $sample ] || sample=$H/samples/$d.json
  for m in $MODELS; do
    run=$I/runs/$m/$d
    if [ -f $run/DONE ]; then
      echo "== skip verdicts $m $d (DONE)"
    else
      start=$(date '+%Y-%m-%d %H:%M:%S')
      echo "== $m $d verdicts start $start avail_mb=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)"
      $PY -I $I/scripts/run_i.py $I/profiles/$m.toml $H/data/$d/evidence.db $run --judge $sample
      rc=$?
      echo "== $m $d verdicts exit=$rc end $(date +%T) avail_mb=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)"
      [ $rc -eq 0 -o $rc -eq 4 ] && echo "$rc $(date +%F_%T)" > $run/DONE
      gpu_check "$start" "$m $d verdicts"
      if [ $rc -eq 1 ] && [ -z "$(ls -A $run/results 2>/dev/null)" ]; then
        echo "ABORT chain: $m $d exit 1 with no request result (startup/environment failure)"; exit 13; fi
      if [ $rc -ge 5 ]; then echo "ABORT chain (exit $rc)"; exit $rc; fi
      [ $rc -eq 0 -o $rc -eq 4 ] || continue
    fi
    if [ -f $run/CONCLUDED_V2 ]; then echo "== skip conclude $m $d (CONCLUDED_V2)"; continue; fi
    start=$(date '+%Y-%m-%d %H:%M:%S')
    echo "== $m $d conclude start $start avail_mb=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)"
    $PY -I $I/scripts/conclude_v2.py $I/profiles/$m.toml $run
    rc=$?
    echo "== $m $d conclude exit=$rc end $(date +%T) avail_mb=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)"
    [ $rc -eq 0 ] && echo "$rc $(date +%F_%T)" > $run/CONCLUDED_V2
    gpu_check "$start" "$m $d conclude"
    if [ $rc -eq 1 ] && [ -z "$(ls -A $run/conclude_v2_results 2>/dev/null)" ]; then
      echo "ABORT chain: $m $d conclude exit 1 with no request result (startup/environment failure)"; exit 13; fi
    if [ $rc -ge 5 ]; then echo "ABORT chain (exit $rc)"; exit $rc; fi
  done
  $PY -I $I/scripts/score_i.py $I/runs | tail -6 && echo "== scored after $d"
done
echo "ALL DONE $(date +%T)"
