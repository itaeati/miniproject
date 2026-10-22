#!/bin/bash
# One-off driver (2026-10-10): v2 conclusion on the old-harness Gemma run (comparison input), archive it, then
# Gemma tuning run 1 with the new harness (variable packing, restored lines, dynamic output, conclude_v2).
set -u
I=/home/ubuntu/forensics-option-a/proposals/2026-10-11/exp_i
cd $I
MODELS=gemma DATASETS=win_lsass_comsvcs bash scripts/run_i.sh > tune_gemma_0_v2conclude.log 2>&1
rc=$?; echo "v2 conclusion on run 0: exit $rc"
[ $rc -eq 0 ] || exit $rc
mkdir -p runs_old && mv runs/gemma/win_lsass_comsvcs runs_old/gemma_run0_fixedpacking
MODELS=gemma DATASETS=win_lsass_comsvcs bash scripts/run_i.sh > tune_gemma_1.log 2>&1
echo "gemma tuning run 1: exit $?"
