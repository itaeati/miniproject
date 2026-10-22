# hdf — local-LLM hypothesis drill-down forensic engine

Reads a directory of log evidence, finds suspicious activity with a local triage
model, forms and tests attack hypotheses with a local reasoning model, and writes
a report in which every statement is either computed from the evidence or was
checked against the events it cites.

## Usage

```bash
cd ~/forensics
# full investigation (resumable: re-run the same command with the same --out)
venv/bin/python3 hypothesis_drilldown_forensics.py run <evidence dir> --config hdf.toml --out hdf_runs/<name>
# evidence store only (inspection, timing)
venv/bin/python3 hypothesis_drilldown_forensics.py ingest <evidence dir> --config hdf.toml --out hdf_runs/<name>
# re-check a finished report against the evidence
venv/bin/python3 hypothesis_drilldown_forensics.py verify hdf_runs/<name> --config hdf.toml

# validation datasets (OTRF Security-Datasets) and scoring
venv/bin/python3 -m hdf_eval list
venv/bin/python3 -m hdf_eval fetch all
venv/bin/python3 -m hdf_eval run win_lsass_comsvcs --config hdf.toml
venv/bin/python3 -m hdf_eval summary --config hdf.toml

# tests (no model server needed)
venv/bin/python3 -m unittest hdf.tests.test_units hdf.tests.test_pipeline
```

Large evidence: `--coverage budget --budget-tokens N` reads the rarest event
patterns first until N phase-1 input tokens are spent; the report states the
coverage that was achieved. The default is full coverage.

## Pipeline

| Phase | What happens | Model |
|---|---|---|
| 0 ingest | Every file is parsed (JSON lines, JSON documents incl. `{"Records":[...]}`, CSV, EVTX, syslog/plain text, `.gz`, `.zip`). All fields are kept in `evidence.db` (SQLite + trigram index). Timestamps are converted to UTC; fields of one source that use a different clock are aligned when their offset is consistent, otherwise flagged. Identical activity that differs only in volatile values (PIDs, ports, GUIDs) is grouped into patterns. | none |
| 1 triage | Patterns are packed into chunks counted with the model's own tokenizer (input ≤ 12,288 tokens incl. instructions, output ≤ 4,096). Each finding must cite pattern IDs; entities and statements are checked against the full cited events. Results are cached per chunk content; failures are retried, split, and never cached as done. | triage |
| 2 reduce + hypothesize | Findings are reduced hierarchically (leads cite findings) until they fit, then hypotheses with verification searches are generated. Hypotheses mentioning values absent from the evidence are discarded. | reasoner |
| 3 drill-down + feedback | Searches run over the whole evidence store (all files, host and time filters, matches sampled across the full time range, same-host neighbours). Verdicts are checked in code. Refuted / unverifiable hypotheses are fed back for alternatives; new pivot values are searched across all evidence and fed back. | reasoner |
| 4 report | Only SUPPORTED hypotheses become conclusions. Tables, timeline and entities come from the store; summary sentences are kept only if every value in them is in their cited events. | reasoner |
| verify | Independent re-check of report.json / report.md against the evidence store. | none |

## What "no hallucination in the final result" means here

Guaranteed by code (tested in `hdf/tests`):
- Every event, host, account, path, address, hash, time, ATT&CK ID, threat-actor or software name in
  sections 2–5 of the report occurs in evidence events cited for that statement, or the statement is
  removed. The verifier fails the run otherwise.
- ATT&CK IDs must exist in the current ATT&CK release; revoked IDs are mapped to their replacements.
- No matching events is never treated as proof that something did not happen.
- Refuted and unverified hypotheses are not reproduced in the report.

Not guaranteed (inherent to any LLM-based analysis):
- The *interpretation* that cited events constitute a technique or an attack stage is a model
  judgement. It is labelled as such and always shown next to the raw events it rests on.
- Activity the triage model does not flag in phase 1 can still be missed (false negatives).

## Files in a run directory

`evidence.db` store · `findings.json` grounded phase-1 findings · `state/` plans, coverage and
investigation state (hypotheses with history) · `results/phase1/` per-chunk results ·
`audit/llm/` every prompt and raw model output · `audit/rejections.jsonl` every claim removed by a
check and why · `report.md`, `report.json`, `verification.json` · `logs/`.

## Configuration

`hdf/default_config.toml` documents every setting. Machine-specific values (model paths, server
script, port, cleanup hook) go in a separate file such as `~/forensics/hdf.toml`. No paths are
hard-coded in the engine.

The model server (`server_tools/openvino_server.py`) must report `"raw_prompt": true` on `/health`:
hdf formats prompts with the model's own chat template, and the server must not apply it a second time.
