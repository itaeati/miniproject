# Experiment I — development tuning log (DEVELOPMENT data: win_lsass_comsvcs, 184 lines, 87 attack)

Rules (fixed before the first run, PLAN.md Task 6):
- Up to 3 runs per model (Gemma, Qwen, fsec). 1 run = all lsass lines judged + conclusion step.
- Each run changes ONE profile value. Run 1 = baseline profile:
  Gemma gemma -> next candidate gemma_sampled; Qwen qwen_think -> next qwen; fsec fsec -> next context_position=after.
  Runs 2-3 are chosen from run 1's result.
- Selection order: 1) recall (bound + unbound attack) 2) true technique exact 3) FP rate 4) generation time.
- Common part (prompt rules, quote binding, scoring) is NOT changed here; a change needs user approval and restarts
  every model's tuning.

| # | date | model | profile (diff vs baseline) | recall (unbound) | FP rate (unbound) | no_verdict | techniques (exact/parent/extra) | hit_limit | gen s | next / reason |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 10-10 | Gemma | gemma (baseline: greedy, thinking off) | pass1 0.471 -> 1.0 (unbound 1) | 0.376 -> 0.753 (unbound 1) | 0 | 1/0/6 (T1003.001; extra T1005, T1012, T1016, T1036.002, T1055, T1059.001) | 0 (verdicts) / 0 (conclusion) | 3241 + 669 | next: gemma_sampled. 66 requests, max prompt 12,139; rounds flipped 68, 16. Conclusion re-run after the select-schema fix (progress.md Ruling); before the fix 12/37 conclusion requests looped (conclusions_v2_freeid.json). |
| 2 | 10-10 | Gemma | gemma_sampled (sampling = model) | pass1 0.506 -> 1.0 (unbound 1) | 0.43 -> 0.817 (unbound 2) | 1 | 1/0/3 (T1003.001; extra T1005, T1012, T1059.001) | 0 | 2874 + ~590 | worse FP, 1 no_verdict, same recall/exact -> gemma (run 1) stays. 56 requests; rounds flipped 66, 16. |
| 1 | 10-11 | Qwen | qwen_think (thinking on, model sampling) | stopped (5 results) | - | - | - | 2 | 3157 | STOPPED by the >900 s rule: f_02 (prompt 10,291) 1,236 s and cut at the output limit (6,093) twice; stopped after the in-flight request. Not a candidate. |
| 2 | 10-11 | Qwen | qwen (thinking off, greedy) | pass1 1.0 -> 1.0 (unbound 0) | 0.086 -> 0.624 (unbound 0) | 0 | 1/0/7 | 0 / 0 | 7976 + 1731 | 42 requests; rounds flipped 26, 27, 0. Final. |
| 1 | 10-11 | fsec | fsec (thinking on, model sampling) | pass1 0.655 -> 0.885 (unbound 14) | 0.43 -> 0.903 (unbound 11) | 2 | 1/0/7 | 2 / 0 | 12296 + 1970 | 103 requests; rounds flipped 53, 3, 10. |
| 2 | 10-11 | fsec | fsec_after (context_position = after) | pass1 0.586 -> 0.954 (unbound 18) | 0.581 -> 0.645 (unbound 11) | 2 | 1/0/15 | 0 / 0 | 10371 + 2447 | higher recall, lower FP -> final. 105 requests; rounds flipped 37, 4, 0. |

Finals (rule: recall > exact > FP > time): Gemma = gemma (run 1; same recall/exact as gemma_sampled, lower FP);
Qwen = qwen (qwen_think stopped by the time rule); fsec = fsec_after (recall 0.954 > 0.885).
No 3rd run: no candidate was fixed in advance for run 3 and the test run needs ~30 h of GPU (PLAN Task 7).
