# Overnight Multi-Dataset & Cross-Model Benchmark Final Report
**Execution Timestamp**: 2026-10-18 16:49:30

## 1. Executive Summary
- **Target Hardware**: Khadas Mind 2 (Intel Core Ultra 7 258V, 32GB LPDDR5X, Arc Xe2 GPU via OpenVINO)
- **Evaluated Datasets**: 3 Windows Attack Scenarios
- **Evaluated Models**: FoundationSec-8B, Gemma-4-26B, Qwen3.8-27B
- **Attribution Methods**: 5 Methods (Method 1 Baseline, Method 2 RAG, Method 3 All CoT, Method 4 Active CoT, Method 5 Hybrid)

### Dataset: `win_bitsadmin_download`
| Model | P1 Recall (LLM direct / total) | P1 FP (FPR) | P1 F1 | M1 (Match/Grounding) | M2 (Match/Grounding) | M3 (Match/Grounding) | M4 (Match/Grounding) | M5 (Match/Grounding) | Duration |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **FoundationSec-8B** | 92.86% / 92.86% (no_verdict 0) | 30 (34.09%) | 61.9% | MISS/UNGROUNDED (FP:10, F1:0.0%, cite-attack:9.09%) | EXACT/GROUNDED (FP:8, F1:20.0%, cite-attack:45.45%) | EXACT/GROUNDED (FP:8, F1:20.0%, cite-attack:30.0%) | EXACT/GROUNDED (FP:3, F1:40.0%, cite-attack:75.0%) | EXACT/GROUNDED (FP:1, F1:66.67%, cite-attack:50.0%) | 8715.49s |
| **Gemma-4-26B** | 100.0% / 100.0% (no_verdict 0) | 56 (63.64%) | 50.0% | EXACT/GROUNDED (FP:2, F1:50.0%, cite-attack:25.0%) | EXACT/GROUNDED (FP:0, F1:100.0%, cite-attack:100.0%) | EXACT/GROUNDED (FP:7, F1:22.22%, cite-attack:11.11%) | EXACT/GROUNDED (FP:2, F1:50.0%, cite-attack:33.33%) | EXACT/GROUNDED (FP:2, F1:50.0%, cite-attack:40.0%) | 2445.42s |
| **Qwen3.8-27B** | 100.0% / 100.0% (no_verdict 0) | 22 (25.0%) | 71.79% | EXACT/GROUNDED (FP:4, F1:33.33%, cite-attack:50.0%) | EXACT/GROUNDED (FP:0, F1:100.0%, cite-attack:100.0%) | EXACT/GROUNDED (FP:2, F1:50.0%, cite-attack:83.33%) | EXACT/GROUNDED (FP:2, F1:50.0%, cite-attack:100.0%) | EXACT/GROUNDED (FP:1, F1:66.67%, cite-attack:33.33%) | 6144.26s |

### Dataset: `win_remote_schtask`
| Model | P1 Recall (LLM direct / total) | P1 FP (FPR) | P1 F1 | M1 (Match/Grounding) | M2 (Match/Grounding) | M3 (Match/Grounding) | M4 (Match/Grounding) | M5 (Match/Grounding) | Duration |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **FoundationSec-8B** | 66.67% / 66.67% (no_verdict 1) | 49 (63.64%) | 54.55% | EXACT/GROUNDED (FP:8, F1:33.33%, cite-attack:46.67%) | EXACT/GROUNDED (FP:6, F1:40.0%, cite-attack:66.67%) | EXACT/GROUNDED (FP:11, F1:15.38%, cite-attack:50.0%) | EXACT/GROUNDED (FP:6, F1:25.0%, cite-attack:77.78%) | EXACT/GROUNDED (FP:9, F1:18.18%, cite-attack:81.82%) | 13340.35s |
| **Gemma-4-26B** | 100.0% / 100.0% (no_verdict 1) | 56 (72.73%) | 69.23% | EXACT/GROUNDED (FP:7, F1:22.22%, cite-attack:72.22%) | EXACT/GROUNDED (FP:6, F1:25.0%, cite-attack:85.71%) | EXACT/GROUNDED (FP:7, F1:22.22%, cite-attack:65.0%) | EXACT/GROUNDED (FP:5, F1:28.57%, cite-attack:86.67%) | EXACT/GROUNDED (FP:8, F1:33.33%, cite-attack:90.91%) | 4070.46s |
| **Qwen3.8-27B** | 85.71% / 85.71% (no_verdict 0) | 32 (41.56%) | 72.48% | EXACT/GROUNDED (FP:7, F1:22.22%, cite-attack:76.47%) | EXACT/GROUNDED (FP:5, F1:28.57%, cite-attack:100.0%) | EXACT/GROUNDED (FP:4, F1:33.33%, cite-attack:100.0%) | EXACT/GROUNDED (FP:4, F1:33.33%, cite-attack:100.0%) | EXACT/GROUNDED (FP:6, F1:25.0%, cite-attack:90.91%) | 9394.06s |

### Dataset: `win_auditpol_disable`
| Model | P1 Recall (LLM direct / total) | P1 FP (FPR) | P1 F1 | M1 (Match/Grounding) | M2 (Match/Grounding) | M3 (Match/Grounding) | M4 (Match/Grounding) | M5 (Match/Grounding) | Duration |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **FoundationSec-8B** | 65.26% / 65.26% (no_verdict 0) | 16 (32.0%) | 71.68% | PARENT/GROUNDED (FP:1, F1:66.67%, cite-attack:100.0%) | MISS/UNGROUNDED (FP:4, F1:0.0%, cite-attack:100.0%) | EXACT/GROUNDED (FP:4, F1:33.33%, cite-attack:80.0%) | EXACT/GROUNDED (FP:3, F1:40.0%, cite-attack:100.0%) | PARENT/GROUNDED (FP:2, F1:50.0%, cite-attack:100.0%) | 7915.24s |
| **Gemma-4-26B** | 100.0% / 100.0% (no_verdict 1) | 0 (0.0%) | 100.0% | MISS/UNGROUNDED (FP:1, F1:0.0%, cite-attack:100.0%) | MISS/UNGROUNDED (FP:0, F1:0.0%, cite-attack:0.0%) | EXACT/GROUNDED (FP:3, F1:57.14%, cite-attack:100.0%) | EXACT/GROUNDED (FP:3, F1:57.14%, cite-attack:100.0%) | EXACT/GROUNDED (FP:2, F1:66.67%, cite-attack:100.0%) | 3333.71s |
| **Qwen3.8-27B** | 100.0% / 100.0% (no_verdict 0) | 4 (8.0%) | 97.94% | MISS/UNGROUNDED (FP:3, F1:0.0%, cite-attack:100.0%) | MISS/UNGROUNDED (FP:2, F1:0.0%, cite-attack:100.0%) | EXACT/GROUNDED (FP:4, F1:33.33%, cite-attack:100.0%) | EXACT/GROUNDED (FP:4, F1:33.33%, cite-attack:100.0%) | EXACT/GROUNDED (FP:2, F1:50.0%, cite-attack:100.0%) | 10383.89s |
