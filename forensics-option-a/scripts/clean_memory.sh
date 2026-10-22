#!/bin/bash
# ==============================================================================
# Unified Process & Complete Memory Reclaiming Script (Rule 9 Compliant)
# ==============================================================================

echo "========================================================"
echo "🛑 Stopping all LLM & Forensic servers & Reclaiming Memory..."
echo "========================================================"

# 1. 포트 점유 프로세스 강제 종료
fuser -k -9 8080/tcp >/dev/null 2>&1 || true
fuser -k -9 8081/tcp >/dev/null 2>&1 || true
fuser -k -9 8086/tcp >/dev/null 2>&1 || true

# 2. 모든 llama 바이너리 및 포렌식/서버 프로세스 전수 추적 종료
pkill -9 -f "llama-server" >/dev/null 2>&1 || true
pkill -9 -f "openvino_server" >/dev/null 2>&1 || true
pkill -9 -f "llama-cli" >/dev/null 2>&1 || true
pkill -9 -f "llama-completion" >/dev/null 2>&1 || true
pkill -9 -f "llama-bench" >/dev/null 2>&1 || true
pkill -9 -f "server.py" >/dev/null 2>&1 || true
pkill -9 -f "foundation_sec_forensics" >/dev/null 2>&1 || true
pkill -9 -f "hierarchical_forensics" >/dev/null 2>&1 || true
pkill -9 -f "recursive_agentic_forensics" >/dev/null 2>&1 || true
pkill -9 -f "run_forensics" >/dev/null 2>&1 || true
pkill -9 -f "run_hierarchical_pipeline" >/dev/null 2>&1 || true
pkill -9 -f "step1_fsec" >/dev/null 2>&1 || true
pkill -9 -f "step2_gemma" >/dev/null 2>&1 || true
pkill -9 -f "step3_assemble" >/dev/null 2>&1 || true

sleep 1

# 3. 잔여 프로세스 전수 확인 및 재차 강제 종료
REMAINING=$(pgrep -f "llama-|openvino_server|server.py|foundation_sec|hierarchical_forensics|recursive_agentic|step1_fsec|step2_gemma|run_hierarchical" || true)
if [ -n "$REMAINING" ]; then
    echo "⚠️ 잔여 프로세스 강제 종료: $REMAINING"
    kill -9 $REMAINING 2>/dev/null || true
fi

# 4. 커널 캐시 및 메모리 단편화 즉시 전수 회수 (drop_caches & compact)
echo "🧹 Reclaiming Page Cache & Compacting Memory..."
if sudo -n true 2>/dev/null; then
    sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches; echo 1 > /proc/sys/vm/compact_memory' 2>/dev/null || true
elif [ -n "$SUDO_PASS" ]; then
    echo "$SUDO_PASS" | sudo -S sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches; echo 1 > /proc/sys/vm/compact_memory' 2>/dev/null || true
fi

echo "========================================================"
echo "✔ 모든 프로세스 및 메모리 회수 완료!"
echo "========================================================"
free -h
