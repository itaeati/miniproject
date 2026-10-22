#!/usr/bin/env bash
set -e

# 기본 설정값
CHAIN="INPUT"
PROTO="tcp"
PORT="80"
QUEUE_NUM="0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="${SCRIPT_DIR}/packet_collect"

# 도움말 출력
usage() {
    echo "Usage: sudo $0 [-c CHAIN] [-p PROTO] [-d DPORT] [-q QUEUE_NUM] [-- EXTRA_ARGS...]"
    echo "  -c CHAIN      : iptables 체인 (기본: INPUT, 예: FORWARD, OUTPUT)"
    echo "  -p PROTO      : 프로토콜 (기본: tcp, 예: udp)"
    echo "  -d DPORT      : 대상 포트 (기본: 80)"
    echo "  -q QUEUE_NUM  : NFQUEUE 번호 (기본: 0)"
    exit 1
}

# CLI 옵션 파싱
while getopts "c:p:d:q:h" opt; do
    case "$opt" in
        c) CHAIN="$OPTARG" ;;
        p) PROTO="$OPTARG" ;;
        d) PORT="$OPTARG" ;;
        q) QUEUE_NUM="$OPTARG" ;;
        h|*) usage ;;
    esac
done
shift $((OPTIND - 1))

# 루트 권한 확인
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] iptables 설정을 위해 root 권한(sudo)이 필요합니다." >&2
    exit 1
fi

# 실행 바이너리 확인
if [ ! -x "$BIN_PATH" ]; then
    echo "[ERROR] 실행 바이너리가 존재하지 않거나 실행 권한이 없습니다: $BIN_PATH" >&2
    exit 1
fi

RULE_ARGS=("$CHAIN" "-p" "$PROTO" "--dport" "$PORT" "-j" "NFQUEUE" "--queue-num" "$QUEUE_NUM")
READY_FILE="$(mktemp /tmp/packet_collect_ready.XXXXXX)"
rm -f "$READY_FILE"
CLEANED=0

# 자원 회수 및 방화벽 원상복구 함수 (중복 실행 방지)
cleanup() {
    if [ "$CLEANED" -eq 1 ]; then
        return
    fi
    CLEANED=1
    echo -e "\n[+] 프로세스 수명주기 종료 감지. 정리 작업 시작..."

    # 1. 방화벽 룰 우선 제거 (신규 패킷 유입 차단 방지)
    if iptables -C "${RULE_ARGS[@]}" 2>/dev/null; then
        iptables -D "${RULE_ARGS[@]}"
        echo "[+] [IPv4] iptables 룰 삭제 완료: -D ${RULE_ARGS[*]}"
    fi

    if ip6tables -C "${RULE_ARGS[@]}" 2>/dev/null; then
        ip6tables -D "${RULE_ARGS[@]}" 2>/dev/null || true
        echo "[+] [IPv6] ip6tables 룰 삭제 완료: -D ${RULE_ARGS[*]}"
    fi

    # 2. 자식 프로세스 정리
    if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
        echo "[+] 실행 중인 packet_collect (PID: $PID) 종료 중..."
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi

    rm -f "$READY_FILE"
    echo "[+] 모든 리소스 회수 및 네트워크 환경 복원 완료."
}

# 종료 트랩 등록
trap cleanup EXIT INT TERM HUP

# 1. packet_collect 선행 기동 및 모델·NFQUEUE 준비 대기 (기동 실패 시 방화벽 미주입)
echo "[+] packet_collect 실행 시작 (체인: $CHAIN, 프로토콜: $PROTO, 포트: $PORT, 큐: $QUEUE_NUM)..."
"$BIN_PATH" -q "$QUEUE_NUM" --ready-file "$READY_FILE" "$@" &
PID=$!

while [ ! -f "$READY_FILE" ]; do
    if ! kill -0 "$PID" 2>/dev/null; then
        set +e
        wait "$PID"
        EXIT_STATUS=$?
        set -e
        echo "[ERROR] packet_collect 기동 실패 (종료 코드: $EXIT_STATUS). 방화벽 룰을 주입하지 않고 종료합니다." >&2
        exit "$EXIT_STATUS"
    fi
    sleep 0.05
done
rm -f "$READY_FILE"

# 2. NFQUEUE 바인드 확인 후 IPv4 및 IPv6 방화벽 룰 주입
echo "[+] [IPv4] iptables 룰 주입: -I ${RULE_ARGS[*]}"
iptables -I "${RULE_ARGS[@]}"

echo "[+] [IPv6] ip6tables 룰 주입: -I ${RULE_ARGS[*]}"
ip6tables -I "${RULE_ARGS[@]}" 2>/dev/null || true

# 룰 주입 직전 수립된 연결까지 누락 없이 보호하도록 재스캔 신호 전달
kill -USR2 "$PID" 2>/dev/null || true
echo "[+] 트래픽 대기 중... (접속 시도나 데이터 패킷이 오면 실시간 출력됩니다. 종료: Ctrl+C)"

# 자식 프로세스 종료 대기
set +e
wait "$PID"
EXIT_STATUS=$?
set -e

# 비정상 크래시 감지 (SIGTERM=143, SIGINT=130 제외)
if [ $EXIT_STATUS -ne 0 ] && [ $EXIT_STATUS -ne 143 ] && [ $EXIT_STATUS -ne 130 ]; then
    if [ $EXIT_STATUS -gt 128 ]; then
        SIGNAL=$((EXIT_STATUS - 128))
        echo -e "\n[!] 경고: packet_collect가 시그널(${SIGNAL})에 의해 급사했습니다 (Segfault, OOM-Kill 등)." >&2
    else
        echo -e "\n[!] 경고: packet_collect가 비정상 코드(${EXIT_STATUS})로 종료되었습니다." >&2
    fi
    exit "$EXIT_STATUS"
fi
