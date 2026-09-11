#!/bin/bash
# AEGIS 전체 회귀 테스트 (타입체크 + 유닛) — 서비스별 병렬 실행
# Usage: ./scripts/test-all.sh [서비스명 ...]   인자 없으면 전체
#   결과 로그: scripts/.logs/test/<서비스>.log
# ponytail: 전 스위트를 무조건 병렬로 띄운다. 포트를 잡는 통합 테스트끼리
#   드물게 충돌할 수 있고, 그때는 서비스명을 인자로 줘서 나눠 돌리면 된다.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT_DIR/scripts/.logs/test"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; DIM='\033[2m'; NC='\033[0m'

TS_SERVICES=(shared backend frontend adapter ecu-simulator container-gateway)
PY_SERVICES=(analysis-agent build-agent knowledge-base llm-gateway sast-runner)

# 자체 node_modules 가 있거나 루트 workspace 로 등록돼 있으면 실행 가능
node_deps_ready() {
  grep -q "\"services/$1\"" "$ROOT_DIR/package.json" && return 0
  [ -d "$ROOT_DIR/services/$1/node_modules" ]
}

run_ts() {
  local s=$1 d="$ROOT_DIR/services/$1" log="$LOG_DIR/$1.log"
  if ! node_deps_ready "$s"; then echo SKIP:의존성_미설치 > "$LOG_DIR/$s.status"; return; fi
  { cd "$d" && npx tsc --noEmit && npm test --if-present; } > "$log" 2>&1 \
    && echo PASS > "$LOG_DIR/$s.status" || echo FAIL > "$LOG_DIR/$s.status"
}

run_py() {
  local s=$1 d="$ROOT_DIR/services/$1" log="$LOG_DIR/$1.log"
  if [ ! -x "$d/.venv/bin/python" ]; then echo SKIP:venv_없음 > "$LOG_DIR/$s.status"; return; fi
  { cd "$d" && .venv/bin/python -m pytest -q -p no:cacheprovider; } > "$log" 2>&1 \
    && echo PASS > "$LOG_DIR/$s.status" || echo FAIL > "$LOG_DIR/$s.status"
}

# 실행 대상 결정
if [ $# -gt 0 ]; then targets=("$@"); else targets=("${TS_SERVICES[@]}" "${PY_SERVICES[@]}"); fi

rm -rf "$LOG_DIR"; mkdir -p "$LOG_DIR"

# backend/frontend 타입체크가 @aegis/shared 의 dist 를 참조하므로 TS 대상이 있을 때만 먼저 빌드
for s in "${targets[@]}"; do
  [[ " ${TS_SERVICES[*]} " == *" $s "* ]] || continue
  printf "${DIM}shared 빌드...${NC}\n"
  if ! (cd "$ROOT_DIR/services/shared" && npm run build) > "$LOG_DIR/_shared-build.log" 2>&1; then
    printf "  ${RED}shared 빌드 실패${NC} — $LOG_DIR/_shared-build.log\n"; exit 1
  fi
  break
done

printf "${DIM}%d개 스위트 병렬 실행...${NC}\n\n" "${#targets[@]}"
for s in "${targets[@]}"; do
  if [[ " ${PY_SERVICES[*]} " == *" $s "* ]]; then run_py "$s" &
  elif [[ " ${TS_SERVICES[*]} " == *" $s "* ]]; then run_ts "$s" &
  else printf "  ${YELLOW}알 수 없는 서비스: %s${NC}\n" "$s"; fi
done
wait

failed=0; skipped=0
for s in "${targets[@]}"; do
  [ -f "$LOG_DIR/$s.status" ] || continue
  status=$(cat "$LOG_DIR/$s.status")
  case "$status" in
    PASS)  printf "  ${GREEN}PASS${NC}  %-18s ${DIM}%s${NC}\n" "$s" "$(grep -hoE '[0-9]+ (passed|tests? passed)' "$LOG_DIR/$s.log" | tail -1)" ;;
    FAIL)  printf "  ${RED}FAIL${NC}  %-18s ${DIM}%s${NC}\n" "$s" "$LOG_DIR/$s.log"; failed=$((failed+1)) ;;
    SKIP*) printf "  ${YELLOW}SKIP${NC}  %-18s ${DIM}%s${NC}\n" "$s" "${status#SKIP:}"; skipped=$((skipped+1)) ;;
  esac
done

echo
if [ $failed -gt 0 ]; then
  printf "${RED}%d개 스위트 실패${NC}" "$failed"; [ $skipped -gt 0 ] && printf ", ${YELLOW}%d개 건너뜀${NC}" "$skipped"; echo
  exit 1
fi
printf "${GREEN}전체 통과${NC}"; [ $skipped -gt 0 ] && printf ", ${YELLOW}%d개 건너뜀${NC}" "$skipped"; echo
