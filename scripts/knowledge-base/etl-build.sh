#!/usr/bin/env bash
# AEGIS Knowledge Base — 위협 지식 ETL 파이프라인
# CWE + ATT&CK (ICS+Enterprise) + CAPEC → Qdrant 벡터 DB + Neo4j 그래프
#
# CVE/NVD는 ETL에서 제외됨 — 프로젝트 분석 시 실시간 조회로 전환 (POST /v1/cve/batch-lookup)
#
# 사전 조건:
#   - KB 서비스(:8002)가 중지된 상태여야 함 (Qdrant 파일 락 충돌 방지)
#   - .venv 설치 완료 (python3 -m venv .venv && pip install -r requirements.txt)
#
# Usage:
#   ./scripts/knowledge-base/etl-build.sh               # Qdrant 적재만
#   ./scripts/knowledge-base/etl-build.sh --seed         # Qdrant + Neo4j 시드
#   ./scripts/knowledge-base/etl-build.sh --fresh        # 캐시 삭제 후 재다운로드
#   ./scripts/knowledge-base/etl-build.sh --fresh --seed # 전체 재빌드
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
KB_DIR="$REPO_ROOT/services/knowledge-base"
QDRANT_PATH="$KB_DIR/data/qdrant"
RAW_CACHE="$KB_DIR/data/threat-db-raw"
SEED=false
FRESH=false
BUILD_ARGS=()

load_env_file() {
  local env_file="$1"
  local line key value
  [ -f "$env_file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" == AEGIS_KB_*"="* ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
      value="${value:1:${#value}-2}"
    fi
    export "${key}=${value}"
  done < "$env_file"
}

redact_url_userinfo() {
  local value="$1"
  local prefix rest
  if [[ "$value" == *"://"* && "$value" == *"@"* ]]; then
    prefix="${value%%://*}://"
    rest="${value#*://}"
    echo "${prefix}***@${rest#*@}"
  else
    echo "$value"
  fi
}

for arg in "$@"; do
  case $arg in
    --seed)  SEED=true ;;
    --fresh) FRESH=true ;;
    *)       BUILD_ARGS+=("$arg") ;;
  esac
done

cd "$KB_DIR"

# .env 로드: shell source 대신 S5-owned AEGIS_KB_* key-value만 안전 export한다.
load_env_file ".env"

LEDGER_URL="${AEGIS_KB_LEDGER_URL:-sqlite:///data/s5-ledger.sqlite}"
NEO4J_URI="${AEGIS_KB_NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${AEGIS_KB_NEO4J_USER:-neo4j}"
NEO4J_PASSWORD="${AEGIS_KB_NEO4J_PASSWORD:-aegis-kb}"

# ── Pre-flight checks ──

if [ ! -d ".venv" ]; then
  echo "ERROR: .venv not found."
  echo "       Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

if [ -f "$QDRANT_PATH/.lock" ]; then
  if ! command -v lsof &>/dev/null 2>&1; then
    echo "ERROR: Qdrant lock file exists but lsof is unavailable; refusing to run ETL fail-closed."
    echo "       KB 서비스를 먼저 중지하거나 lsof를 설치한 뒤 stale lock 여부를 확인하세요."
    exit 1
  fi
  if lsof "$QDRANT_PATH/.lock" &>/dev/null 2>&1; then
    echo "ERROR: Qdrant DB가 다른 프로세스에 의해 사용 중입니다."
    echo "       KB 서비스를 먼저 중지하세요: $REPO_ROOT/scripts/stop.sh"
    exit 1
  fi
fi

# ── 시작 배너 ──

echo ""
echo "=== AEGIS KB ETL Pipeline ==="
echo "  소스:   CWE + ATT&CK (ICS+Enterprise) + CAPEC"
echo "  Qdrant: $QDRANT_PATH"
if [ "$SEED" = true ]; then
  echo "  Neo4j:  ledger-derived projection seed 포함 (--seed)"
  LEDGER_DISPLAY_URL="$(redact_url_userinfo "$LEDGER_URL")"
  echo "  Ledger: $LEDGER_DISPLAY_URL"
fi
[ "$FRESH" = true ] && echo "  모드:   캐시 초기화 (--fresh)"
echo ""

ETL_START=$SECONDS

# ── Fresh 모드: 다운로드 캐시 삭제 ──

if [ "$FRESH" = true ] && [ -d "$RAW_CACHE" ]; then
  echo "  캐시 삭제: $RAW_CACHE"
  rm -rf "$RAW_CACHE"
  echo ""
fi

# ── Phase 1~5: ETL 실행 ──

.venv/bin/python scripts/threat-db/build.py \
  --qdrant-path "$QDRANT_PATH" \
  "${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}"

# ── Neo4j 시드 (--seed 옵션) ──

if [ "$SEED" = true ]; then
  echo ""
  echo "=== Neo4j Seed ==="

  NEO4J_HOME="${NEO4J_HOME:-$HOME/neo4j-community-5.26.3}"
  if [ ! -x "$NEO4J_HOME/bin/neo4j" ]; then
    echo "ERROR: Neo4j 미설치 ($NEO4J_HOME)"
    exit 1
  fi

  STATUS=$("$NEO4J_HOME/bin/neo4j" status 2>&1 || true)
  if echo "$STATUS" | grep -q "not running"; then
    echo "  Neo4j 기동 중..."
    "$NEO4J_HOME/bin/neo4j" start
    for i in $(seq 1 15); do
      if bash -c "echo > /dev/tcp/localhost/7687" 2>/dev/null; then
        echo "  Neo4j ready (${i}초)"
        break
      fi
      if [ "$i" -eq 15 ]; then
        echo "ERROR: Neo4j 기동 타임아웃 (15초)"
        exit 1
      fi
      sleep 1
    done
  fi

  .venv/bin/python scripts/neo4j-seed.py \
    --ledger-url "$LEDGER_URL" \
    --neo4j-uri "$NEO4J_URI" \
    --neo4j-user "$NEO4J_USER" \
    --neo4j-password "$NEO4J_PASSWORD" \
    --clear
  echo ""
  echo "=== Neo4j Seed 완료 ==="
fi

# ── 완료 ──

ETL_ELAPSED=$(( SECONDS - ETL_START ))
ETL_MIN=$(( ETL_ELAPSED / 60 ))
ETL_SEC=$(( ETL_ELAPSED % 60 ))

echo ""
echo "=== ETL 완료 (${ETL_MIN}분 ${ETL_SEC}초) ==="
echo "  다음 단계: $REPO_ROOT/scripts/start-knowledge-base.sh 로 KB 서비스 기동"
