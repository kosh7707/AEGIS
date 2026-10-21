# 설치·운영·복구 런북

이 문서는 새 Linux/WSL 환경에서 AEGIS를 clone해 개발·검증 환경을 복원하는 절차다. 명령은 저장소 루트에서 실행한다. 운영 비밀값이나 기존 `.env`는 저장소에 넣지 않는다.

## 1. 복원 기준 기록

백업이나 이전 전 다음 값을 별도 기록한다.

```bash
git rev-parse HEAD
git remote -v
node --version
npm --version
python3 --version
git status --short
```

코드와 문서의 기준은 같은 AEGIS 커밋이다. 외부 데이터는 커밋 해시와 함께 취득 위치, 생성 시각, 크기, SHA-256을 기록한다. 이 저장소 하나가 현재 코드와 문서의 복원 기준이다.

## 2. 도구와 버전

저장소에 마지막으로 문서화된 개발 조합은 Node.js 22.23.2, npm 12.0.2, Python 3.12.3이다. `package-lock.json`과 각 `requirements.txt`가 설치 입력이며, Python 전이 의존성 전체가 lock된 형태는 아니다.

| 도구 | 필요 범위 | 확인 |
|---|---|---|
| Git(심볼릭 링크 지원) | clone, S3 공용 런타임 | `git config --get core.symlinks`; `test -L services/analysis-agent/app/agent_runtime` |
| Node.js 22 / npm 12 계열 | TS 6개 서비스 | `node --version && npm --version` |
| Python 3.12 계열 + `venv` | Python 5개 서비스 | `python3 --version && python3 -m venv --help` |
| C/C++ 빌드 도구, `make`, Python | `better-sqlite3`, 대상 빌드 | `command -v g++ make python3` |
| `lsof`, `curl` | 통합 시작/상태 점검 | `command -v lsof curl` |
| SAST 도구 | 실제 Quick의 전체 도구 증적 | `command -v cppcheck flawfinder clang-tidy scan-build gcc` |
| Docker | S8만 | `docker version` |
| QEMU user-mode, `gdb-multiarch` | 크로스 타깃·동적 실험만 | 설치한 타깃용 `qemu-* --version` |
| Neo4j 5.x | S5 그래프 기능 | `neo4j version` |
| `sqlite3`, GNU tar, `zstd`, `sha256sum` | 데이터 백업·복구만 | `command -v sqlite3 tar zstd sha256sum` |

Semgrep은 S4 Python requirements에 고정되어 설치된다. 다른 SAST 실행 파일이 없으면 S4가 일부 요청을 거부하거나 결과를 degraded/partial로 표시할 수 있다.

## 3. clone과 의존성 설치

심볼릭 링크가 유지되는 Linux 파일시스템에 clone한다. Windows Git을 거친 checkout이면 clone 전에 해당 환경에서 `core.symlinks=true`를 설정하고 두 `agent_runtime` 경로가 링크인지 확인한다.

```bash
git clone https://github.com/kosh7707/AEGIS.git AEGIS
cd AEGIS

npm ci
for service in adapter ecu-simulator container-gateway; do
  (cd "services/$service" && npm ci)
done

for service in analysis-agent build-agent knowledge-base llm-gateway sast-runner; do
  (
    cd "services/$service"
    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/pip install -r requirements.txt
  )
done

test -L services/analysis-agent/app/agent_runtime
test -L services/build-agent/app/agent_runtime
```

`npm ci`가 네이티브 모듈 빌드에서 실패하면 C/C++ 툴체인과 루트 `package.json`의 `allowScripts` 적용 여부를 먼저 확인한다. 임의로 `package-lock.json`을 다시 생성하지 않는다.

## 4. 설정: mock과 real

### 로컬 mock 기준

S7 기본값은 `mock`이다. 비밀 파일을 만들 필요 없이 현재 셸에 명시해 단독 실행할 수 있다.

```bash
test ! -e services/llm-gateway/.env && (
  cd services/llm-gateway
  env AEGIS_LLM_MODE=mock AEGIS_LLM_API_KEY= \
    .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
)
```

전체 기동도 LLM 설정이 없다면 mock 모드로 시작한다. mock 응답은 연결과 계약 개발용이며 실제 Deep 품질의 증거가 아니다.

### 실제 LLM 엔진

엔진 주소와 모델명은 배포 환경에서 주입한다. 아래 값은 자리표시자이며 실제 호스트나 키를 문서·Git·셸 기록에 남기지 않는다.

```bash
test ! -e services/llm-gateway/.env && (
  cd services/llm-gateway
  env \
    AEGIS_LLM_MODE=real \
    AEGIS_LLM_ENDPOINT=http://LLM_ENGINE_HOST:PORT \
    AEGIS_LLM_MODEL=MODEL_ID \
    .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
)
```

API 키가 필요한 환경은 권한이 제한된 서비스 설정이나 비밀 관리자를 통해 `AEGIS_LLM_API_KEY`를 주입한다. 실제 모드 판정은 포트 개방이 아니라 S7 `/v1/health`의 `llmMode`, `ready`, `llmReady`와 실제 요청 결과로 확인한다.

### S5 외부 저장소

S5는 로컬 Qdrant 경로를 기본으로 사용하고, Neo4j가 없으면 그래프 기능을 비활성화한 채 기동할 수 있다. 현재 시작 스크립트는 `NEO4J_HOME` 또는 사용자 홈 아래 특정 기본 경로를 찾으므로, 다른 설치 위치에서는 명시한다.

```bash
NEO4J_HOME=/opt/neo4j-community ./scripts/start-knowledge-base.sh
```

실제 비밀번호와 원격 Qdrant 자격 증명은 `AEGIS_KB_*` 환경변수로 비밀 관리 경로에서 주입한다.

## 5. 기동과 상태 확인

전체 기본 기동은 9개 프로세스를 시작한다. S8은 포함하지 않는다.

```bash
./scripts/start.sh
# 선택 예시
./scripts/start.sh --no-ecu --scenario=mixed --speed=1
```

`start.sh`는 포트 LISTEN 또는 ECU 프로세스 생존을 확인한다. 이는 애플리케이션과 외부 의존성이 실제 작업을 수행할 준비가 되었다는 판정이 아니다. 다음 단계로 상태를 확인한다.

```bash
curl -fsS http://localhost:3000/health
curl -fsS http://localhost:8000/v1/health
curl -fsS http://localhost:8001/v1/health
curl -fsS http://localhost:8002/v1/health
curl -fsS http://localhost:8003/v1/health
curl -fsS http://localhost:9000/v1/health
```

Frontend는 `http://localhost:5173`, 로그는 `scripts/.logs/`에서 확인한다. 요청별 장기 작업은 해당 서비스가 지원하는 경우 `/v1/health?requestId=...` 또는 Backend 상태 API로 추적한다.

S8은 Docker 이미지와 데몬을 준비한 뒤 별도로 시작한다.

```bash
docker build -t aegis-s8-qemu-compile:latest \
  -f services/container-gateway/docker/container-toolchain.Dockerfile .
./scripts/start-container-gateway.sh
curl -fsS http://localhost:4010/health
```

종료:

```bash
./scripts/stop.sh
```

`stop.sh`는 PID 파일이 없으면 알려진 포트의 프로세스를 찾아 종료하므로, 같은 포트를 다른 프로그램이 쓰는 환경에서는 먼저 점유 프로세스를 확인한다. S8은 이 스크립트의 종료 목록에 없으므로 S8을 실행한 터미널이나 별도 프로세스 관리자에서 종료한다.

## 6. 검증 프로필

### 정적·단위 회귀

```bash
npm test
# 또는 선택 실행
./scripts/test-all.sh backend analysis-agent sast-runner
```

`scripts/test-all.sh`는 TS 타입 검사와 서비스 테스트를 병렬 실행한다. 의존성이 없는 스위트는 `SKIP`, 실행된 스위트가 하나도 없으면 실패다. 복원 판정에는 PASS/FAIL뿐 아니라 SKIP 목록과 이유를 함께 남긴다.

허용 가능한 조건부 skip은 외부 데이터셋·Docker/QEMU·실제 LLM·선택적 paper manifest처럼 선택 자산이 명시적으로 없는 테스트뿐이다. 핵심 단위 테스트의 의존성 미설치, 로컬 문서 부재, 예상하지 못한 도구 부재를 정상 복원으로 간주하지 않는다. 병렬 실행에서 포트/부하 민감 스위트만 실패하면 해당 서비스 단독으로 재실행하고 두 결과를 모두 기록한다.

### 단계별 복원 확인

1. **개발 기준:** 설치 후 대상 서비스의 타입 검사·단위 테스트가 실행되고 통과한다.
2. **통신 기준:** Backend와 하위 서비스 health가 응답하며, unreachable/degraded 원인이 설명된다.
3. **Quick 기준:** 작은 C/C++ fixture에서 빌드 준비가 `compile_commands.json`을 만들고, 요구된 SAST 도구 상태·증적과 Quick 결과가 저장된다.
4. **Deep mock 기준:** mock 모드임이 응답에 드러나고 계약·상태 전이가 끝난다.
5. **Deep real 기준:** S7이 `real`과 LLM 준비 상태를 보고하고, 실제 요청이 모델·request ID·증적을 보존한 결과로 끝난다.
6. **동적/S8 기준:** 해당 기능을 보존해야 할 때만 실제 Adapter/ECU 또는 Docker fixture로 별도 검증한다.

## 7. 데이터 백업과 복구

Git이 보존하지 않는 핵심 상태는 다음과 같다.

- `uploads/`: 업로드 원본, 추출 소스, 빌드 대상과 생성 증적
- Backend SQLite DB 및 WAL/SHM 파일
- `services/knowledge-base/data/`: S5 ledger, 로컬 Qdrant, 캐시와 적재 상태
- 서비스별 `.env`: 비밀 저장소에서 별도 복구하며 Git 아카이브에 포함하지 않는다.
- 외부 LLM 모델, Neo4j 데이터, QEMU/SDK/toolchain 이미지와 원본 데이터셋

일관된 SQLite 백업에는 실행 중 파일 복사보다 SQLite backup 명령을 사용한다. 서비스가 중지된 상태라면 데이터 디렉터리를 권한과 심볼릭 링크를 보존하는 아카이브 도구로 백업한다. 각 아카이브에 SHA-256 목록을 함께 둔다. 아래는 목적지 파일시스템에 충분한 공간이 있고 기본 DB 경로를 사용하는 경우의 예다. **`stop.sh`는 알려진 포트의 다른 프로세스도 종료할 수 있으므로 아래 예는 AEGIS 전용 환경에서만 실행한다.** 공유 환경에서는 먼저 `lsof`와 PID를 확인하고 해당 AEGIS 프로세스만 중지한다.

```bash
archive_dir=/mnt/aegis-archive/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$archive_dir"
./scripts/stop.sh

git rev-parse HEAD > "$archive_dir/git-commit.txt"
sqlite3 services/backend/aegis.db ".backup '$archive_dir/aegis.db'"
tar --create --zstd --file "$archive_dir/runtime-data.tar.zst" \
  uploads services/knowledge-base/data
(
  cd "$archive_dir"
  sha256sum aegis.db runtime-data.tar.zst git-commit.txt > SHA256SUMS
)
```

실제 `DB_PATH`, S5 원격 Qdrant/Neo4j, 외부 SDK·모델·이미지가 다르면 위 예에 자동 포함되지 않는다. 각 외부 자산에는 제품/버전, 원본 위치, 라이선스, image digest 또는 체크섬, 복구 명령을 별도 manifest로 기록한다. 비밀값 자체는 manifest에 넣지 않는다.

복구 순서는 코드 checkout → 의존성 → 비밀 설정 → 외부 도구/이미지 → DB·uploads·S5 데이터 → health → Quick/Deep 검증이다. 복구 전에 기존 경로 위에 덮어쓰지 말고 빈 작업 위치에서 체크섬과 구조를 확인한다. DB와 `uploads`가 서로 다른 시점이면 프로젝트 메타데이터가 실제 경로를 가리키지 않을 수 있으므로 같은 중지 시점의 쌍으로 보존한다.

```bash
archive_dir=/mnt/aegis-archive/ARCHIVE_ID
(cd "$archive_dir" && sha256sum --check SHA256SUMS)
tar --list --zstd --file "$archive_dir/runtime-data.tar.zst" | less
# 새 checkout에서 충돌 대상이 없음을 확인한 뒤에만 실행한다.
tar --extract --zstd --file "$archive_dir/runtime-data.tar.zst"
cp --preserve=mode,timestamps "$archive_dir/aegis.db" services/backend/aegis.db
```

생성 로그(`logs/`, `scripts/.logs/`), PID, 캐시, `node_modules`, `.venv`는 재생성 가능하다. 장애 조사에 필요한 로그는 코드·데이터 백업과 분리해 보존 기간과 민감정보 정책을 적용한다.

## 8. 장애 시작점

- 기동 직후 종료: `scripts/.logs/<service>.log`
- 전체 상태: `GET /health`
- LLM mock/real 혼동: S7 `GET /v1/health`
- SDK 등록·추출 실패: [`troubleshooting/sdk.md`](troubleshooting/sdk.md)
- 계약과 상태 의미: [`invariants.md`](invariants.md), [`contracts/`](contracts/)

주요 구현 근거: `package.json`, `package-lock.json`, `scripts/start*.sh`, `scripts/stop.sh`, `scripts/test-all.sh`, 각 Python 서비스의 `requirements.txt`, `.gitignore`.
