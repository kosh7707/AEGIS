# AEGIS — Automotive Embedded Governance & Inspection System

자동차 임베디드 소프트웨어 보안 취약점 종합 검증 플랫폼.

## Documentation

- Canonical agent-facing wiki: sibling repo `aegis-static-wiki`
- Start at: `wiki/system/index.md` inside the `aegis-static-wiki` repo
- Local repo docs are intentionally reduced to:
  - `docs/AEGIS.md`
  - `docs/mcp.md`
- Use `wiki/system/migration-map.md` inside the `aegis-static-wiki` repo to resolve legacy `docs/**` references that still appear in comments or historical notes.

`aegis-static-wiki`는 이 레포와 **형제 디렉터리**로 clone해야 한다. 없으면 문서를 못 찾고,
`sast-runner`의 governance 스펙 테스트 1건이 skip된다.

```
<parent>/
├── AEGIS/              ← 이 레포
└── aegis-static-wiki/  ← 형제 레포
```

## Prerequisites

아래 버전은 **전 스위트 통과가 확인된 조합**이다. 더 낮은 버전은 검증된 적이 없다.

| 도구 | 검증된 버전 | 용도 |
|------|------|------|
| **Node.js** | 22.23.2 | Frontend, Backend, Adapter, ECU Simulator, Container Gateway |
| **npm** | 12.0.2 | `package.json`의 `allowScripts`는 npm 11+ 기능이다 |
| **Python** | 3.12.3 | Python 서비스 5개 |
| **C++ 툴체인** | `g++`, `make`, `python3` | `better-sqlite3` 네이티브 빌드 (backend) |
| **lsof** | — | 포트 헬스체크 (`start.sh` 내부) |
| **git** | 심링크 지원 필요 | `services/shared-py`를 심링크로 공유한다 (네이티브 Windows 체크아웃은 별도 설정 필요) |

## Setup

### 1. Node 의존성

락파일이 정본이므로 `npm install`이 아니라 **`npm ci`**를 쓴다.

```bash
# 루트 workspaces (services/shared, services/frontend, services/backend)
npm ci

# workspace 가 아닌 서비스는 각자 설치
for s in adapter ecu-simulator container-gateway; do
  (cd "services/$s" && npm ci)
done
```

`better-sqlite3`와 `esbuild`는 네이티브 빌드가 필요하다. npm 11+는 install script를
기본 차단하므로 루트 `package.json`의 `allowScripts`에 두 패키지가 버전 고정으로
승인돼 있다. 빌드가 건너뛰어지면 backend 테스트가 대량 실패한다.

### 2. Python 의존성 (5개 서비스 전부)

```bash
for s in analysis-agent build-agent knowledge-base llm-gateway sast-runner; do
  (cd "services/$s" && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)
done
```

모든 `requirements.txt`는 직접 의존성을 `==`로 고정해 두었다. 전이 의존성은 고정하지
않았으므로 완전한 lock은 아니다.

### 3. 검증

```bash
npm test     # = ./scripts/test-all.sh
```

11개 스위트(TS 6 + Python 5)를 병렬 실행한다. 의존성이 없는 서비스는 실패가 아니라
`SKIP`으로 보고하므로 부분 설치 상태에서도 결과를 신뢰할 수 있다. 단 **아무 스위트도
실행되지 않으면 통과로 보고하지 않고** exit 1 한다 — 설치가 안 된 상태가 green 으로
보이면 안 되기 때문이다.

특정 서비스만 돌리려면 인자로 넘긴다.

```bash
./scripts/test-all.sh backend analysis-agent
```

#### 알려진 부하 민감 테스트

`adapter`의 `qemu-real-adapter-smoke` 1건은 11개 스위트를 동시에 돌릴 때 간헐적으로
실패한다. 스모크 두 번째 케이스가 펌웨어를 의도적으로 종료시키는데, 부하가 걸리면
브릿지 정리가 응답 도착보다 먼저 끝나 `bridge exited with code 1`이 된다.
전체 실행 2회 중 1회, 단독 실행 3회는 전부 통과했다(약 1초). 전체 실행에서 이 스위트만
실패했다면 단독으로 다시 확인해라.

```bash
./scripts/test-all.sh adapter
```

#### 갓 clone한 상태에서 예상되는 skip

| 위치 | 이유 |
|------|------|
| `analysis-agent` 2건 | 스테이징 데이터셋이 `uploads/` 아래에 있고 이 디렉터리는 버전 관리 대상이 아니다 |
| `sast-runner` 1건 | 형제 `aegis-static-wiki` 체크아웃이 필요하다 |
| `sast-runner` 1건 | paper 요청 manifest는 문서화된 optional 경로에만 존재한다 |
| `frontend` 199개 파일 | 아직 `it.todo` placeholder다 |

## Run

```bash
./scripts/start.sh            # 전체 기동
./scripts/stop.sh             # 전체 종료
```

`start.sh`는 9개 프로세스를 띄운다: llm-gateway, sast-runner, knowledge-base,
build-agent, analysis-agent, adapter, backend, ecu-simulator, frontend.
**Container Gateway(S8)는 포함되지 않으므로** 필요하면 따로 띄운다.

```bash
./scripts/start-container-gateway.sh
```

### start.sh 옵션

| 옵션 | 설명 |
|------|------|
| `--no-ecu` | ECU Simulator 미기동 |
| `--no-frontend` | Frontend 미기동 |
| `--scenario=NAME` | ECU 시나리오 (기본: mixed) |
| `--speed=N` | ECU 트래픽 속도 (기본: 1) |

## 설정

무설정으로 기동된다. 모든 환경변수에 기본값이 있고 서비스 간 URL은 `localhost`를
가리킨다. LLM 엔진이 없으면 `llmMode: mock`으로 degrade한다.

```bash
curl http://localhost:8001/v1/health
# {"service":"s3-agent","status":"ok","llmMode":"mock", ...}
```

Backend만 조정 항목이 많아 템플릿이 있다.

```bash
cp services/backend/.env.example services/backend/.env
```

## 외부 의존성 (없어도 기동된다)

| 대상 | 필요한 곳 | 없을 때 |
|------|------|------|
| Neo4j, Qdrant | S5 Knowledge Base | 기동은 되고 해당 기능만 비활성 |
| vLLM 엔진 (DGX) | S7 LLM Gateway | `llmMode: mock` |
| QEMU | S6 통합 테스트 | 해당 테스트만 영향 |
| `aegis-static-wiki` | 문서, S4 governance 테스트 1건 | 해당 테스트 skip |

`services/build-agent/scripts/stage_hot11_datasets.py`는 레포 밖 데이터를 쓰므로
위치를 환경변수로 넘길 수 있다: `AEGIS_HOT11_SOURCE_ROOT`, `AEGIS_TI_SDK_ROOT`.

## Services (7인 체제, 9서비스)

| ID | 서비스 | 포트 | 스택 |
|----|--------|------|------|
| S1 | Frontend + QA | 5173 | Vite + React + TypeScript |
| S2 | AEGIS Core (Backend) | 3000 | Express 5 + TypeScript + SQLite |
| S3 | Analysis Agent | 8001 | Python + FastAPI |
| S3 | Build Agent (S3 겸임) | 8003 | Python + FastAPI |
| S4 | SAST Runner | 9000 | Python + FastAPI |
| S5 | Knowledge Base | 8002 | Python + FastAPI + Neo4j + Qdrant |
| S6 | Dynamic Analysis (Adapter + ECU Sim) | 4000 | TypeScript |
| S7 | LLM Gateway + Engine | 8000, DGX | Python + FastAPI + vLLM |
| S8 | Container Gateway | 4010 | Express 5 + TypeScript + Docker |

Python 서비스 헬스체크는 `/v1/health`다.

### 공유 코드

| 경로 | 사용처 |
|------|------|
| `services/shared` | TypeScript 타입/계약 — backend, frontend (npm workspace) |
| `services/shared-py/agent_runtime` | Python 에이전트 런타임 — analysis-agent, build-agent (심링크) |
