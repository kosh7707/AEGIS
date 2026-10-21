# LLM Gateway (S7)

자동차 전장부품 사이버보안 검증 프레임워크의 LLM 연동 게이트웨이 서비스.

## 역할

Core Service(S2)로부터 Task 기반 분석 요청을 받아 프롬프트를 조립하고,
LLM(또는 Mock)에 전달하여 구조화된 Assessment를 반환한다.

## 실행

```bash
cd services/llm-gateway
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## 환경변수

`services/llm-gateway/.env` 파일에서 자동 로드된다.

| 변수 | 기본값 | 설명 |
|------|--------|------|
| AEGIS_LLM_MODE | mock | `mock` / `real` |
| AEGIS_LLM_ENDPOINT | (`.env.example` 참조) | LLM Engine 엔드포인트 (vLLM) |
| AEGIS_LLM_MODEL | Qwen/Qwen3.6-27B | 사용할 모델명 (S7 품질 우선 기본값) |
| AEGIS_LLM_API_KEY | (빈 문자열) | API 키 (vLLM: 불필요) |

## API

- `POST /v1/tasks` — Task 기반 AI 분석 요청
- `GET /v1/health` — 서비스 상태 확인
- `GET /v1/models` — 등록된 model profile 목록
- `GET /v1/prompts` — 등록된 prompt template 목록

상세 API 계약은 [`../../docs/contracts/llm-gateway.md`](../../docs/contracts/llm-gateway.md), 설치와 실행 절차는 [`../../docs/runbook.md`](../../docs/runbook.md)를 참고한다.

## 내부 구조

```
app/
├── main.py                 # FastAPI 앱 진입점
├── config.py               # 설정 (.env → Settings)
├── context.py              # 요청 컨텍스트 (requestId)
├── errors.py               # GatewayError 계층
├── types.py                # TaskType, TaskStatus, FailureCode
├── clients/
│   ├── base.py             # LlmClient ABC
│   └── real.py             # RealLlmClient (OpenAI-compatible, vLLM 대상)
├── schemas/
│   ├── request.py          # TaskRequest, EvidenceRef, Context, Constraints
│   └── response.py         # TaskSuccessResponse, AssessmentResult, AuditInfo 등
├── registry/
│   ├── prompt_registry.py  # PromptEntry + PromptRegistry
│   └── model_registry.py   # ModelProfile + ModelProfileRegistry
├── validators/
│   ├── schema_validator.py # 출력 스키마 검증
│   └── evidence_validator.py # refId hallucination 감지
├── pipeline/
│   ├── prompt_builder.py   # 3계층 trust 분리 프롬프트 조립
│   ├── response_parser.py  # Assessment JSON 파싱
│   ├── confidence.py       # 신뢰도 산출 (4항목 가중합)
│   └── task_pipeline.py    # 오케스트레이터
├── mock/
│   └── dispatcher.py       # Mock Assessment 생성
└── routers/
    └── tasks.py            # API 엔드포인트
```
