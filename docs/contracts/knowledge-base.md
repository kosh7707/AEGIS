# Knowledge Base 계약

S5는 보안 지식 검색, 코드 그래프, target context, judge와 프로젝트 메모리를 제공한다. 모든 세부 스키마는 `services/knowledge-base/app/routers/`와 관련 `app/contracts/`, 서비스 모델을 정본으로 삼는다.

## 활성 API 묶음

- 검색/상태: `POST /v1/search`, `POST /v1/search/batch`, `GET /v1/graph/stats`, `GET /v1/graph/neighbors/{node_id}`, `GET /v1/health`, `GET /v1/ready`
- 코드 그래프: `/v1/code-graph/{project_id}` 아래 `ingest`, `stats`, `callers`, `callees`, `dangerous-callers`, `search`, 삭제; `GET /v1/code-graph`
- CVE/판정: `POST /v1/cve/batch-lookup`, `POST /v1/judge/query`, `POST /v1/analyst-brief`
- target context: `POST /v1/target-contexts`와 `/{id}/acquire/{cve,cve-discovery,cve-candidate-evaluation,code-search,threat-search,dangerous-callers}`
- source KG: `POST /v1/source-code-kg/ingest`, `POST /v1/source-code-kg/context`
- 프로젝트 메모리: `GET|POST /v1/project-memory/{project_id}`, `DELETE /v1/project-memory/{project_id}/{memory_id}`
- 계약 조회: `GET /v1/contracts/{acquisition,source-code-kg,analyst-brief,judge,paper-context}`

`/v1/health`는 프로세스 생존, `/v1/ready`는 의존 데이터와 검색 준비 여부를 나타낸다. 운영 준비 판정에는 `ready`를 사용한다. 검색 결과 없음, graph node 없음, CVE 미매치는 취약점 부재가 아니라 해당 증거원에서 확인되지 않았다는 의미다. provenance, source coverage, uncertainty, fallback/reasoning trace를 소비자까지 보존한다.

## 실험적 paper context

`/v1/paper` 아래 `code-kb/prepare`, `finding-context/retrieve`, `source-kg/explore`, `threat-context/generic`은 증거 행과 coverage를 생성하는 내부 실험 API다. 스키마 버전과 요청/응답은 `app/routers/paper_context_api.py` 및 계약 조회 API가 정본이다. 이 표면은 별도 paper 저장소에 의존하지 않는다.

관련 문서: [공유 모델](shared-models.md), [Analysis Agent](analysis-agent.md), [제약](../limitations.md).
