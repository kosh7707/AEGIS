# Golden Set — Analysis Agent 품질 평가 정답지

## 개요

각 JSON 파일은 하나의 테스트 케이스로, 에이전트에게 주어지는 **입력**(SAST findings + 소스코드)과 **기대 결과**(반드시 찾아야 할 것, 거부해야 할 것)를 정의한다.

## 케이스 목록

### Unit-style golden cases

| ID | CWE | 유형 | 난이도 | 핵심 검증 |
|----|-----|------|--------|-----------|
| cwe78_getenv_system | CWE-78 | TP | basic | OS command injection |
| cwe120_gets_overflow | CWE-120 | mixed | basic | BOF 탐지 + 안전한 memcpy FP 거부 |
| cwe134_printf_format | CWE-134 | TP | moderate | format string (네트워크 입력) |
| cwe362_toctou_access | CWE-362 | TP | moderate | TOCTOU race condition |
| safe_snprintf_fp_reject | — | FP거부 | basic | snprintf+sizeof 안전 코드 |

### Full-pipeline / Quality Gate oracles

| 파일 | 용도 | 핵심 검증 |
|---|---|---|
| `hot11_full_pipeline_oracle.json` | hot11 Build→Analyze→Generate-PoC strict oracle | matched finding마다 clean PoC(`poc_accepted` + `qualityOutcome=accepted` + `cleanPass=true`) 필요 |
| `qg_anomaly_oracle.json` | completed-but-non-clean anomaly golden set | `completed`라도 `poc_inconclusive`, `accepted_with_caveats`, `no_accepted_claims`, dependency failure 등은 strict clean pass가 아님 |

## 케이스 추가 방법

1. `cases/` 디렉토리에 JSON 파일 생성
2. `input.sast_findings`에 SAST 결과를 pre-compute하여 포함 (S4 불필요)
3. `input.source_code`에 분석 대상 소스코드 인라인
4. `expected`에 must_find / must_reject / severity_range 정의
5. `python -m pytest tests/test_scorer.py -q`로 scorer 호환성 확인

## 유형

- **true_positive**: 실제 취약점. must_find에 기대 claim 정의.
- **false_positive_rejection**: 안전한 코드. must_reject에 SAST FP 정의. claim 0개 기대.
- **mixed**: TP + FP가 동시에 존재. must_find + must_reject 모두 정의.

## Strict clean 정책

HotN/hot11의 paper-quality verdict는 task completion만으로 통과하지 않는다.

```text
clean analysis = completed + analysisOutcome=accepted_claims + qualityOutcome=accepted
clean PoC      = completed + pocOutcome=poc_accepted + qualityOutcome=accepted + cleanPass=true
```

따라서 이전처럼 Generate-PoC가 `completed`이지만 `pocOutcome=poc_inconclusive`,
`qualityOutcome=rejected`, `cleanPass=false`인 결과는 oracle 실패로 집계한다.
