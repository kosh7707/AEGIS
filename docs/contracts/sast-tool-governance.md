# SAST 도구 포트폴리오 거버넌스

Decision: **keep-current-six-tools**

현재 도구 집합은 `semgrep`, `cppcheck`, `flawfinder`, `clang-tidy`, `scan-build`, `gcc-fanalyzer`다. 이 결정은 각 도구가 결정론적 로컬 증거를 제공하고 서로 다른 기여를 가진다는 현재 Golden Corpus 결과에 근거한다. 도구는 최종 보안 verdict를 내리지 않으며 외부 지식이나 네트워크를 요구하지 않는다.

## 변경 전 필수 gate

모든 gate가 증거로 통과해야 포트폴리오 변경을 검토한다.

1. Golden Corpus coverage
2. Evidence contract compatibility
3. Parser compatibility
4. Benchmark slice coverage
5. Unique contribution / overlap accounting
6. Runtime and stability budget
7. Consumer safety

기계 판정의 정본은 `services/sast-runner/benchmark/tool_portfolio_governance.py`이며 schema는 `s4-tool-portfolio-governance-v1`이다. parser 보고서는 현재 여섯 도구의 정규화 출력과 fixture 순서를 확인하고, benchmark 결과의 `consumerPolicy=benchmark_quality_evidence_not_runtime_verdict`는 품질 증거를 런타임 verdict로 승격하지 못하게 한다.

## 현재 결정의 범위

이번 결정은 does **not** add a new SAST tool. 또한 does **not** remove or upgrade any current tool. 추가·제거·품질 주장을 위한 업그레이드는 failing-before/passing-after corpus 사례, parser compatibility, benchmark slice, 고유 기여 및 runtime budget 증거가 먼저 필요하다.

각 도구의 역할과 한계는 governance report의 `tools[]` (`role`, `uniqueContribution`, `overlap`, `limitations`, `capabilityOracle`)에 기록한다. 결과에 `vulnerable`, `safe`, `affected`, `clean`, `riskScore`, `securityVerdict` 같은 최종 verdict 키를 추가하지 않는다.

관련 문서: [SAST Runner](sast-runner.md), [불변 규칙](../invariants.md).
