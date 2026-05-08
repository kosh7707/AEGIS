from __future__ import annotations

import importlib.util
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = REPO_ROOT / "services/analysis-agent/scripts/hot11_full_pipeline_runner.py"
MANIFEST_PATH = REPO_ROOT / "uploads/build-agent-stabilization-datasets/manifest.json"
ORACLE_PATH = REPO_ROOT / "services/analysis-agent/eval/golden/hot11_full_pipeline_oracle.json"


def load_runner():
    spec = importlib.util.spec_from_file_location("hot11_full_pipeline_runner_under_test", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_oracle_covers_manifest_hot11_cases_exactly():
    manifest = json.loads(MANIFEST_PATH.read_text())
    oracle = json.loads(ORACLE_PATH.read_text())
    manifest_cases = {case["caseId"] for case in manifest["cases"]}
    oracle_cases = {case["caseId"] for case in oracle["cases"]}

    assert len(manifest_cases) == 11
    assert oracle_cases == manifest_cases
    assert oracle["policy"]["passRequiresAllExpectedFindings"] is True


def test_oracle_contains_no_local_network_credentials():
    text = ORACLE_PATH.read_text()
    # Keep these assembled so the repository diff itself does not contain the
    # local credential/path markers that this guard is meant to prevent.
    forbidden_fragments = [
        "Gold" + "medal" + "77",
        "auth" + ".txt",
        "client" + ".key",
        "se" + "hwa",
    ]
    assert not any(fragment in text for fragment in forbidden_fragments)


def test_dry_run_stages_oracle_artifacts(tmp_path):
    runner = load_runner()
    args = runner.parse_args([
        "--limit",
        "1",
        "--output-dir",
        str(tmp_path),
        "--run-label",
        "pytest-hot11-dryrun",
    ])

    aggregate = runner.run(args)

    assert aggregate["overallStatus"] == "staged"
    assert aggregate["oracle"]["enabled"] is True
    case = aggregate["cases"][0]
    assert case["caseId"] == "certificate-maker"
    assert case["oracleEnabled"] is True
    assert case["oracleExpectedFindingCount"] == 1
    assert (tmp_path / "certificate-maker/oracle-case.json").is_file()


def test_oracle_evaluation_passes_gateway_webserver_claim_with_poc():
    runner = load_runner()
    oracle = runner.load_oracle(ORACLE_PATH)
    oracle_case = runner._oracle_case(oracle, "gateway-webserver")
    analysis_response = {
        "status": "completed",
        "result": {
            "claims": [
                {
                    "title": "CWE-78 command injection through curl popen",
                    "location": "src/clients/http_client.cpp:62",
                    "summary": "run_curl builds a curl shell command and executes it via popen, enabling RCE/command injection.",
                    "cwe": "CWE-78",
                    "severity": "critical",
                }
            ]
        },
    }
    poc_summaries = [
        {
            "status": "completed",
            "oracleFindingIds": ["gateway-webserver-curl-popen-command-injection"],
            "responseSummary": {"result": {"description": "diagnostic curl/popen command injection PoC"}},
        }
    ]

    verdict = runner.evaluate_oracle(oracle_case, analysis_response, poc_summaries)

    assert verdict["enabled"] is True
    assert verdict["passed"] is True
    assert verdict["matchedFindings"][0]["id"] == "gateway-webserver-curl-popen-command-injection"


def test_oracle_evaluation_fails_when_required_finding_missing():
    runner = load_runner()
    oracle = runner.load_oracle(ORACLE_PATH)
    oracle_case = runner._oracle_case(oracle, "gateway-webserver")
    analysis_response = {
        "status": "completed",
        "result": {"claims": [{"title": "generic style issue", "location": "README.md:1"}]},
    }

    verdict = runner.evaluate_oracle(oracle_case, analysis_response, [])

    assert verdict["enabled"] is True
    assert verdict["passed"] is False
    assert verdict["missingFindings"][0]["id"] == "gateway-webserver-curl-popen-command-injection"
