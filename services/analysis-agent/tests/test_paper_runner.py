from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "paper_runner.py"
spec = importlib.util.spec_from_file_location("paper_runner", SCRIPT)
paper_runner = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = paper_runner
spec.loader.exec_module(paper_runner)


class FakeResponse:
    def __init__(self, status_code: int, body):
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, *, json=None):
        self.calls.append(("POST", url, json))
        return self.responses.pop(0)

    def get(self, url):
        self.calls.append(("GET", url, None))
        return self.responses.pop(0)


def test_load_manifest_accepts_cases_object_and_array(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": [{"caseId": "case-1"}]}))
    assert paper_runner.load_manifest(manifest) == [{"caseId": "case-1"}]
    manifest.write_text(json.dumps([{"caseId": "case-2"}]))
    assert paper_runner.load_manifest(manifest) == [{"caseId": "case-2"}]


def test_run_cases_creates_starts_and_fetches_artifacts_sequentially():
    client = FakeClient(
        [
            FakeResponse(201, {"status": "CASE_REGISTERED"}),
            FakeResponse(200, {"status": "PAPER_EXPORT_READY"}),
            FakeResponse(200, {"files": ["case-export-manifest.json"]}),
        ]
    )
    result = paper_runner.run_cases([{"caseId": "case-1"}], client=client, base_url="http://s3.local/")
    assert result.ok is True
    assert result.summary["completedCount"] == 1
    assert [call[0] for call in client.calls] == ["POST", "POST", "GET"]
    assert client.calls[0][1] == "http://s3.local/v1/paper/analysis-cases"
    assert client.calls[1][1] == "http://s3.local/v1/paper/analysis-cases/case-1/start"
    assert client.calls[2][1] == "http://s3.local/v1/paper/analysis-cases/case-1/artifacts"


def test_run_cases_records_failure_and_continues_by_default():
    client = FakeClient(
        [
            FakeResponse(201, {"status": "CASE_REGISTERED"}),
            FakeResponse(500, {"error": "boom"}),
            FakeResponse(201, {"status": "CASE_REGISTERED"}),
            FakeResponse(200, {"status": "PAPER_EXPORT_READY"}),
            FakeResponse(200, {"files": []}),
        ]
    )
    result = paper_runner.run_cases([{"caseId": "bad"}, {"caseId": "good"}], client=client, base_url="http://s3.local")
    assert result.ok is False
    assert result.summary["completedCount"] == 1
    assert result.summary["failedCount"] == 1
    assert [call[1] for call in client.calls if call[0] == "POST"] == [
        "http://s3.local/v1/paper/analysis-cases",
        "http://s3.local/v1/paper/analysis-cases/bad/start",
        "http://s3.local/v1/paper/analysis-cases",
        "http://s3.local/v1/paper/analysis-cases/good/start",
    ]


def test_run_cases_fail_fast_stops_after_first_failure():
    client = FakeClient(
        [
            FakeResponse(201, {"status": "CASE_REGISTERED"}),
            FakeResponse(500, {"error": "boom"}),
            FakeResponse(201, {"status": "CASE_REGISTERED"}),
        ]
    )
    result = paper_runner.run_cases([{"caseId": "bad"}, {"caseId": "skipped"}], client=client, base_url="http://s3.local", fail_fast=True)
    assert result.ok is False
    assert result.summary["caseCount"] == 2
    assert len(result.summary["cases"]) == 1
    assert len(client.calls) == 2
