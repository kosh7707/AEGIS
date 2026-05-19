from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from benchmark.tool_portfolio_acquisition_manifest import (
    ACQUISITION_SCHEMA_VERSION,
    manifest_checksum,
    validate_acquisition_manifest,
)
from benchmark.tool_portfolio_corpus_readiness import build_corpus_readiness_gate
from benchmark.tool_portfolio_experiment_manifest import CORPUS_SCHEMA_VERSION, TRACKED_CWES, validate_corpus_manifest

CORPUS_ACQUISITION_BUNDLE_SCHEMA_VERSION = "s4-tool-portfolio-corpus-acquisition-bundle-v1"
DEFAULT_CORPUS_PROFILE = "c-cpp-tool-portfolio-v1"
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".omx" / "corpora" / "s4-tool-portfolio"
_CLI_INPUT_INVALID = "input validation failed"
_CLI_OUTPUT_FAILED = "corpus acquisition output failed"
_CLI_INPUT_INVALID_REASON = "CORPUS_ACQUISITION_CLI_INPUT_INVALID"
_CLI_OUTPUT_FAILED_REASON = "CORPUS_ACQUISITION_CLI_OUTPUT_FAILED"


@dataclass(frozen=True)
class CorpusSource:
    acquisition_id: str
    source_name: str
    source_url: str
    source_page_url: str
    source_version: str
    license_or_redistribution_note: str
    archive_sha256: str
    archive_name: str
    source_artifact: str

    @property
    def archive_checksum(self) -> str:
        return f"sha256:{self.archive_sha256}"


JULIET_SOURCE = CorpusSource(
    acquisition_id="juliet-c-cpp-1.3",
    source_name="Juliet C/C++",
    source_url="https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip",
    source_page_url="https://samate.nist.gov/SARD/test-suites/112",
    source_version="1.3",
    license_or_redistribution_note=(
        "NIST SAMATE/SARD Juliet C/C++ benchmark corpus; acquired for local offline scoring only; "
        "archives/extractions remain under ignored .omx corpus cache and are not committed."
    ),
    archive_sha256="ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb",
    archive_name="2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip",
    source_artifact="Juliet C/C++ 1.3",
)

SARD_VULNERABLE_SOURCE = CorpusSource(
    acquisition_id="sard-c-v2-vulnerable",
    source_name="SARD C Test Suite for Source Code Analyzer v2 - Vulnerable",
    source_url="https://samate.nist.gov/SARD/downloads/test-suites/2015-03-15-c-test-suite-for-source-code-analyzer-v2-vulnerable.zip",
    source_page_url="https://samate.nist.gov/SARD/test-suites/100",
    source_version="v2 vulnerable 2015-03-15",
    license_or_redistribution_note=(
        "NIST SAMATE/SARD C source-code-analyzer vulnerable suite; acquired for local offline scoring only; "
        "archives/extractions remain under ignored .omx corpus cache and are not committed."
    ),
    archive_sha256="423f20e8ead850bf64cd93cd4a73dc1161d7b5bb6036328e16fc32e27d09f0d1",
    archive_name="2015-03-15-c-test-suite-for-source-code-analyzer-v2-vulnerable.zip",
    source_artifact="SARD C source-code-analyzer v2 vulnerable",
)

SARD_SECURE_SOURCE = CorpusSource(
    acquisition_id="sard-c-v2-secure",
    source_name="SARD C Test Suite for Source Code Analyzer v2 - Secure",
    source_url="https://samate.nist.gov/SARD/downloads/test-suites/2015-03-15-c-test-suite-for-source-code-analyzer-secure-vv2.zip",
    source_page_url="https://samate.nist.gov/SARD/test-suites/101",
    source_version="v2 secure 2015-03-15",
    license_or_redistribution_note=(
        "NIST SAMATE/SARD C source-code-analyzer secure suite; acquired for local offline scoring only; "
        "archives/extractions remain under ignored .omx corpus cache and are not committed."
    ),
    archive_sha256="19b7059d067c093d078c6b34d1ec669ccd648aa5b8507ca3fb49d58324bb802b",
    archive_name="2015-03-15-c-test-suite-for-source-code-analyzer-secure-vv2.zip",
    source_artifact="SARD C source-code-analyzer v2 secure",
)

KNOWN_SOURCES: dict[str, CorpusSource] = {
    source.acquisition_id: source
    for source in [JULIET_SOURCE, SARD_VULNERABLE_SOURCE, SARD_SECURE_SOURCE]
}
DEFAULT_REQUIRED_CORPORA = [
    JULIET_SOURCE.acquisition_id,
    SARD_VULNERABLE_SOURCE.acquisition_id,
    SARD_SECURE_SOURCE.acquisition_id,
]

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)")
_FUNCTION_RE_TEMPLATE = r"\b{function}\s*\("


class _FixedDiagnosticArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise ValueError(_CLI_INPUT_INVALID)


def _parse_cli_sources(raw_corpora: Sequence[str] | None) -> list[CorpusSource]:
    selected_ids = list(raw_corpora or DEFAULT_REQUIRED_CORPORA)
    selected: list[CorpusSource] = []
    for corpus_id in selected_ids:
        if not isinstance(corpus_id, str) or not corpus_id or corpus_id != corpus_id.strip():
            raise ValueError(_CLI_INPUT_INVALID)
        source = KNOWN_SOURCES.get(corpus_id)
        if source is None:
            raise ValueError(_CLI_INPUT_INVALID)
        selected.append(source)
    return selected


def _emit_cli_error(*, error: str, reason_code: str, stage: str) -> None:
    try:
        sys.stderr.write(json.dumps({
            "error": error,
            "reasonCode": reason_code,
            "stage": stage,
        }, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, TypeError, ValueError, UnicodeError):
        return


def _write_cli_summary_output(bundle: Mapping[str, Any], path: Path) -> bool:
    try:
        _write_json(bundle, path)
    except (OSError, TypeError, ValueError, UnicodeError):
        return False
    return True


def _emit_cli_bundle_stdout(bundle: Mapping[str, Any]) -> bool:
    try:
        output = json.dumps(dict(bundle), indent=2, sort_keys=True, ensure_ascii=False)
        sys.stdout.write(output + "\n")
    except (OSError, TypeError, ValueError, UnicodeError):
        return False
    return True


def acquire_known_corpora(
    *,
    sources: Sequence[CorpusSource] | None = None,
    output_root: Path | str = DEFAULT_OUTPUT_ROOT,
    force: bool = False,
    corpus_manifest_name: str = "juliet-sard-focused-v1.json",
    readiness_output_name: str = "juliet-sard-focused-readiness-v1.json",
    downloaded_at: str | None = None,
) -> dict[str, Any]:
    """Download, verify, extract, manifest, and readiness-check the known S4 external corpora."""

    output_root = Path(output_root)
    selected_sources = list(sources or KNOWN_SOURCES.values())
    downloaded_at = downloaded_at or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    paths = _corpus_paths(output_root)
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)

    acquisition_manifests: list[dict[str, Any]] = []
    acquisition_reports: list[dict[str, Any]] = []
    for source in selected_sources:
        archive_path = _download_archive(source, paths["downloads"] / source.archive_name, force=force)
        extraction_root = paths["extracted"] / source.acquisition_id
        manifest_path = paths["acquisition_manifests"] / f"{source.acquisition_id}.json"
        _extract_archive(
            archive_path,
            extraction_root,
            source=source,
            manifest_path=manifest_path,
            force=force,
            allowed_delete_root=output_root,
        )
        manifest = _existing_or_new_acquisition_manifest(
            source,
            archive_path,
            extraction_root,
            manifest_path=manifest_path,
            downloaded_at=downloaded_at,
            force=force,
        )
        validate_acquisition_manifest(manifest)
        _write_json(manifest, manifest_path)
        acquisition_manifests.append(manifest)
        acquisition_reports.append({
            "acquisitionId": source.acquisition_id,
            "archivePath": str(archive_path),
            "extractionRoot": str(extraction_root),
            "manifestPath": str(manifest_path),
            "manifestChecksum": manifest_checksum(manifest),
        })

    corpus_manifest = build_focused_corpus_manifest(acquisition_manifests)
    validate_corpus_manifest(corpus_manifest, acquisition_index=_acquisition_index_for_validation(acquisition_manifests))
    corpus_manifest_path = paths["corpus_manifests"] / corpus_manifest_name
    _write_json(corpus_manifest, corpus_manifest_path)

    readiness_gate = build_corpus_readiness_gate(
        acquisition_manifests=acquisition_manifests,
        corpus_manifest=corpus_manifest,
        required_corpora=[source.acquisition_id for source in selected_sources],
    )
    readiness_path = paths["readiness"] / readiness_output_name
    _write_json(readiness_gate, readiness_path)

    bundle = {
        "schemaVersion": CORPUS_ACQUISITION_BUNDLE_SCHEMA_VERSION,
        "status": "available" if readiness_gate.get("status") == "available" else "blocked",
        "createdAt": downloaded_at,
        "outputRoot": str(output_root),
        "acquisitions": acquisition_reports,
        "corpusManifestPath": str(corpus_manifest_path),
        "readinessGatePath": str(readiness_path),
        "readinessGateStatus": readiness_gate.get("status"),
        "decisionGradeReady": readiness_gate.get("decisionGradeReady") is True,
        "requiredCorpora": [source.acquisition_id for source in selected_sources],
        "caseCount": len(corpus_manifest.get("cases", [])),
        "splitCounts": _count_cases_by_field(corpus_manifest.get("cases", []), "split"),
        "sliceCounts": _count_cases_by_field(corpus_manifest.get("cases", []), "sliceKind"),
        "consumerPolicy": "actual_downloaded_corpora_cached_locally_not_committed_to_repo",
    }
    _write_json(bundle, output_root / "bundle-summary.json")
    return bundle


def build_focused_corpus_manifest(acquisition_manifests: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    acquisition_by_id = {str(manifest.get("acquisitionId")): dict(manifest) for manifest in acquisition_manifests}
    cases: list[dict[str, Any]] = []

    if JULIET_SOURCE.acquisition_id in acquisition_by_id:
        cases.extend(_juliet_cases(acquisition_by_id[JULIET_SOURCE.acquisition_id]))
    if SARD_VULNERABLE_SOURCE.acquisition_id in acquisition_by_id:
        cases.extend(_sard_cases(acquisition_by_id[SARD_VULNERABLE_SOURCE.acquisition_id], polarity="positive"))
    if SARD_SECURE_SOURCE.acquisition_id in acquisition_by_id:
        cases.extend(_sard_cases(acquisition_by_id[SARD_SECURE_SOURCE.acquisition_id], polarity="negative"))

    return {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": DEFAULT_CORPUS_PROFILE,
        "createdAt": _corpus_manifest_created_at(acquisition_manifests),
        "owner": "s4-sast-runner",
        "trackedCwes": list(TRACKED_CWES),
        "cases": cases,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = _FixedDiagnosticArgumentParser(
        description="Acquire and pin the S4 Juliet/SARD tool-portfolio external corpora.",
    )
    parser.add_argument(
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="Corpus cache root. Defaults to AEGIS/.omx/corpora/s4-tool-portfolio.",
    )
    parser.add_argument(
        "--corpus",
        action="append",
        help="Known corpus acquisitionId to acquire. May be repeated. Defaults to Juliet + SARD vulnerable + SARD secure.",
    )
    parser.add_argument("--force", action="store_true", help="Re-extract archives and overwrite stale cached downloads.")
    parser.add_argument("--summary-output", default=None, help="Optional path to write bundle summary JSON.")

    try:
        args = parser.parse_args(argv)
        selected = _parse_cli_sources(args.corpus)
    except ValueError:
        _emit_cli_error(
            error=_CLI_INPUT_INVALID,
            reason_code=_CLI_INPUT_INVALID_REASON,
            stage="input",
        )
        return 1

    bundle = acquire_known_corpora(sources=selected, output_root=args.output_root, force=args.force)
    if args.summary_output:
        if not _write_cli_summary_output(bundle, Path(args.summary_output)):
            _emit_cli_error(
                error=_CLI_OUTPUT_FAILED,
                reason_code=_CLI_OUTPUT_FAILED_REASON,
                stage="output",
            )
            return 1
    if not _emit_cli_bundle_stdout(bundle):
        _emit_cli_error(
            error=_CLI_OUTPUT_FAILED,
            reason_code=_CLI_OUTPUT_FAILED_REASON,
            stage="output",
        )
        return 1
    return 0 if bundle.get("status") == "available" else 2


def _corpus_paths(output_root: Path) -> dict[str, Path]:
    return {
        "downloads": output_root / "downloads",
        "extracted": output_root / "extracted",
        "acquisition_manifests": output_root / "manifests" / "acquisitions",
        "corpus_manifests": output_root / "manifests" / "corpus",
        "readiness": output_root / "readiness",
    }


def _download_archive(source: CorpusSource, archive_path: Path, *, force: bool) -> Path:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    expected = source.archive_checksum
    if archive_path.exists() and not force:
        _require_checksum(archive_path, expected)
        return archive_path
    if archive_path.exists() and force:
        archive_path.unlink()

    request = urllib.request.Request(source.source_url, headers={"User-Agent": "AEGIS-S4-corpus-acquisition/1.0"})
    tmp_path = archive_path.with_suffix(archive_path.suffix + ".tmp")
    try:
        with urllib.request.urlopen(request, timeout=60) as response, tmp_path.open("wb") as output:
            shutil.copyfileobj(response, output)
        _require_checksum(tmp_path, expected)
        tmp_path.replace(archive_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
    return archive_path


def _extract_archive(
    archive_path: Path,
    extraction_root: Path,
    *,
    source: CorpusSource,
    manifest_path: Path,
    force: bool,
    allowed_delete_root: Path,
) -> Path:
    if extraction_root.exists():
        if not force and _existing_extraction_is_trusted(
            source,
            archive_path,
            extraction_root,
            manifest_path=manifest_path,
        ):
            return extraction_root
        _safe_rmtree(extraction_root, allowed_root=allowed_delete_root)
    extraction_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            target = _safe_zip_target(extraction_root, member.filename)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
    return extraction_root


def _existing_extraction_is_trusted(
    source: CorpusSource,
    archive_path: Path,
    extraction_root: Path,
    *,
    manifest_path: Path,
) -> bool:
    """Return true only when an existing extraction matches a prior pinned manifest.

    Existing corpus cache directories are deliberately treated as untrusted unless
    the previous acquisition manifest still validates against the current archive
    checksum and the recomputed extraction tree checksum. This prevents a
    tampered cache from being silently re-pinned into a fresh manifest.
    """

    if not manifest_path.exists():
        return False
    try:
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(existing, Mapping):
        return False
    try:
        validate_acquisition_manifest(existing)
    except ValueError:
        return False

    expected_fields = {
        "schemaVersion": ACQUISITION_SCHEMA_VERSION,
        "acquisitionId": source.acquisition_id,
        "sourceName": source.source_name,
        "sourceUrl": source.source_url,
        "sourceVersion": source.source_version,
        "expectedArchiveChecksum": source.archive_checksum,
        "archiveChecksum": _sha256_file(archive_path),
        "extractionRootChecksum": _sha256_tree(extraction_root),
        "offlineScoringOnly": True,
        "networkAccessRequiredForScoring": False,
    }
    if any(existing.get(field) != value for field, value in expected_fields.items()):
        return False
    try:
        return Path(str(existing["localPath"])).resolve() == extraction_root.resolve()
    except (KeyError, OSError, RuntimeError):
        return False


def _build_acquisition_manifest(source: CorpusSource, archive_path: Path, extraction_root: Path, *, downloaded_at: str) -> dict[str, Any]:
    return {
        "schemaVersion": ACQUISITION_SCHEMA_VERSION,
        "acquisitionId": source.acquisition_id,
        "sourceName": source.source_name,
        "sourceUrl": source.source_url,
        "sourcePageUrl": source.source_page_url,
        "sourceVersion": source.source_version,
        "licenseOrRedistributionNote": source.license_or_redistribution_note,
        "downloadedAt": downloaded_at,
        "archiveChecksum": _sha256_file(archive_path),
        "expectedArchiveChecksum": source.archive_checksum,
        "extractionRootChecksum": _sha256_tree(extraction_root),
        "localPath": str(extraction_root),
        "offlineScoringOnly": True,
        "networkAccessRequiredForScoring": False,
    }


def _existing_or_new_acquisition_manifest(
    source: CorpusSource,
    archive_path: Path,
    extraction_root: Path,
    *,
    manifest_path: Path,
    downloaded_at: str,
    force: bool,
) -> dict[str, Any]:
    candidate = _build_acquisition_manifest(source, archive_path, extraction_root, downloaded_at=downloaded_at)
    if force or not manifest_path.exists():
        return candidate
    existing = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(existing, Mapping):
        return candidate
    try:
        validate_acquisition_manifest(existing)
    except ValueError:
        return candidate
    stable_fields = [
        "schemaVersion",
        "acquisitionId",
        "sourceName",
        "sourceUrl",
        "sourcePageUrl",
        "sourceVersion",
        "licenseOrRedistributionNote",
        "archiveChecksum",
        "expectedArchiveChecksum",
        "extractionRootChecksum",
        "localPath",
        "offlineScoringOnly",
        "networkAccessRequiredForScoring",
    ]
    if all(existing.get(field) == candidate.get(field) for field in stable_fields):
        return dict(existing)
    byte_stable_fields = [
        "schemaVersion",
        "acquisitionId",
        "sourceName",
        "sourceUrl",
        "sourceVersion",
        "archiveChecksum",
        "expectedArchiveChecksum",
        "extractionRootChecksum",
        "localPath",
        "offlineScoringOnly",
        "networkAccessRequiredForScoring",
    ]
    if all(existing.get(field) == candidate.get(field) for field in byte_stable_fields):
        candidate["downloadedAt"] = existing["downloadedAt"]
    return candidate


def _juliet_cases(acquisition: Mapping[str, Any]) -> list[dict[str, Any]]:
    root = Path(str(acquisition["localPath"]))
    checksum = manifest_checksum(acquisition)
    cases: list[dict[str, Any]] = []
    for cwe_id in TRACKED_CWES:
        cwe_num = cwe_id.split("-", 1)[1]
        validation_path = _select_juliet_file(root, cwe_num, preferred_suffix="_01.c")
        test_path = _select_juliet_file(root, cwe_num, preferred_suffix="_02.c", exclude={validation_path})
        for split, source_file in [("validation", validation_path), ("test", test_path)]:
            relative_path = _relative_posix(source_file, root)
            line_text = source_file.read_text(encoding="utf-8", errors="replace")
            bad_region = _function_region(line_text, "bad")
            good_region = _function_region(line_text, "good")
            sink_line = _target_line(line_text, bad_region)
            good_line = _target_line(line_text, good_region)
            case_stem = _safe_case_stem(source_file.stem)
            lineage_id = f"juliet-{cwe_id.lower()}-{split}-{case_stem}"
            cases.append(_case_record(
                case_id=f"{lineage_id}-positive",
                lineage_id=lineage_id,
                slice_kind="juliet-controlled-positive",
                split=split,
                source_artifact=JULIET_SOURCE.source_artifact,
                acquisition=acquisition,
                acquisition_manifest_checksum=checksum,
                source_path=relative_path,
                cwe_id=cwe_id,
                polarity="positive",
                target_line=sink_line,
                function_region=bad_region,
                target_function="bad",
                notes=["Generated from downloaded Juliet C/C++ corpus; positive bad-region oracle target."],
            ))
            cases.append(_case_record(
                case_id=f"{lineage_id}-negative",
                lineage_id=lineage_id,
                slice_kind="juliet-controlled-negative",
                split=split,
                source_artifact=JULIET_SOURCE.source_artifact,
                acquisition=acquisition,
                acquisition_manifest_checksum=checksum,
                source_path=relative_path,
                cwe_id=cwe_id,
                polarity="negative",
                target_line=good_line,
                function_region=good_region,
                target_function="good",
                notes=["Generated from downloaded Juliet C/C++ corpus; negative good-region oracle target."],
            ))
    return cases


def _select_juliet_file(root: Path, cwe_num: str, *, preferred_suffix: str, exclude: set[Path] | None = None) -> Path:
    exclude = exclude or set()
    prefix = f"CWE{cwe_num}_"
    candidates = sorted(
        path for path in (root / "C" / "testcases").rglob("*.c")
        if path.parent.name != "testcasesupport"
        and any(part.startswith(prefix) for part in path.parts)
        and path.name.endswith(preferred_suffix)
        and path not in exclude
    )
    if not candidates:
        candidates = sorted(
            path for path in (root / "C" / "testcases").rglob("*.c")
            if any(part.startswith(prefix) for part in path.parts) and path not in exclude
        )
    if not candidates:
        raise FileNotFoundError("No Juliet file found")
    return candidates[0]


def _sard_cases(acquisition: Mapping[str, Any], *, polarity: str) -> list[dict[str, Any]]:
    root = Path(str(acquisition["localPath"]))
    checksum = manifest_checksum(acquisition)
    candidates_by_cwe: dict[str, list[tuple[Path, dict[str, Any]]]] = {cwe: [] for cwe in TRACKED_CWES}
    for manifest_path in sorted(root.rglob("manifest.sarif")):
        sarif = json.loads(manifest_path.read_text(encoding="utf-8"))
        cwe_id = _sard_cwe_id(sarif)
        if cwe_id in candidates_by_cwe:
            candidates_by_cwe[cwe_id].append((manifest_path, sarif))

    cases: list[dict[str, Any]] = []
    for cwe_id, candidates in candidates_by_cwe.items():
        if not candidates:
            continue
        selected = _split_selected_sard_candidates(candidates)
        for split, (manifest_path, sarif) in selected.items():
            source_uri, start_line = _sard_artifact_and_line(sarif)
            source_file = manifest_path.parent / source_uri
            if not source_file.exists():
                continue
            relative_path = _relative_posix(source_file, root)
            line_text = source_file.read_text(encoding="utf-8", errors="replace")
            region = _line_region(line_text, start_line)
            case_dir = manifest_path.parent.name
            case_id = f"sard-{cwe_id.lower()}-{split}-{case_dir}-{polarity}"
            cases.append(_case_record(
                case_id=case_id,
                lineage_id=f"sard-{cwe_id.lower()}-{split}-{case_dir}",
                slice_kind="sard-focused",
                split=split,
                source_artifact=str(acquisition.get("sourceName") or "SARD C v2"),
                acquisition=acquisition,
                acquisition_manifest_checksum=checksum,
                source_path=relative_path,
                cwe_id=cwe_id,
                polarity=polarity,
                target_line=start_line,
                function_region=region,
                target_function=region["function"],
                notes=["Generated from downloaded NIST SARD manifest.sarif evidence."],
            ))
    return cases


def _split_selected_sard_candidates(candidates: Sequence[tuple[Path, dict[str, Any]]]) -> dict[str, tuple[Path, dict[str, Any]]]:
    if len(candidates) == 1:
        return {"validation": candidates[0]}
    return {"validation": candidates[0], "test": candidates[1]}


def _case_record(
    *,
    case_id: str,
    lineage_id: str,
    slice_kind: str,
    split: str,
    source_artifact: str,
    acquisition: Mapping[str, Any],
    acquisition_manifest_checksum: str,
    source_path: str,
    cwe_id: str,
    polarity: str,
    target_line: int,
    function_region: Mapping[str, Any],
    target_function: str,
    notes: Sequence[str],
) -> dict[str, Any]:
    target_id = f"{case_id}-target"
    expected: dict[str, Any] = {
        "targetId": target_id,
        "granularity": "sink-line" if polarity == "positive" else "negative-region",
        "cweId": cwe_id,
        "polarity": polarity,
        "locations": [{"file": source_path, "line": target_line, "role": "sink"}],
        "functionRegion": dict(function_region),
        "allowedMatchWindows": {"lineDelta": 5, "functionFallback": False},
    }
    if polarity == "negative":
        expected["allowedWarningPolicy"] = {"mode": "no-findings-in-region", "allowedRuleIds": []}
    local_root = Path(str(acquisition["localPath"]))
    return {
        "caseId": case_id,
        "targetId": target_id,
        "lineageId": lineage_id,
        "sliceKind": slice_kind,
        "split": split,
        "language": "c",
        "sourceArtifact": source_artifact,
        "acquisitionId": str(acquisition["acquisitionId"]),
        "acquisitionManifestChecksum": acquisition_manifest_checksum,
        "sourceRef": f"{acquisition['acquisitionId']}:{source_path}",
        "sourcePath": source_path,
        "checksum": _sha256_file(local_root / source_path),
        "expected": expected,
        "buildContext": {"requiresCompileCommands": False, "compileCommandsFixture": None, "defines": [], "includePaths": []},
        "notes": list(notes) + [f"targetFunction={target_function}"],
    }


def _sard_cwe_id(sarif: Mapping[str, Any]) -> str | None:
    for run in sarif.get("runs", []) if isinstance(sarif.get("runs"), list) else []:
        if not isinstance(run, Mapping):
            continue
        for result in run.get("results", []) if isinstance(run.get("results"), list) else []:
            if not isinstance(result, Mapping):
                continue
            for taxa in result.get("taxa", []) if isinstance(result.get("taxa"), list) else []:
                if isinstance(taxa, Mapping) and str(taxa.get("id") or "").isdigit():
                    return f"CWE-{taxa['id']}"
            rule_id = str(result.get("ruleId") or "")
            match = _CWE_RE.search(rule_id)
            if match:
                return f"CWE-{match.group(1)}"
        for taxonomy in run.get("taxonomies", []) if isinstance(run.get("taxonomies"), list) else []:
            if not isinstance(taxonomy, Mapping):
                continue
            for taxa in taxonomy.get("taxa", []) if isinstance(taxonomy.get("taxa"), list) else []:
                if isinstance(taxa, Mapping) and str(taxa.get("id") or "").isdigit():
                    return f"CWE-{taxa['id']}"
    return None


def _sard_artifact_and_line(sarif: Mapping[str, Any]) -> tuple[str, int]:
    fallback_uri = ""
    for run in sarif.get("runs", []) if isinstance(sarif.get("runs"), list) else []:
        if not isinstance(run, Mapping):
            continue
        artifacts = run.get("artifacts", [])
        if isinstance(artifacts, list) and artifacts:
            first_artifact = artifacts[0]
            if isinstance(first_artifact, Mapping):
                fallback_uri = str(first_artifact.get("location", {}).get("uri") or "")
        for result in run.get("results", []) if isinstance(run.get("results"), list) else []:
            if not isinstance(result, Mapping):
                continue
            for location in result.get("locations", []) if isinstance(result.get("locations"), list) else []:
                physical = location.get("physicalLocation") if isinstance(location, Mapping) else None
                if not isinstance(physical, Mapping):
                    continue
                artifact_uri = str(physical.get("artifactLocation", {}).get("uri") or fallback_uri)
                region = physical.get("region") if isinstance(physical.get("region"), Mapping) else {}
                line = int(region.get("startLine") or 1)
                return artifact_uri, line
    if not fallback_uri:
        raise ValueError("SARD SARIF did not contain an artifact URI")
    return fallback_uri, 1


def _function_region(text: str, function: str) -> dict[str, Any]:
    lines = text.splitlines()
    pattern = re.compile(_FUNCTION_RE_TEMPLATE.format(function=re.escape(function)))
    for index, line in enumerate(lines, start=1):
        if pattern.search(line):
            return {"function": function, "startLine": index, "endLine": _function_end_line(lines, index)}
    return {"function": function, "startLine": 1, "endLine": min(len(lines), 1)}


def _line_region(text: str, line: int) -> dict[str, Any]:
    lines = text.splitlines()
    bounded = max(1, min(line, max(1, len(lines))))
    return {"function": "sarif-region", "startLine": bounded, "endLine": bounded}


def _function_end_line(lines: Sequence[str], start_line: int) -> int:
    depth = 0
    saw_open = False
    for index in range(start_line, len(lines) + 1):
        line = lines[index - 1]
        depth += line.count("{")
        if "{" in line:
            saw_open = True
        depth -= line.count("}")
        if saw_open and depth <= 0:
            return index
    return min(len(lines), start_line)


def _target_line(text: str, region: Mapping[str, Any]) -> int:
    start = int(region.get("startLine") or 1)
    end = int(region.get("endLine") or start)
    lines = text.splitlines()
    sink_patterns = ["memcpy", "memmove", "strcpy", "strcat", "system", "printf", "malloc", "free", "/", "NULL"]
    for index in range(max(1, start), min(len(lines), end) + 1):
        if any(pattern in lines[index - 1] for pattern in sink_patterns):
            return index
    return max(1, min(start, max(1, len(lines))))


def _safe_zip_target(root: Path, member_name: str) -> Path:
    pure = PurePosixPath(member_name)
    if pure.is_absolute() or any(part in {"..", ""} for part in pure.parts):
        raise ValueError("unsafe zip member path")
    target = (root / Path(*pure.parts)).resolve()
    root_resolved = root.resolve()
    if os.path.commonpath([str(root_resolved), str(target)]) != str(root_resolved):
        raise ValueError("unsafe zip member path escapes root")
    return target


def _safe_rmtree(path: Path, *, allowed_root: Path) -> None:
    root = path.resolve()
    allowed = allowed_root.resolve()
    if os.path.commonpath([str(allowed), str(root)]) != str(allowed):
        raise ValueError("refusing to delete extraction path outside corpus cache")
    shutil.rmtree(path)


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _require_checksum(path: Path, expected_checksum: str) -> None:
    actual = _sha256_file(path)
    if actual != expected_checksum:
        raise ValueError("checksum mismatch")


def _sha256_tree(root: Path) -> str:
    digest = sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        rel = _relative_posix(path, root)
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256_file(path).encode("utf-8"))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _relative_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _safe_case_stem(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return normalized[:100] or "case"


def _write_json(payload: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _acquisition_index_for_validation(manifests: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(manifest["acquisitionId"]): {"manifest": dict(manifest), **validate_acquisition_manifest(manifest)}
        for manifest in manifests
    }


def _count_cases_by_field(cases: Any, field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not isinstance(cases, list):
        return counts
    for case in cases:
        if not isinstance(case, Mapping):
            continue
        key = str(case.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _corpus_manifest_created_at(acquisition_manifests: Sequence[Mapping[str, Any]]) -> str:
    dates: list[str] = []
    for manifest in acquisition_manifests:
        downloaded_at = manifest.get("downloadedAt")
        if not isinstance(downloaded_at, str) or not downloaded_at.strip():
            continue
        date = downloaded_at.split("T", 1)[0].strip()
        if date:
            dates.append(date)
    return max(dates) if dates else "1970-01-01"


if __name__ == "__main__":
    raise SystemExit(main())
