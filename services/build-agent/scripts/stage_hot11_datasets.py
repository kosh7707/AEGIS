#!/usr/bin/env python3
"""Stage Build Agent hot11 stabilization datasets.

The staged fixture directory is intentionally under ``uploads/`` because the
datasets are large, local, and generated from user-provided projects. This
script is the tracked, reviewable recipe that recreates the hot11 manifest:
existing hot6 cases are preserved from the current manifest when present, and
five RE100/TI SDK cases are materialized from ``~/RE100/RE100``.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

DEFAULT_SOURCE_ROOT = Path("/home/kosh/RE100/RE100")
DEFAULT_DEST_ROOT = Path("/home/kosh/AEGIS/uploads/build-agent-stabilization-datasets")
DEFAULT_MANIFEST = DEFAULT_DEST_ROOT / "manifest.json"
DEFAULT_SDK_ROOT = Path("/home/kosh/ti-sdk")
DEFAULT_SETUP_SCRIPT = "linux-devkit/environment-setup-armv7at2hf-neon-linux-gnueabi"
DEFAULT_SYSROOT = "linux-devkit/sysroots/armv7at2hf-neon-linux-gnueabi"
DEFAULT_TOOLCHAIN_TRIPLET = "arm-none-linux-gnueabihf"

GATEWAY_APPS = ("central", "mqtt_broker", "coap_server", "lwm2m_server")
HOT6_CASE_IDS = ("certificate-maker", "cjson", "libexpat", "redis", "openssl", "pjproject")

_IGNORE_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    "build",
    "dist",
    "build-wsl",
    "compile_commands.json",
    "dist.tar.gz",
}


def _ignore_generated(_dir: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        if name in _IGNORE_NAMES or name.startswith("build-aegis"):
            ignored.add(name)
    return ignored


def _copy_path(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    if src.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, ignore=_ignore_generated)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def _clean_dir(path: Path, *, clean: bool) -> None:
    if clean and path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _discover_sdk_descriptor_paths(sdk_root: Path) -> tuple[str, str]:
    default_setup = sdk_root / DEFAULT_SETUP_SCRIPT
    if default_setup.is_file():
        setup_script = DEFAULT_SETUP_SCRIPT
    else:
        matches = sorted((sdk_root / "linux-devkit").glob("environment-setup*"))
        setup_script = str(matches[0].relative_to(sdk_root)) if matches else DEFAULT_SETUP_SCRIPT

    default_sysroot = sdk_root / DEFAULT_SYSROOT
    if default_sysroot.is_dir():
        sysroot = DEFAULT_SYSROOT
    else:
        sysroots = sorted(p for p in (sdk_root / "linux-devkit" / "sysroots").glob("*") if p.is_dir())
        sysroot = str(sysroots[0].relative_to(sdk_root)) if sysroots else DEFAULT_SYSROOT
    return setup_script, sysroot


def _sdk_build_descriptor(*, sdk_root: Path, script_hint_path: str) -> dict[str, Any]:
    setup_script, sysroot = _discover_sdk_descriptor_paths(sdk_root)
    return {
        "mode": "sdk",
        "sdkId": "ti-am335x-08.02.00.24",
        "sdkRootPath": str(sdk_root),
        "setupScript": setup_script,
        "sysroot": sysroot,
        "toolchainTriplet": DEFAULT_TOOLCHAIN_TRIPLET,
        "scriptHintPath": script_hint_path,
    }


def _completed_clean_oracle() -> dict[str, Any]:
    return {
        "taskClass": "completed_clean",
        "status": "completed",
        "cleanPass": True,
        "buildOutcome": "built",
    }


def _executable(name: str) -> dict[str, Any]:
    return {"artifactType": "executable", "name": name, "required": True}


def _stage_gateway_webserver(source_root: Path, dest_root: Path, sdk_root: Path, *, clean: bool) -> dict[str, Any]:
    src = source_root / "gateway-webserver"
    dst = dest_root / "gateway-webserver"
    _clean_dir(dst, clean=clean)
    for child in ("src", "scripts", "libraries", "certs", "README.md"):
        _copy_path(src / child, dst / child)
    return {
        "caseId": "gateway-webserver",
        "title": "RE100 gateway-webserver TI SDK build",
        "projectPath": str(dst),
        "buildTargetPath": ".",
        "buildTargetName": "gateway-webserver",
        "build": _sdk_build_descriptor(sdk_root=sdk_root, script_hint_path="scripts/cross_build.sh"),
        "expectedArtifacts": [_executable("gateway_webserver")],
        "expectedOracle": _completed_clean_oracle(),
        "sourcePath": str(src),
    }


def _stage_gateway_app(source_root: Path, dest_root: Path, sdk_root: Path, app: str, *, clean: bool) -> dict[str, Any]:
    src = source_root / "gateway"
    case_id = f"gateway-{app}"
    dst = dest_root / case_id
    _clean_dir(dst, clean=clean)
    _copy_path(src / "scripts" / "build", dst / "scripts" / "build")
    _copy_path(src / "libraries", dst / "libraries")
    _copy_path(src / "certs", dst / "certs")
    _copy_path(src / "README.md", dst / "README.md")
    _copy_path(src / "apps" / app, dst / "apps" / app)
    return {
        "caseId": case_id,
        "title": f"RE100 gateway {app} TI SDK build",
        "projectPath": str(dst),
        "buildTargetPath": ".",
        "buildTargetName": case_id,
        "build": _sdk_build_descriptor(sdk_root=sdk_root, script_hint_path="scripts/build/build_all.sh"),
        "expectedArtifacts": [_executable(app)],
        "expectedOracle": _completed_clean_oracle(),
        "sourcePath": str(src / "apps" / app),
    }


def stage_re100_cases(
    *,
    source_root: Path,
    dest_root: Path,
    sdk_root: Path,
    clean: bool = False,
) -> list[dict[str, Any]]:
    """Stage the five RE100/TI SDK cases and return manifest case objects."""

    source_root = source_root.expanduser()
    dest_root = dest_root.expanduser()
    sdk_root = sdk_root.expanduser()
    cases = [_stage_gateway_webserver(source_root, dest_root, sdk_root, clean=clean)]
    cases.extend(
        _stage_gateway_app(source_root, dest_root, sdk_root, app, clean=clean)
        for app in GATEWAY_APPS
    )
    return cases


def stage_control_cases(
    *,
    dest_root: Path,
    sdk_root: Path,
    clean: bool = False,
) -> list[dict[str, Any]]:
    """Stage opt-in metamorphic/negative-control cases.

    The control intentionally reuses a real SDK project shape while changing
    the case id and fixture parent directory. It catches implementations that
    special-case ``gateway-webserver`` or the canonical fixture directory name
    instead of following the request descriptor.
    """

    source = dest_root.expanduser() / "gateway-webserver"
    control = dest_root.expanduser() / "renamed-sdk-control-web"
    if not source.is_dir():
        return []
    if clean and control.exists():
        shutil.rmtree(control)
    if control.exists():
        shutil.rmtree(control)
    shutil.copytree(source, control, ignore=_ignore_generated)
    return [
        {
            "caseId": "renamed-sdk-control-web",
            "title": "Metamorphic renamed SDK control for gateway webserver",
            "projectPath": str(control),
            "buildTargetPath": ".",
            "buildTargetName": "renamed-sdk-control-web",
            "build": _sdk_build_descriptor(sdk_root=sdk_root.expanduser(), script_hint_path="scripts/cross_build.sh"),
            "expectedArtifacts": [_executable("gateway_webserver")],
            "expectedOracle": _completed_clean_oracle(),
            "sourcePath": str(source),
            "controlKind": "metamorphic-renamed-fixture",
            "controlOf": "gateway-webserver",
        }
    ]


def load_existing_hot6(manifest_path: Path) -> list[dict[str, Any]]:
    if not manifest_path.is_file():
        return []
    raw = json.loads(manifest_path.read_text())
    by_id = {str(case.get("caseId")): case for case in raw.get("cases", [])}
    return [by_id[case_id] for case_id in HOT6_CASE_IDS if case_id in by_id]


def write_manifest(
    path: Path,
    cases: list[dict[str, Any]],
    *,
    controls: list[dict[str, Any]] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {"cases": cases}
    if controls:
        payload["controls"] = controls
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--dest-root", type=Path, default=DEFAULT_DEST_ROOT)
    parser.add_argument("--sdk-root", type=Path, default=DEFAULT_SDK_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--clean", action="store_true")
    parser.add_argument(
        "--no-preserve-hot6",
        action="store_true",
        help="write only the five RE100 SDK cases instead of preserving existing hot6 entries",
    )
    parser.add_argument(
        "--no-controls",
        action="store_true",
        help="do not stage opt-in metamorphic/negative-control cases",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    hot6 = [] if args.no_preserve_hot6 else load_existing_hot6(args.manifest)
    re100 = stage_re100_cases(
        source_root=args.source_root,
        dest_root=args.dest_root,
        sdk_root=args.sdk_root,
        clean=args.clean,
    )
    controls = [] if args.no_controls else stage_control_cases(
        dest_root=args.dest_root,
        sdk_root=args.sdk_root,
        clean=args.clean,
    )
    write_manifest(args.manifest, hot6 + re100, controls=controls)
    print(json.dumps({
        "manifest": str(args.manifest),
        "cases": [case["caseId"] for case in hot6 + re100],
        "controls": [case["caseId"] for case in controls],
    }, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
