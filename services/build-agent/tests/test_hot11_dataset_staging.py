from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


_STAGER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "stage_hot11_datasets.py"
_SPEC = importlib.util.spec_from_file_location("stage_hot11_datasets", _STAGER_PATH)
assert _SPEC and _SPEC.loader
stager = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = stager
_SPEC.loader.exec_module(stager)


def _write(path: Path, text: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _fake_re100(root: Path) -> None:
    _write(root / "gateway-webserver" / "scripts" / "cross_build.sh", "#!/bin/bash\nmake\n")
    _write(root / "gateway-webserver" / "src" / "main.cpp", "int main(){return 0;}\n")
    _write(root / "gateway-webserver" / "libraries" / "civetweb" / "include" / "civetweb.h", "")
    _write(root / "gateway" / "scripts" / "build" / "build_all.sh", "#!/bin/sh\n")
    _write(root / "gateway" / "scripts" / "build" / "cross_build.sh", "#!/bin/bash\n")
    _write(root / "gateway" / "libraries" / "mosquitto" / "include" / "mosquitto.h", "")
    _write(root / "gateway" / "certs" / "ca.crt", "")
    for app in stager.GATEWAY_APPS:
        _write(root / "gateway" / "apps" / app / "src" / "main.cpp", "int main(){return 0;}\n")


def test_stage_re100_hot11_sdk_cases_are_descriptor_based_and_app_isolated(tmp_path: Path) -> None:
    source_root = tmp_path / "RE100"
    dest_root = tmp_path / "fixtures"
    sdk_root = tmp_path / "sdk"
    _fake_re100(source_root)
    _write(sdk_root / "linux-devkit" / "environment-setup-arm", "export CC=arm-gcc\n")
    (sdk_root / "linux-devkit" / "sysroots" / "arm").mkdir(parents=True)

    cases = stager.stage_re100_cases(
        source_root=source_root,
        dest_root=dest_root,
        sdk_root=sdk_root,
        clean=True,
    )

    case_ids = {case["caseId"] for case in cases}
    assert case_ids == {
        "gateway-webserver",
        "gateway-central",
        "gateway-mqtt_broker",
        "gateway-coap_server",
        "gateway-lwm2m_server",
    }
    for case in cases:
        build = case["build"]
        assert build["mode"] == "sdk"
        assert build["sdkRootPath"] == str(sdk_root)
        assert build["setupScript"] == "linux-devkit/environment-setup-arm"
        assert build["sysroot"] == "linux-devkit/sysroots/arm"
        assert build["toolchainTriplet"] == "arm-none-linux-gnueabihf"
        assert "ti-processor-sdk-linux-am335x-evm-08.02.00.24" not in str(case)

    central = dest_root / "gateway-central"
    assert (central / "apps" / "central" / "src" / "main.cpp").is_file()
    assert not (central / "apps" / "mqtt_broker").exists()
    assert (central / "scripts" / "build" / "build_all.sh").is_file()
    assert (central / "libraries" / "mosquitto" / "include" / "mosquitto.h").is_file()


def test_stage_re100_adds_opt_in_renamed_control_case(tmp_path: Path) -> None:
    source_root = tmp_path / "RE100"
    dest_root = tmp_path / "fixtures"
    sdk_root = tmp_path / "sdk"
    _fake_re100(source_root)
    _write(sdk_root / "linux-devkit" / "environment-setup-arm", "export CC=arm-gcc\n")
    (sdk_root / "linux-devkit" / "sysroots" / "arm").mkdir(parents=True)

    stager.stage_re100_cases(
        source_root=source_root,
        dest_root=dest_root,
        sdk_root=sdk_root,
        clean=True,
    )
    controls = stager.stage_control_cases(dest_root=dest_root, sdk_root=sdk_root, clean=True)

    assert [case["caseId"] for case in controls] == ["renamed-sdk-control-web"]
    control = controls[0]
    assert Path(control["projectPath"]).name == "renamed-sdk-control-web"
    assert control["buildTargetName"] == "renamed-sdk-control-web"
    assert control["controlKind"] == "metamorphic-renamed-fixture"
    assert control["controlOf"] == "gateway-webserver"
    assert control["expectedArtifacts"] == [{"artifactType": "executable", "name": "gateway_webserver", "required": True}]
    assert (dest_root / "renamed-sdk-control-web" / "scripts" / "cross_build.sh").is_file()
    assert (dest_root / "renamed-sdk-control-web" / "src" / "main.cpp").is_file()
