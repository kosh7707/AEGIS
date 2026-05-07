from __future__ import annotations

from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1] / "app"


def test_active_build_agent_code_has_no_host_sdk_or_re100_shortcuts() -> None:
    forbidden = [
        "/home/kosh/ti-sdk",
        "gateway-webserver",
        "gateway-central",
        "gateway-mqtt_broker",
        "gateway-coap_server",
        "gateway-lwm2m_server",
        "RE100",
    ]
    hits: list[str] = []
    for path in APP_ROOT.rglob("*.py"):
        text = path.read_text(errors="replace")
        for marker in forbidden:
            if marker in text:
                hits.append(f"{path.relative_to(APP_ROOT)}:{marker}")

    assert hits == []

