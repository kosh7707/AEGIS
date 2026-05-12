from __future__ import annotations

from app.graphrag.lexical_signals import lexical_methods, lexical_signals_for_query, split_identifier_tokens


def test_split_identifier_tokens_handles_cpp_symbols_paths_macros_and_camel_case():
    tokens = split_identifier_tokens("Gateway::runCommand HTTPClient_send /src/net/http_client.cpp CWE-78")

    assert "gateway" in tokens
    assert "run" in tokens
    assert "command" in tokens
    assert "http" in tokens
    assert "client" in tokens
    assert "send" in tokens
    assert "CWE-78" in tokens


def test_lexical_signals_cover_native_security_and_profiles_without_negative_evidence():
    signals = lexical_signals_for_query(
        "ECU UDS handler calls popen then strcpy into parser buffer",
        profiles=["automotive-specialization"],
    )
    canonical = {signal["canonical"] for signal in signals}

    assert {"command_execution", "memory_safety", "embedded_ics_profile"} <= canonical
    assert lexical_methods(signals) == ["keyword_match"]
    for signal in signals:
        assert signal["trust"] == "weak"
        assert signal["consumerPolicy"] == "contextual_only"
        assert signal["negativeEvidenceAllowed"] is False
