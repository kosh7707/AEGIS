"""C/C++ native-security lexical signal extraction for S5 GraphRAG.

Keyword matching remains a weak/contextual signal, but it should not be a single
hard-coded automotive keyword list.  This module normalizes code-ish tokens and
maps them into C/C++ system-security concepts that can expand candidate pools
and make retrieval traces understandable to S3/S4.
"""

from __future__ import annotations

import re
from typing import Any

_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ACRONYM_BOUNDARY_RE = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_TOKEN_RE = re.compile(r"CVE-\d{4}-\d+|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d+)?|[A-Za-z][A-Za-z0-9_]*|\.\./|/[^\s]+")

LEXICAL_ALIAS_GROUPS: dict[str, dict[str, Any]] = {
    "command_execution": {
        "category": "native_security_primitive",
        "aliases": [
            "system", "popen", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp",
            "shell", "cmd", "command", "commandline", "command-line", "powershell", "bash", "sh", "fork",
            "xp_cmdshell", "T1059", "T0807", "CAPEC-88", "CWE-78", "CWE-77",
        ],
    },
    "memory_safety": {
        "category": "native_security_primitive",
        "aliases": [
            "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf",
            "gets", "scanf", "malloc", "calloc", "realloc", "free", "uaf", "useafterfree", "doublefree",
            "overflow", "underflow", "bounds", "buffer", "CWE-119", "CWE-120", "CWE-787", "CWE-416",
        ],
    },
    "path_file_access": {
        "category": "native_security_primitive",
        "aliases": [
            "path", "traversal", "../", "fopen", "open", "openat", "read", "write", "readlink",
            "symlink", "unlink", "rename", "canonicalize", "realpath", "CWE-22", "CWE-73",
        ],
    },
    "crypto_tls": {
        "category": "native_security_primitive",
        "aliases": [
            "ssl", "tls", "openssl", "mbedtls", "wolfssl", "certificate", "x509", "verify", "cipher",
            "random", "rng", "CWE-295", "CWE-327", "CWE-330",
        ],
    },
    "network_protocol": {
        "category": "native_security_primitive",
        "aliases": [
            "socket", "connect", "send", "recv", "http", "mqtt", "can", "uds", "doip", "tcp", "udp",
            "parse", "parser", "deserialize", "protobuf", "json", "CWE-20", "CWE-502",
        ],
    },
    "concurrency_resource_lifecycle": {
        "category": "native_security_primitive",
        "aliases": [
            "thread", "mutex", "lock", "unlock", "race", "deadlock", "fd", "handle", "close", "dispose",
            "lifetime", "CWE-362", "CWE-772",
        ],
    },
    "package_identity": {
        "category": "package_identity",
        "aliases": [
            "purl", "cpe", "pkg", "package", "library", "version", "openssl", "curl", "zlib", "busybox",
            "CVE", "GHSA", "OSV", "NVD",
        ],
    },
    "embedded_ics_profile": {
        "category": "specialization_profile",
        "aliases": [
            "ecu", "firmware", "rtos", "bootloader", "ota", "can", "uds", "doip", "autosar", "hmi",
            "plc", "scada", "modbus", "dnp3", "ics", "ot", "T0807",
        ],
    },
}


def split_identifier_tokens(text: str) -> list[str]:
    """Split C/C++-ish identifiers, paths, namespaces, and macros into tokens."""

    tokens: list[str] = []
    for raw in _TOKEN_RE.findall(text or ""):
        raw = raw.strip()
        if not raw:
            continue
        if re.fullmatch(r"CVE-\d{4}-\d+|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d+)?", raw, flags=re.I):
            token = raw.upper()
            if token not in tokens:
                tokens.append(token)
            continue
        pieces = re.split(r"::|->|\.|/|\\|-", raw)
        for piece in pieces:
            split_piece = _ACRONYM_BOUNDARY_RE.sub(" ", _CAMEL_BOUNDARY_RE.sub(" ", piece))
            for camel_piece in split_piece.split():
                for sub in camel_piece.split("_"):
                    token = sub.strip().lower()
                    if len(token) < 2 and token not in {"c"}:
                        continue
                    if token not in tokens:
                        tokens.append(token)
    return tokens


def _canonical_alias_map() -> dict[str, tuple[str, dict[str, Any]]]:
    aliases: dict[str, tuple[str, dict[str, Any]]] = {}
    for canonical, spec in LEXICAL_ALIAS_GROUPS.items():
        for alias in spec["aliases"]:
            aliases[str(alias).lower()] = (canonical, spec)
    return aliases


def lexical_signals_for_query(query: str, profiles: list[str] | None = None) -> list[dict[str, Any]]:
    """Return deduplicated lexical signals for a query.

    Signals are intentionally weak: they are ranking/candidate-generation hints,
    not vulnerability truth and never negative evidence.
    """

    alias_map = _canonical_alias_map()
    tokens = split_identifier_tokens(query)
    # Preserve common joined forms that token splitting separates.
    normalized_query = (query or "").lower().replace("_", "").replace("-", "")
    emitted: dict[str, dict[str, Any]] = {}
    for token in tokens:
        lookup_terms = {token.lower(), token.upper().lower()}
        if token.lower() in {"use", "after", "free"} and "useafterfree" in normalized_query:
            lookup_terms.add("useafterfree")
        if token.lower() in {"double", "free"} and "doublefree" in normalized_query:
            lookup_terms.add("doublefree")
        for term in lookup_terms:
            if term not in alias_map:
                continue
            canonical, spec = alias_map[term]
            signal = emitted.setdefault(
                canonical,
                {
                    "term": token,
                    "canonical": canonical,
                    "category": spec["category"],
                    "method": "keyword_match",
                    "trust": "weak",
                    "consumerPolicy": "contextual_only",
                    "negativeEvidenceAllowed": False,
                    "aliases": [],
                    "profiles": list(profiles or []),
                },
            )
            if token not in signal["aliases"]:
                signal["aliases"].append(token)
    return list(emitted.values())


def matched_terms_from_signals(signals: list[dict[str, Any]]) -> list[str]:
    terms: list[str] = []
    for signal in signals:
        for value in [signal.get("term"), signal.get("canonical"), *(signal.get("aliases") or [])]:
            if not value:
                continue
            term = str(value)
            if term not in terms:
                terms.append(term)
    return terms


def lexical_methods(signals: list[dict[str, Any]]) -> list[str]:
    return ["keyword_match"] if signals else []
