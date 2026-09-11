"""Minimal JSON-schema subset validator for S3 tool-call arguments."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SchemaDict = Mapping[str, Any]


def validate_tool_arguments(arguments: object, schema: SchemaDict | None) -> list[str]:
    """Return human-readable violations for the supported S3 schema subset."""
    violations: list[str] = []
    _validate_value(arguments, schema or {}, "$", violations)
    return violations


def _validate_value(value: object, schema: SchemaDict, path: str, violations: list[str]) -> None:
    schema_type = _schema_type(schema)

    if schema_type == "object":
        if not isinstance(value, dict):
            violations.append(f"TYPE {path}: expected object, got {_type_name(value)}")
            return
        _validate_object(value, schema, path, violations)
        return

    if schema_type == "array":
        if not isinstance(value, list):
            violations.append(f"TYPE {path}: expected array, got {_type_name(value)}")
            return
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate_value(item, item_schema, f"{path}[{index}]", violations)
        return

    if schema_type == "string":
        if not isinstance(value, str):
            violations.append(f"TYPE {path}: expected string, got {_type_name(value)}")
        return

    if schema_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            violations.append(f"TYPE {path}: expected integer, got {_type_name(value)}")
        return

    if schema_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            violations.append(f"TYPE {path}: expected number, got {_type_name(value)}")
        return

    if schema_type == "boolean":
        if not isinstance(value, bool):
            violations.append(f"TYPE {path}: expected boolean, got {_type_name(value)}")
        return

    # Unsupported or absent keywords are intentionally ignored for forward compatibility.


def _validate_object(value: dict[str, object], schema: SchemaDict, path: str, violations: list[str]) -> None:
    properties = schema.get("properties")
    property_schemas = properties if isinstance(properties, Mapping) else {}

    required = schema.get("required")
    if isinstance(required, list):
        for key in required:
            if isinstance(key, str) and key not in value:
                violations.append(f"MISSING {path}.{key}")

    additional_properties = schema.get("additionalProperties", _ALLOW_EXTRAS)

    for key, item in value.items():
        child_path = f"{path}.{key}"
        child_schema = property_schemas.get(key)
        if isinstance(child_schema, Mapping):
            _validate_value(item, child_schema, child_path, violations)
            continue

        if additional_properties is False:
            violations.append(f"UNEXPECTED {child_path}")
            continue

        if isinstance(additional_properties, Mapping):
            _validate_value(item, additional_properties, child_path, violations)


def _schema_type(schema: SchemaDict) -> str | None:
    raw = schema.get("type")
    if isinstance(raw, str):
        return raw
    if any(key in schema for key in ("properties", "required", "additionalProperties")):
        return "object"
    if "items" in schema:
        return "array"
    return None


def _type_name(value: object) -> str:
    return type(value).__name__


_ALLOW_EXTRAS = object()
