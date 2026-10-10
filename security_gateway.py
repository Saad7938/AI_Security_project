"""Dependency-free authorization helpers for the AI-agent security demo.

This is a teaching prototype, not a production authorization system.
The model never chooses its own principal; the application assigns it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_LOG_FILE = "tool_gateway_log.jsonl"

# Fictional records only. Classification is attached to the resource, not
# inferred from words such as "secret" in a model-generated argument.
ASSETS: dict[str, dict[str, Any]] = {
    "printer-204": {
        "aliases": ("printer", "printer-204", "office printer"),
        "classification": "internal",
        "details": {
            "asset_id": "PRINTER-204",
            "type": "Printer",
            "status": "Active",
        },
    },
    "server-xyz-123": {
        "aliases": ("server", "server-xyz-123", "xyz-123"),
        "classification": "restricted",
        "details": {
            "asset_id": "SERVER-XYZ-123",
            "type": "Server",
            "owner": "IT Admin",
            "status": "Active",
            "location": "Basement",
        },
    },
}

# These permissions are assigned by application code, not by the LLM.
PRINCIPAL_PERMISSIONS: dict[str, set[str]] = {
    "support_agent": {
        "tool:read_support_docs",
        "tool:create_ticket",
        "tool:query_asset_inventory",
        "asset:read:internal",
    },
    "asset_admin": {
        "tool:read_support_docs",
        "tool:create_ticket",
        "tool:query_asset_inventory",
        "asset:read:internal",
        "asset:read:restricted",
    },
}

TOOL_PERMISSION = {
    "read_support_docs": "tool:read_support_docs",
    "create_ticket": "tool:create_ticket",
    "query_asset_inventory": "tool:query_asset_inventory",
}


def resolve_asset(query: str) -> tuple[str | None, dict[str, Any] | None]:
    """Resolve a user/model query to a canonical fictional asset record."""
    normalized = " ".join(query.casefold().replace("_", "-").split())
    # Prefer the most specific aliases before broad aliases like "server".
    matches: list[tuple[int, str, dict[str, Any]]] = []
    for asset_id, record in ASSETS.items():
        for alias in record["aliases"]:
            if alias in normalized:
                matches.append((len(alias), asset_id, record))
    if not matches:
        return None, None
    _, asset_id, record = max(matches, key=lambda item: item[0])
    return asset_id, record


def authorize_tool_call(
    tool_name: str,
    query: str,
    principal: str = "support_agent",
) -> tuple[bool, str]:
    """Return an authorization decision using permissions and resource labels."""
    permissions = PRINCIPAL_PERMISSIONS.get(principal)
    if permissions is None:
        return False, "Unknown principal"

    required_tool_permission = TOOL_PERMISSION.get(tool_name)
    if required_tool_permission is None:
        return False, "Tool not registered"
    if required_tool_permission not in permissions:
        return False, "Principal lacks permission for tool"

    if tool_name == "query_asset_inventory":
        asset_id, record = resolve_asset(query)
        if record is None:
            return False, "Asset not found"
        classification = record["classification"]
        required_resource_permission = f"asset:read:{classification}"
        if required_resource_permission not in permissions:
            return False, f"Principal lacks permission for {classification} asset"
    return True, "Authorized"


def lookup_asset_inventory(
    query: str,
    principal: str = "support_agent",
) -> str:
    """Return only the record that the principal is authorized to read."""
    allowed, reason = authorize_tool_call(
        "query_asset_inventory", query, principal=principal
    )
    if not allowed:
        return f"ACCESS DENIED: {reason}."

    asset_id, record = resolve_asset(query)
    # authorize_tool_call guarantees that a record was found.
    assert asset_id is not None and record is not None
    return f"Asset found: {json.dumps(record['details'], sort_keys=True)}"


def write_audit_event(
    tool_name: str,
    query: str,
    principal: str,
    allowed: bool,
    reason: str,
    log_file: str | Path = DEFAULT_LOG_FILE,
) -> None:
    """Append one JSONL event. Query text is truncated to reduce data exposure."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "principal": principal,
        "tool": tool_name,
        "decision": "ALLOW" if allowed else "BLOCK",
        "reason": reason,
        "query_summary": query[:160],
    }
    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
