"""Database-driven RBAC decision. Deny by default; fail closed on ambiguity."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .tools import resolve_assets


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    asset_id: str | None = None
    # Does this denial count toward the intrusion tripwire? Genuine authorisation
    # violations do; a plain "asset not found" typo does not.
    suspicious: bool = False


def _classes(conn: sqlite3.Connection, principal: str, tool: str) -> set[str]:
    rows = conn.execute(
        "SELECT DISTINCT p.resource_class FROM principal_roles pr "
        "JOIN permissions p ON p.role = pr.role WHERE pr.principal=? AND p.tool=?",
        (principal, tool)).fetchall()
    return {r[0] for r in rows}


def authorize(conn: sqlite3.Connection, principal: str, tool: str, query: str) -> Decision:
    kind_row = conn.execute("SELECT kind FROM tools WHERE name=?", (tool,)).fetchone()
    if kind_row is None:
        return Decision(False, "Tool not registered", suspicious=True)

    classes = _classes(conn, principal, tool)
    if not classes:
        return Decision(False, "Principal lacks permission for tool", suspicious=True)

    if kind_row["kind"] == "plain":
        if "*" in classes:
            return Decision(True, "Authorized")
        return Decision(False, "Principal lacks permission for tool", suspicious=True)

    # asset_scoped: authorise against the classification of the canonical resource
    matches = resolve_assets(conn, query)
    if not matches:
        return Decision(False, "Asset not found")
    if len(matches) > 1:
        return Decision(False, "Ambiguous asset reference (multiple assets named)",
                        suspicious=True)
    asset_id = next(iter(matches))
    cls = conn.execute("SELECT classification FROM assets WHERE id=?", (asset_id,)).fetchone()[0]
    if cls in classes or "*" in classes:
        return Decision(True, "Authorized", asset_id=asset_id)
    return Decision(False, f"Principal lacks permission for {cls} asset", suspicious=True)
