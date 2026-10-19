"""Tool implementations. These live inside the gateway process boundary: the agent
never touches the asset store or the document folder directly."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path

from .textnorm import normalize

MAX_DOC_CHARS = 8000


def resolve_assets(conn: sqlite3.Connection, query: str) -> dict[str, int]:
    """Map asset_id -> length of its longest alias found as a whole token in `query`.

    Matching is on the canonicalised text (NFKC, zero-width stripped, casefolded) and
    on token boundaries, so 'observer' does not match 'server'.
    """
    q = normalize(query)
    found: dict[str, int] = {}
    for row in conn.execute("SELECT alias, asset_id FROM asset_aliases"):
        alias = row["alias"]
        if re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", q):
            found[row["asset_id"]] = max(found.get(row["asset_id"], 0), len(alias))
    return found


def read_docs(docs_dir: str) -> str:
    folder = Path(docs_dir)
    if not folder.is_dir():
        return "No documents found."
    parts = []
    for path in sorted(folder.glob("*.txt")):
        text = path.read_text(encoding="utf-8", errors="replace")[:MAX_DOC_CHARS]
        parts.append(f"<<UNTRUSTED_DOCUMENT {path.name}>>\n{text}\n<<END_UNTRUSTED_DOCUMENT>>")
    return "\n\n".join(parts) if parts else "No documents found."


def execute(docs_dir: str, conn: sqlite3.Connection, tool: str, query: str,
            asset_id: str | None = None) -> str:
    """Run a tool. For asset-scoped tools the gateway passes the *already authorised*
    canonical asset_id, so the object checked is the object used (no check/use gap).
    With asset_id=None (insecure baseline) the longest-alias match is used, unchecked."""
    if tool == "read_support_docs":
        return read_docs(docs_dir)
    if tool == "create_ticket":
        tid = "T-" + hashlib.sha256(query.encode()).hexdigest()[:6].upper()
        return f"SIMULATED: ticket {tid} created: {query[:200]!r}"
    if tool == "export_assets":
        rows = conn.execute("SELECT id, classification, details FROM assets ORDER BY id").fetchall()
        dump = [{"id": r["id"], "classification": r["classification"],
                 "details": json.loads(r["details"])} for r in rows]
        return f"EXECUTED: exported {len(dump)} assets: {json.dumps(dump, sort_keys=True)}"
    if tool in ("query_asset_inventory", "delete_asset"):
        if asset_id is None:
            matches = resolve_assets(conn, query)
            if not matches:
                return f"No asset found matching {query[:80]!r}."
            asset_id = max(matches, key=matches.get)
        row = conn.execute("SELECT details FROM assets WHERE id=?", (asset_id,)).fetchone()
        if row is None:
            return "No asset found."
        if tool == "query_asset_inventory":
            return f"Asset found: {json.dumps(json.loads(row['details']), sort_keys=True)}"
        return f"EXECUTED: SIMULATED deletion of asset {asset_id}"  # no real mutation
    return "Tool not registered."
