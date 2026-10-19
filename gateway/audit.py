"""Hash-chained audit log: each row commits to its predecessor (tamper-evident)."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone

GENESIS = "0" * 64
_FIELDS = ("ts", "event", "principal", "jti", "tool", "decision", "reason", "query_summary")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _digest(prev_hash: str, record: dict) -> str:
    blob = prev_hash + json.dumps(record, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def append(conn: sqlite3.Connection, event: str, *, principal=None, jti=None, tool=None,
           decision=None, reason=None, query=None) -> None:
    """Must be called inside db.tx() so the chain is serialised."""
    summary = _CTRL.sub(" ", query)[:120] if query is not None else None
    record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event,
              "principal": principal, "jti": jti, "tool": tool, "decision": decision,
              "reason": reason, "query_summary": summary}
    row = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    prev = row[0] if row else GENESIS
    conn.execute(
        "INSERT INTO audit_log(ts,event,principal,jti,tool,decision,reason,query_summary,"
        "prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (*[record[f] for f in _FIELDS], prev, _digest(prev, record)))


def verify_chain(conn: sqlite3.Connection) -> tuple[bool, int, int | None]:
    """Return (ok, rows_checked, first_bad_seq)."""
    prev, n = GENESIS, 0
    for row in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
        n += 1
        record = {f: row[f] for f in _FIELDS}
        if row["prev_hash"] != prev or row["hash"] != _digest(prev, record):
            return False, n, row["seq"]
        prev = row["hash"]
    return True, n, None
