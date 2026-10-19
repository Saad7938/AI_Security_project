"""SQLite-backed RBAC store. Policy lives in data, not in code."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .textnorm import normalize

SCHEMA = """
CREATE TABLE IF NOT EXISTS principals(
  id TEXT PRIMARY KEY, description TEXT, disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS roles(name TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS principal_roles(
  principal TEXT NOT NULL REFERENCES principals(id),
  role TEXT NOT NULL REFERENCES roles(name),
  PRIMARY KEY(principal, role));
CREATE TABLE IF NOT EXISTS tools(name TEXT PRIMARY KEY, kind TEXT NOT NULL
  CHECK(kind IN ('plain','asset_scoped')));
CREATE TABLE IF NOT EXISTS permissions(
  role TEXT NOT NULL REFERENCES roles(name),
  tool TEXT NOT NULL REFERENCES tools(name),
  resource_class TEXT NOT NULL DEFAULT '*',
  PRIMARY KEY(role, tool, resource_class));
CREATE TABLE IF NOT EXISTS assets(
  id TEXT PRIMARY KEY, classification TEXT NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS asset_aliases(
  alias TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(id));
CREATE TABLE IF NOT EXISTS sessions(
  jti TEXT PRIMARY KEY, principal TEXT NOT NULL REFERENCES principals(id),
  issued_at TEXT NOT NULL, consecutive_denials INTEGER NOT NULL DEFAULT 0,
  total_denials INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS revoked_tokens(
  jti TEXT PRIMARY KEY, revoked_at TEXT NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, event TEXT NOT NULL,
  principal TEXT, jti TEXT, tool TEXT, decision TEXT, reason TEXT,
  query_summary TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
"""

SEED_FILE = Path(__file__).with_name("seed_data.json")


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def tx(conn: sqlite3.Connection):
    """Serialised write transaction (also serialises the audit hash chain)."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def init_db(path: str, seed_file: Path = SEED_FILE) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        if conn.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 0:
            load_seed(conn, seed_file)
    finally:
        conn.close()


def load_seed(conn: sqlite3.Connection, seed_file: Path) -> None:
    seed = json.loads(Path(seed_file).read_text(encoding="utf-8"))
    with tx(conn):
        for p in seed["principals"]:
            conn.execute("INSERT INTO principals(id, description) VALUES(?,?)",
                         (p["id"], p.get("description", "")))
        for r in seed["roles"]:
            conn.execute("INSERT INTO roles(name) VALUES(?)", (r,))
        conn.executemany("INSERT INTO principal_roles VALUES(?,?)", seed["principal_roles"])
        for t in seed["tools"]:
            conn.execute("INSERT INTO tools(name, kind) VALUES(?,?)", (t["name"], t["kind"]))
        conn.executemany("INSERT INTO permissions VALUES(?,?,?)", seed["permissions"])
        for a in seed["assets"]:
            conn.execute("INSERT INTO assets VALUES(?,?,?)",
                         (a["id"], a["classification"], json.dumps(a["details"], sort_keys=True)))
            for alias in a["aliases"]:
                conn.execute("INSERT INTO asset_aliases VALUES(?,?)", (normalize(alias), a["id"]))
