from gateway import audit
from tests.conftest import ADMIN, call, mint


def test_audit_records_allow_block_and_tripwire(client, conn):
    tok, _ = mint(client, "support_agent")
    call(client, tok, "query_asset_inventory", "printer")
    for _ in range(3):
        call(client, tok, "query_asset_inventory", "server")
    events = [(r["event"], r["decision"]) for r in conn.execute("SELECT event, decision FROM audit_log")]
    assert ("TOOL_CALL", "ALLOW") in events and ("TOOL_CALL", "BLOCK") in events
    assert ("TRIPWIRE_REVOKE", "REVOKE") in events


def test_chain_verifies_and_detects_tampering(client, conn):
    tok, _ = mint(client, "support_agent")
    for q in ("printer", "server", "printer"):
        call(client, tok, "query_asset_inventory", q)
    assert client.get("/admin/audit/verify", headers=ADMIN).json()["ok"] is True
    conn.execute("UPDATE audit_log SET decision='ALLOW' WHERE decision='BLOCK'")   # attacker edits history
    ok, _, bad = audit.verify_chain(conn)
    assert ok is False and bad is not None


def test_audit_never_stores_full_query_or_control_chars(client, conn):
    tok, _ = mint(client, "support_agent")
    call(client, tok, "create_ticket", "A" * 500 + "\n\x00injected log line")
    row = conn.execute("SELECT query_summary FROM audit_log WHERE tool='create_ticket'").fetchone()
    assert len(row[0]) <= 120 and "\n" not in row[0] and "\x00" not in row[0]
