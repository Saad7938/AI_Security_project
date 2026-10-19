"""Policy decisions are database-driven, deny-by-default and canonicalised."""
from gateway.policy import authorize
from gateway.tools import resolve_assets

Q = "query_asset_inventory"


def test_support_reads_internal_not_restricted(conn):
    assert authorize(conn, "support_agent", Q, "printer-204").allowed
    d = authorize(conn, "support_agent", Q, "server")
    assert not d.allowed and "restricted" in d.reason


def test_admin_reads_restricted(conn):
    assert authorize(conn, "asset_admin", Q, "xyz-123").allowed


def test_decision_does_not_depend_on_trigger_words(conn):
    # benign text containing 'secret' / 'admin' / 'restricted' is not blocked...
    assert authorize(conn, "support_agent", "create_ticket", "restricted admin secret reset").allowed
    # ...and a restricted asset with none of those words is still denied
    assert not authorize(conn, "support_agent", Q, "the server").allowed


def test_unknown_tool_principal_and_viewer_denied(conn):
    assert not authorize(conn, "support_agent", "run_shell", "ls").allowed
    assert not authorize(conn, "nobody", "read_support_docs", "x").allowed
    assert not authorize(conn, "viewer_agent", "create_ticket", "x").allowed
    assert authorize(conn, "viewer_agent", "read_support_docs", "x").allowed


def test_support_cannot_use_privileged_tools(conn):
    assert not authorize(conn, "support_agent", "delete_asset", "printer-204").allowed
    assert not authorize(conn, "support_agent", "export_assets", "all").allowed


def test_ambiguous_reference_fails_closed(conn):
    d = authorize(conn, "support_agent", Q, "printer-204 and server-xyz-123")
    assert not d.allowed and d.suspicious


def test_unicode_and_zero_width_obfuscation_is_canonicalised(conn):
    assert "server-xyz-123" in resolve_assets(conn, "\uff53\uff45\uff52\uff56\uff45\uff52-xyz-123")
    assert "server-xyz-123" in resolve_assets(conn, "s\u200berver")
    assert resolve_assets(conn, "observer") == {}          # token boundaries, no substring match


def test_not_found_is_denied_but_not_suspicious(conn):
    d = authorize(conn, "support_agent", Q, "toaster")
    assert not d.allowed and not d.suspicious


def test_policy_change_takes_effect_immediately(client, conn):
    assert not authorize(conn, "support_agent", Q, "server").allowed
    body = {"role": "support", "tool": Q, "resource_class": "restricted"}
    assert client.post("/admin/permissions/grant", json=body, headers={"X-Admin-Key": "a" * 24}).status_code == 200
    assert authorize(conn, "support_agent", Q, "server").allowed
    client.post("/admin/permissions/revoke", json=body, headers={"X-Admin-Key": "a" * 24})
    assert not authorize(conn, "support_agent", Q, "server").allowed
