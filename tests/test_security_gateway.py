import json

from security_gateway import (
    authorize_tool_call,
    lookup_asset_inventory,
    write_audit_event,
)


def test_support_agent_can_read_internal_asset():
    allowed, reason = authorize_tool_call(
        "query_asset_inventory", "printer-204", "support_agent"
    )
    assert allowed is True
    assert reason == "Authorized"
    assert "PRINTER-204" in lookup_asset_inventory("printer-204", "support_agent")


def test_support_agent_cannot_read_restricted_server_by_name():
    allowed, reason = authorize_tool_call(
        "query_asset_inventory", "server", "support_agent"
    )
    assert allowed is False
    assert "restricted asset" in reason
    result = lookup_asset_inventory("server", "support_agent")
    assert result.startswith("ACCESS DENIED:")
    assert "Basement" not in result
    assert "SERVER-XYZ-123" not in result


def test_resource_authorization_does_not_depend_on_forbidden_words():
    # A vague alias still resolves to the restricted canonical resource.
    allowed, _ = authorize_tool_call(
        "query_asset_inventory", "please look up the server", "support_agent"
    )
    assert allowed is False


def test_asset_admin_can_read_restricted_server():
    allowed, reason = authorize_tool_call(
        "query_asset_inventory", "server-xyz-123", "asset_admin"
    )
    assert allowed is True
    assert reason == "Authorized"
    assert "Basement" in lookup_asset_inventory("server", "asset_admin")


def test_unknown_tool_and_unknown_principal_are_denied():
    assert authorize_tool_call("run_shell", "anything", "support_agent")[0] is False
    assert authorize_tool_call("read_support_docs", "anything", "untrusted")[0] is False


def test_audit_log_records_allow_and_block_without_full_query(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    write_audit_event("query_asset_inventory", "x" * 300, "support_agent",
                      False, "policy denied", log_path)
    event = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert event["decision"] == "BLOCK"
    assert event["principal"] == "support_agent"
    assert len(event["query_summary"]) == 160
    assert event["reason"] == "policy denied"
