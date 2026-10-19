from agent.gateway_client import GatewayClient


def test_client_fails_closed_when_gateway_unreachable():
    r = GatewayClient("http://127.0.0.1:9", "token", timeout=0.5).invoke("query_asset_inventory", "printer")
    assert r.decision == "ERROR" and not r.allowed
    assert r.for_model().startswith("BLOCKED")
