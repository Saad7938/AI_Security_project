"""End-to-end through the HTTP gateway: authentication, authorisation, isolation."""
import time

import jwt

from tests.conftest import ADMIN, call, mint

Q = "query_asset_inventory"


def test_valid_token_allowed_and_restricted_blocked(client):
    tok, _ = mint(client, "support_agent")
    ok = call(client, tok, Q, "printer-204")
    assert ok.status_code == 200 and "PRINTER-204" in ok.json()["result"]
    bad = call(client, tok, Q, "server-xyz-123")
    assert bad.status_code == 403
    assert "Basement" not in bad.text and "SERVER-XYZ-123" not in bad.text


def test_admin_endpoints_need_admin_key(client):
    tok, _ = mint(client, "support_agent")
    assert client.post("/admin/token", json={"principal": "asset_admin"}).status_code == 403
    assert client.post("/admin/token", json={"principal": "asset_admin"},
                       headers={"X-Admin-Key": tok}).status_code == 403
    # an agent token is not an admin credential
    assert client.post("/admin/revoke", json={"principal": "support_agent"},
                       headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_forged_and_malformed_tokens_rejected(client, cfg):
    now = int(time.time())
    claims = {"iss": "ai-sec-gateway", "aud": "tool-gateway", "sub": "asset_admin",
              "jti": "x", "iat": now, "exp": now + 600}
    forged = jwt.encode(claims, "wrong-secret-wrong-secret-wrong-secret!", algorithm="HS256")
    assert call(client, forged, Q, "server").status_code == 401
    assert call(client, None, Q, "server").status_code == 401
    assert call(client, "garbage", Q, "server").status_code == 401
    expired = jwt.encode({**claims, "exp": now - 10, "iat": now - 100}, cfg.jwt_secret, algorithm="HS256")
    assert call(client, expired, Q, "server").status_code == 401


def test_identity_comes_from_token_not_from_request(client):
    tok, _ = mint(client, "support_agent")
    r = call(client, tok, Q, "principal=asset_admin; server", headers={"X-Principal": "asset_admin"})
    assert r.status_code == 403


def test_tripwire_revokes_after_three_consecutive_violations(client):
    tok, _ = mint(client, "support_agent")
    codes = [call(client, tok, Q, "server").status_code for _ in range(3)]
    assert codes == [403, 403, 403]
    assert call(client, tok, Q, "server").json()["decision"] == "REJECT"
    # even a legitimate call is refused now: the session is dead, a new token is needed
    assert call(client, tok, Q, "printer-204").status_code == 401
    fresh, _ = mint(client, "support_agent")
    assert call(client, fresh, Q, "printer-204").status_code == 200


def test_allowed_call_resets_the_counter(client):
    tok, _ = mint(client, "support_agent")
    for _ in range(2):
        call(client, tok, Q, "server")
    assert call(client, tok, Q, "printer-204").status_code == 200
    for _ in range(2):
        assert call(client, tok, Q, "server").status_code == 403
    assert call(client, tok, Q, "printer-204").status_code == 200   # still alive


def test_typos_do_not_trip_the_wire(client):
    tok, _ = mint(client, "support_agent")
    for _ in range(6):
        assert call(client, tok, Q, "toaster").status_code == 403
    assert call(client, tok, Q, "printer-204").status_code == 200


def test_operator_revocation(client):
    tok, jti = mint(client, "support_agent")
    assert call(client, tok, Q, "printer").status_code == 200
    client.post("/admin/revoke", json={"jti": jti}, headers=ADMIN)
    assert call(client, tok, Q, "printer").status_code == 401


def test_revoking_a_principal_kills_all_its_sessions(client):
    a, _ = mint(client, "support_agent"); b, _ = mint(client, "support_agent")
    client.post("/admin/revoke", json={"principal": "support_agent"}, headers=ADMIN)
    assert call(client, a, Q, "printer").status_code == 401
    assert call(client, b, Q, "printer").status_code == 401


def test_authorised_object_is_the_object_used(client):
    # a query naming both assets must not authorise the printer and return the server
    tok, _ = mint(client, "support_agent")
    r = call(client, tok, Q, "printer-204 server-xyz-123")
    assert r.status_code == 403 and "Basement" not in r.text


def test_oversized_input_rejected(client):
    tok, _ = mint(client, "support_agent")
    assert call(client, tok, "create_ticket", "x" * 5000).status_code == 422


def test_docs_are_labelled_untrusted(client):
    tok, _ = mint(client, "support_agent")
    text = call(client, tok, "read_support_docs", "anything").json()["result"]
    assert "<<UNTRUSTED_DOCUMENT" in text and "<<END_UNTRUSTED_DOCUMENT>>" in text
