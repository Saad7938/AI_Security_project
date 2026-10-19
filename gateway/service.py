"""FastAPI gateway: the only component that can reach tools and data.

The agent presents a signed, short-lived token. Identity -> roles -> permissions are
resolved from the database on every call, so policy changes take effect immediately.
Repeated authorisation violations trip an automatic session revocation (IPS behaviour).
"""
from __future__ import annotations

import hmac
from datetime import datetime, timezone

import jwt
from fastapi import Depends, FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import audit, tokens
from .config import Config
from .db import connect, init_db, tx
from .policy import authorize
from .tools import execute


class InvokeBody(BaseModel):
    tool: str = Field(max_length=64)
    query: str = Field(max_length=4096)


class TokenBody(BaseModel):
    principal: str = Field(max_length=64)


class RevokeBody(BaseModel):
    jti: str | None = None
    principal: str | None = None


class PermBody(BaseModel):
    role: str
    tool: str
    resource_class: str = "*"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_app(cfg: Config) -> FastAPI:
    init_db(cfg.db_path)
    app = FastAPI(title="Tool Gateway", docs_url=None, redoc_url=None, openapi_url=None)

    def get_conn():
        conn = connect(cfg.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def require_admin(x_admin_key: str | None = Header(default=None)):
        if not x_admin_key or not hmac.compare_digest(x_admin_key, cfg.admin_key):
            return JSONResponse({"detail": "forbidden"}, status_code=403)
        return None

    def reject(conn, reason, *, jti=None, principal=None, tool=None, query=None):
        with tx(conn):
            audit.append(conn, "REJECT", principal=principal, jti=jti, tool=tool,
                         decision="REJECT", reason=reason, query=query)
        return JSONResponse({"decision": "REJECT", "reason": reason}, status_code=401)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/v1/invoke")
    def invoke(body: InvokeBody, authorization: str | None = Header(default=None),
               conn=Depends(get_conn)):
        if not authorization or not authorization.lower().startswith("bearer "):
            return reject(conn, "Missing bearer token", tool=body.tool, query=body.query)
        try:
            claims = tokens.verify(cfg.jwt_secret, authorization[7:].strip())
        except jwt.PyJWTError as exc:
            # Claims of an unverified token are never trusted or logged as identity.
            return reject(conn, f"Invalid token ({type(exc).__name__})",
                          tool=body.tool, query=body.query)

        jti = claims["jti"]
        with tx(conn):
            if conn.execute("SELECT 1 FROM revoked_tokens WHERE jti=?", (jti,)).fetchone():
                audit.append(conn, "REJECT", jti=jti, tool=body.tool, decision="REJECT",
                             reason="Token revoked", query=body.query)
                return JSONResponse({"decision": "REJECT", "reason": "Token revoked"},
                                    status_code=401)
            sess = conn.execute("SELECT principal FROM sessions WHERE jti=?", (jti,)).fetchone()
            prin = conn.execute("SELECT disabled FROM principals WHERE id=?",
                                (claims["sub"],)).fetchone()
            if sess is None or sess["principal"] != claims["sub"] or prin is None or prin["disabled"]:
                audit.append(conn, "REJECT", jti=jti, tool=body.tool, decision="REJECT",
                             reason="Unknown session or principal", query=body.query)
                return JSONResponse({"decision": "REJECT", "reason": "Unknown session or principal"},
                                    status_code=401)

            principal = claims["sub"]
            decision = authorize(conn, principal, body.tool, body.query)
            if decision.allowed:
                conn.execute("UPDATE sessions SET consecutive_denials=0 WHERE jti=?", (jti,))
                result = execute(cfg.docs_dir, conn, body.tool, body.query, decision.asset_id)
                audit.append(conn, "TOOL_CALL", principal=principal, jti=jti, tool=body.tool,
                             decision="ALLOW", reason=decision.reason, query=body.query)
                return {"decision": "ALLOW", "result": result}

            revoked = False
            if decision.suspicious:
                conn.execute("UPDATE sessions SET consecutive_denials=consecutive_denials+1,"
                             "total_denials=total_denials+1 WHERE jti=?", (jti,))
                n = conn.execute("SELECT consecutive_denials FROM sessions WHERE jti=?",
                                 (jti,)).fetchone()[0]
                revoked = n >= cfg.tripwire_threshold
            audit.append(conn, "TOOL_CALL", principal=principal, jti=jti, tool=body.tool,
                         decision="BLOCK", reason=decision.reason, query=body.query)
            if revoked:
                conn.execute("INSERT INTO revoked_tokens VALUES(?,?,?)",
                             (jti, _now(), "tripwire: consecutive authorisation violations"))
                audit.append(conn, "TRIPWIRE_REVOKE", principal=principal, jti=jti,
                             decision="REVOKE",
                             reason=f"{cfg.tripwire_threshold} consecutive violations")
            return JSONResponse({"decision": "BLOCK", "reason": decision.reason,
                                 "session_revoked": revoked}, status_code=403)

    # ---- operator-only endpoints (never reachable with an agent token) ----
    @app.post("/admin/token")
    def admin_token(body: TokenBody, deny=Depends(require_admin), conn=Depends(get_conn)):
        if deny:
            return deny
        row = conn.execute("SELECT disabled FROM principals WHERE id=?", (body.principal,)).fetchone()
        if row is None or row["disabled"]:
            return JSONResponse({"detail": "unknown or disabled principal"}, status_code=404)
        token, jti = tokens.issue(cfg.jwt_secret, body.principal, cfg.token_ttl_seconds)
        with tx(conn):
            conn.execute("INSERT INTO sessions(jti, principal, issued_at) VALUES(?,?,?)",
                         (jti, body.principal, _now()))
            audit.append(conn, "TOKEN_ISSUED", principal=body.principal, jti=jti)
        return {"token": token, "jti": jti, "expires_in": cfg.token_ttl_seconds}

    @app.post("/admin/revoke")
    def admin_revoke(body: RevokeBody, deny=Depends(require_admin), conn=Depends(get_conn)):
        if deny:
            return deny
        with tx(conn):
            if body.jti:
                jtis = [body.jti]
            elif body.principal:
                jtis = [r[0] for r in conn.execute(
                    "SELECT jti FROM sessions WHERE principal=?", (body.principal,))]
            else:
                return JSONResponse({"detail": "jti or principal required"}, status_code=422)
            for j in jtis:
                conn.execute("INSERT OR IGNORE INTO revoked_tokens VALUES(?,?,?)",
                             (j, _now(), "operator revocation"))
                audit.append(conn, "OPERATOR_REVOKE", jti=j, decision="REVOKE",
                             reason="operator revocation")
        return {"revoked": len(jtis)}

    @app.post("/admin/permissions/grant")
    def grant(body: PermBody, deny=Depends(require_admin), conn=Depends(get_conn)):
        if deny:
            return deny
        with tx(conn):
            conn.execute("INSERT OR IGNORE INTO permissions VALUES(?,?,?)",
                         (body.role, body.tool, body.resource_class))
            audit.append(conn, "POLICY_CHANGE", decision="GRANT",
                         reason=f"{body.role}:{body.tool}:{body.resource_class}")
        return {"ok": True}

    @app.post("/admin/permissions/revoke")
    def revoke_perm(body: PermBody, deny=Depends(require_admin), conn=Depends(get_conn)):
        if deny:
            return deny
        with tx(conn):
            conn.execute("DELETE FROM permissions WHERE role=? AND tool=? AND resource_class=?",
                         (body.role, body.tool, body.resource_class))
            audit.append(conn, "POLICY_CHANGE", decision="REVOKE",
                         reason=f"{body.role}:{body.tool}:{body.resource_class}")
        return {"ok": True}

    @app.get("/admin/audit/verify")
    def audit_verify(deny=Depends(require_admin), conn=Depends(get_conn)):
        if deny:
            return deny
        ok, n, bad = audit.verify_chain(conn)
        return {"ok": ok, "rows": n, "first_bad_seq": bad}

    return app
