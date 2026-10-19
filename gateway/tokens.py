"""Short-lived signed session tokens (HS256 JWT). Revocation is server-side."""
from __future__ import annotations

import time
import uuid

import jwt

ISSUER = "ai-sec-gateway"
AUDIENCE = "tool-gateway"
_REQUIRED = ["exp", "iat", "sub", "jti", "iss", "aud"]


def issue(secret: str, principal: str, ttl_seconds: int) -> tuple[str, str]:
    now = int(time.time())
    jti = uuid.uuid4().hex
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": principal, "jti": jti,
              "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(claims, secret, algorithm="HS256"), jti


def verify(secret: str, token: str) -> dict:
    """Raises jwt.PyJWTError on any failure. `alg` is pinned: 'none' is rejected."""
    return jwt.decode(token, secret, algorithms=["HS256"], audience=AUDIENCE,
                      issuer=ISSUER, options={"require": _REQUIRED})
