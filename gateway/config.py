"""Gateway configuration. Secrets come from the gateway's own environment only."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    db_path: str
    docs_dir: str
    jwt_secret: str
    admin_key: str
    token_ttl_seconds: int = 900
    tripwire_threshold: int = 3

    @classmethod
    def from_env(cls) -> "Config":
        secret = os.environ.get("GATEWAY_JWT_SECRET", "")
        admin = os.environ.get("GATEWAY_ADMIN_KEY", "")
        if len(secret) < 32 or len(admin) < 16:
            raise RuntimeError(
                "Set GATEWAY_JWT_SECRET (>=32 chars) and GATEWAY_ADMIN_KEY (>=16 chars) "
                "in the gateway's environment, e.g. `openssl rand -hex 32`. "
                "There is deliberately no default secret."
            )
        return cls(
            db_path=os.environ.get("GATEWAY_DB", "gateway.db"),
            docs_dir=os.environ.get("GATEWAY_DOCS_DIR", "docs"),
            jwt_secret=secret,
            admin_key=admin,
            token_ttl_seconds=int(os.environ.get("GATEWAY_TOKEN_TTL", "900")),
            tripwire_threshold=int(os.environ.get("GATEWAY_TRIPWIRE_THRESHOLD", "3")),
        )
