"""Starts a real gateway process (separate PID, localhost HTTP) for benchmarks."""
from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import httpx
import jwt

ROOT = Path(__file__).resolve().parent.parent


class GatewayProcess:
    def __init__(self, docs_src: Path = ROOT / "docs", threshold: int = 3):
        self.tmp = Path(tempfile.mkdtemp(prefix="gw_bench_"))
        self.docs = self.tmp / "docs"
        shutil.copytree(docs_src, self.docs)
        self.secret = secrets.token_hex(32)
        self.admin_key = secrets.token_hex(16)
        s = socket.socket(); s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]; s.close()
        self.url = f"http://127.0.0.1:{self.port}"
        env = {**os.environ, "GATEWAY_JWT_SECRET": self.secret, "GATEWAY_ADMIN_KEY": self.admin_key,
               "GATEWAY_DB": str(self.tmp / "gw.db"), "GATEWAY_DOCS_DIR": str(self.docs),
               "GATEWAY_PORT": str(self.port), "GATEWAY_TRIPWIRE_THRESHOLD": str(threshold)}
        self.proc = subprocess.Popen([sys.executable, "-m", "gateway.serve"], cwd=ROOT, env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.admin = httpx.Client(base_url=self.url, headers={"X-Admin-Key": self.admin_key}, timeout=5)
        for _ in range(100):
            try:
                if httpx.get(self.url + "/health", timeout=1).status_code == 200:
                    return
            except httpx.HTTPError:
                time.sleep(0.1)
        raise RuntimeError("gateway did not start")

    def token(self, principal: str) -> tuple[str, str]:
        r = self.admin.post("/admin/token", json={"principal": principal}); r.raise_for_status()
        return r.json()["token"], r.json()["jti"]

    def revoke(self, jti: str) -> None:
        self.admin.post("/admin/revoke", json={"jti": jti}).raise_for_status()

    def verify_audit(self) -> dict:
        return self.admin.get("/admin/audit/verify").json()

    def forge(self, mode: str, principal: str) -> str | None:
        """Token for an attack case. 'valid'/'revoked' are operator-issued; the rest are forgeries."""
        now = int(time.time())
        claims = {"iss": "ai-sec-gateway", "aud": "tool-gateway", "sub": "asset_admin",
                  "jti": uuid.uuid4().hex, "iat": now, "exp": now + 600}
        if mode == "none":
            return None
        if mode == "garbage":
            return "not.a.jwt"
        if mode == "alg_none":
            b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
            return f"{b({'alg': 'none', 'typ': 'JWT'})}.{b(claims)}."
        if mode == "wrong_secret":
            return jwt.encode(claims, secrets.token_hex(32), algorithm="HS256")
        if mode == "tampered":
            tok, _ = self.token("support_agent")
            h, _, sig = tok.split(".")
            payload = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
            payload["sub"] = "asset_admin"
            p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
            return f"{h}.{p}.{sig}"
        if mode == "expired":
            return jwt.encode({**claims, "sub": "support_agent", "iat": now - 900, "exp": now - 300},
                              self.secret, algorithm="HS256")
        if mode == "wrong_aud":
            return jwt.encode({**claims, "sub": "support_agent", "aud": "other-service"},
                              self.secret, algorithm="HS256")
        if mode == "ghost_principal":
            return jwt.encode({**claims, "sub": "ghost"}, self.secret, algorithm="HS256")
        if mode == "revoked":
            tok, jti = self.token(principal); self.revoke(jti); return tok
        return self.token(principal)[0]   # "valid"

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.admin.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


def load(name: str) -> list[dict]:
    path = ROOT / "bench" / "dataset" / f"{name}.jsonl"
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
