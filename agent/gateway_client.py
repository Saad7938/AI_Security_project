"""HTTP client the agent uses for every tool call. Fails closed."""
from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class GatewayResult:
    decision: str            # ALLOW | BLOCK | REJECT | ERROR
    text: str
    session_revoked: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    def for_model(self) -> str:
        return self.text if self.allowed else f"BLOCKED: {self.text}"


class GatewayClient:
    def __init__(self, base_url: str, token: str | None, timeout: float = 5.0,
                 client: httpx.Client | None = None, extra_headers: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.extra_headers = extra_headers or {}
        self._http = client or httpx.Client(timeout=timeout)

    def invoke(self, tool: str, query: str) -> GatewayResult:
        headers = dict(self.extra_headers)
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            r = self._http.post(f"{self.base_url}/v1/invoke",
                                json={"tool": tool, "query": query}, headers=headers)
            body = r.json()
        except (httpx.HTTPError, ValueError) as exc:   # unreachable / garbage => deny
            return GatewayResult("ERROR", f"gateway unreachable or invalid response ({type(exc).__name__})")
        decision = body.get("decision", "ERROR")
        if decision == "ALLOW":
            return GatewayResult("ALLOW", body.get("result", ""))
        return GatewayResult(decision, body.get("reason", "denied"),
                             bool(body.get("session_revoked")))

    def close(self) -> None:
        self._http.close()
