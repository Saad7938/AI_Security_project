"""Operator utility to mint a short-lived token through the gateway admin API.

Run from the repository root after starting the gateway:
    python scripts/issue_token.py support_agent

The gateway signing secret and admin key must stay in the gateway-side environment;
the agent receives only the returned token.
"""
from __future__ import annotations

import argparse
import os
import sys

import httpx
from dotenv import load_dotenv


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue a short-lived gateway token.")
    parser.add_argument("principal", help="Principal to issue a token for, e.g. support_agent")
    args = parser.parse_args()

    load_dotenv(".env.gateway")
    url = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8000").rstrip("/")
    admin_key = os.environ.get("GATEWAY_ADMIN_KEY")
    if not admin_key:
        parser.error("GATEWAY_ADMIN_KEY is missing; configure the gateway-side .env.gateway first")

    try:
        response = httpx.post(
            f"{url}/admin/token",
            json={"principal": args.principal},
            headers={"X-Admin-Key": admin_key},
            timeout=5.0,
        )
    except httpx.HTTPError as exc:
        print(f"Could not reach the gateway at {url}: {type(exc).__name__}", file=sys.stderr)
        return 1

    if response.is_error:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        print(f"Token issuance failed (HTTP {response.status_code}): {detail}", file=sys.stderr)
        return 1

    try:
        token = response.json()["token"]
    except (ValueError, KeyError, TypeError):
        print("Gateway returned an unexpected response; no token printed.", file=sys.stderr)
        return 1

    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
