import shutil
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore", message=".*httpx.*starlette.*")
from fastapi.testclient import TestClient  # noqa: E402

from gateway.config import Config            # noqa: E402
from gateway.db import connect               # noqa: E402
from gateway.service import create_app       # noqa: E402

ADMIN = {"X-Admin-Key": "a" * 24}
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def cfg(tmp_path):
    shutil.copytree(ROOT / "docs", tmp_path / "docs")
    return Config(db_path=str(tmp_path / "gw.db"), docs_dir=str(tmp_path / "docs"),
                  jwt_secret="s" * 48, admin_key="a" * 24)


@pytest.fixture()
def client(cfg):
    return TestClient(create_app(cfg))


@pytest.fixture()
def conn(cfg, client):          # client fixture initialises the DB
    c = connect(cfg.db_path)
    yield c
    c.close()


def mint(client, principal):
    r = client.post("/admin/token", json={"principal": principal}, headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()["token"], r.json()["jti"]


def call(client, token, tool, query, headers=None):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/v1/invoke", json={"tool": tool, "query": query}, headers={**h, **(headers or {})})
