from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path
from threading import Thread
from http.cookiejar import CookieJar
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor
from urllib.error import URLError

import pytest


@pytest.fixture(scope="module")
def web_server(tmp_path_factory: pytest.TempPathFactory) -> str:
    from csp.web.server import run_server

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    data_dir = tmp_path_factory.mktemp("csp-data")
    os.environ["CSP_DATA_DIR"] = str(data_dir)

    t = Thread(target=run_server, args=("127.0.0.1", port), daemon=True)
    t.start()
    time.sleep(0.3)

    return f"http://127.0.0.1:{port}"


class APIClient:
    def __init__(self, base: str):
        self.base = base
        self.cookiejar = CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.cookiejar))

    def _req(self, method: str, path: str, body: dict = None) -> dict:
        url = f"{self.base}{path}"
        data = json.dumps(body).encode("utf-8") if body else None
        req = Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with self.opener.open(req) as resp:
                raw = resp.read().decode("utf-8")
                if raw:
                    return json.loads(raw)
                return {}
        except URLError as e:
            if hasattr(e, "read"):
                try:
                    return json.loads(e.read().decode("utf-8"))
                except Exception:
                    return {"error": str(e)}
            return {"error": str(e)}

    def get(self, path: str) -> dict:
        return self._req("GET", path)

    def post(self, path: str, body: dict = None) -> dict:
        return self._req("POST", path, body)

    def put(self, path: str, body: dict = None) -> dict:
        return self._req("PUT", path, body)

    def delete(self, path: str, body: dict = None) -> dict:
        return self._req("DELETE", path, body)

    def login(self, username: str = "tester", password: str = "GoodPass1234!") -> None:
        self.post("/api/login", {"username": username, "password": password})

    def logout(self) -> None:
        self.post("/api/logout")


@pytest.fixture(scope="module")
def api(web_server: str) -> APIClient:
    client = APIClient(web_server)
    client.post("/api/setup", {
        "username": "tester",
        "password": "GoodPass1234!",
        "hint_question": "What is your pet name?",
        "hint_answer": "fluffy",
    })
    return client


def test_setup_status(api: APIClient):
    res = api.get("/api/setup/status")
    assert res.get("first_run") is False
    assert "tester" in res.get("users", [])


def test_login_bad_password(api: APIClient):
    res = api.post("/api/login", {"username": "tester", "password": "wrong"})
    assert "error" in res


def test_login_good_and_status(api: APIClient):
    api.login()
    res = api.get("/api/status")
    assert res.get("user") == "tester"
    api.logout()


def test_logout_clears_session(api: APIClient):
    api.login()
    res = api.get("/api/status")
    assert res.get("user") == "tester"
    api.logout()
    res = api.get("/api/status")
    assert res.get("user") is None


def test_vault_crud(api: APIClient):
    api.login()

    res = api.get("/api/vault/credentials")
    assert isinstance(res, list)

    res = api.post("/api/vault/credentials", {
        "title": "Test Site",
        "username": "alice",
        "password": "s3cret",
    })
    assert "error" not in res
    cred_id = res.get("id")
    assert cred_id is not None

    res = api.get(f"/api/vault/credentials/{cred_id}")
    assert res.get("title") == "Test Site"

    res = api.put(f"/api/vault/credentials/{cred_id}", {"title": "Updated Site"})
    assert res.get("title") == "Updated Site"

    res = api.delete(f"/api/vault/credentials/{cred_id}")
    assert res.get("status") == "ok"

    api.logout()


def test_vault_genpw(api: APIClient):
    api.login()
    res = api.get("/api/vault/genpw?length=20")
    assert "password" in res
    assert len(res["password"]) == 20
    api.logout()


def test_incidents(api: APIClient):
    api.login()

    res = api.post("/api/incidents", {"title": "Breach detected", "severity": "high"})
    assert "error" not in res
    inc_id = res.get("id")

    res = api.get("/api/incidents")
    assert any(i.get("id") == inc_id for i in res)

    res = api.post(f"/api/incidents/{inc_id}/close")
    assert res.get("status") == "closed"

    api.logout()


def test_static_file_served(web_server: str):
    req = Request(f"{web_server}/")
    with urlopen(req) as resp:
        html = resp.read().decode("utf-8")
    assert "<!DOCTYPE html>" in html
    assert "csp" in html


def test_404(api: APIClient):
    res = api.get("/api/nonexistent")
    assert "error" in res


def test_auth_required(api: APIClient):
    res = api.get("/api/vault/credentials")
    assert "error" in res


def test_password_change(api: APIClient):
    api.login()
    res = api.post("/api/passwd", {
        "old_password": "GoodPass1234!",
        "new_password": "NewStrongPw1!",
    })
    assert res.get("status") == "ok"
    api.logout()

    # Login with new password.
    res = api.post("/api/login", {"username": "tester", "password": "NewStrongPw1!"})
    assert res.get("status") == "ok"
    api.logout()
