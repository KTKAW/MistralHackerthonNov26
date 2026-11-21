"""Suite for svc-06. Must pass on the vulnerable version (authlib 1.8.0) BEFORE any fix."""
from fastapi.testclient import TestClient

from svc_06.app import app

client = TestClient(app)


def test_health():
    assert client.get("/health").status_code == 200


def test_login_redirect():
    r = client.get("/login")
    assert r.status_code == 200
    url = r.json()["authorize_url"]
    assert url.startswith("https://idp.example/authorize?")
    assert "client_id=demo-client" in url
    assert "state=demo-state" in url
    assert "response_type=code" in url
