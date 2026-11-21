"""Suite for svc-04. Must pass on the vulnerable version (authlib 1.8.0) BEFORE any fix."""
import json

from fastapi.testclient import TestClient
from authlib.jose import JsonWebToken

from svc_04.app import app
from svc_04.config import SIGNING_KEY

client = TestClient(app)
jwt = JsonWebToken(["HS256"])


def legit_token():
    return jwt.encode(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "alice", "role": "user"},
        SIGNING_KEY,
    ).decode()


def test_health():
    assert client.get("/health").status_code == 200


def test_legit_token_accepted():
    r = client.get("/me", headers={"Authorization": f"Bearer {legit_token()}"})
    assert r.status_code == 200
    assert r.json()["user"] == "alice"


def test_garbage_rejected():
    r = client.get("/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401
