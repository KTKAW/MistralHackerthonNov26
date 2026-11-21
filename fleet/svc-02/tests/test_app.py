"""Suite for svc-02. Must pass on the vulnerable version (authlib 1.8.0) BEFORE any fix."""
import json

from fastapi.testclient import TestClient
from authlib.jose import JsonWebSignature

from svc_02.app import app
from svc_02.config import SIGNING_KEY

client = TestClient(app)
jws = JsonWebSignature(["HS256"])


def legit_token():
    # compact serialization WITH a real signature
    return jws.serialize_compact(
        {"alg": "HS256", "typ": "JWT"}, json.dumps({"sub": "alice"}), SIGNING_KEY
    )


def test_health():
    assert client.get("/health").status_code == 200


def test_legit_token_charges():
    r = client.post(
        "/charge",
        json={"amount": 100},
        headers={"Authorization": f"Bearer {legit_token().decode()}"},
    )
    assert r.status_code == 200
    assert r.json()["user"] == "alice"


def test_garbage_rejected():
    r = client.post(
        "/charge",
        json={"amount": 100},
        headers={"Authorization": "Bearer not-a-jws"},
    )
    assert r.status_code == 401
