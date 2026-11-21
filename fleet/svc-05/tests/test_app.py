"""Suite for svc-05. Must pass on the vulnerable version (authlib 1.8.0) BEFORE any fix."""
import json

from fastapi.testclient import TestClient
from authlib.jose import JsonWebSignature

from svc_05.app import app
from svc_05.config import SIGNING_KEY

client = TestClient(app)
jws = JsonWebSignature(["HS256"])


def legit_token():
    return jws.serialize_compact(
        {"alg": "HS256"}, json.dumps({"sub": "alice"}), SIGNING_KEY
    ).decode()


def test_health():
    assert client.get("/health").status_code == 200


def test_legit_token_accepted():
    r = client.post("/verify", headers={"Authorization": f"Bearer {legit_token()}"})
    assert r.status_code == 200
    assert r.json()["claims"]["sub"] == "alice"


def test_garbage_rejected():
    r = client.post("/verify", headers={"Authorization": "Bearer not-a-jws"})
    assert r.status_code == 401
