"""Suite for svc-01. Must pass on the vulnerable version (authlib 1.8.0) BEFORE any fix."""
import json

from fastapi.testclient import TestClient
from authlib.jose import JsonWebSignature

from svc_01.app import app
from svc_01.config import SIGNING_KEY

client = TestClient(app)
jws = JsonWebSignature(["HS256"])


def legit_token():
    # general JSON serialization WITH a real signature
    return jws.serialize_json(
        [{"protected": {"alg": "HS256"}, "header": {"kid": "demo"}}],
        {"sub": "alice", "role": "user"},
        SIGNING_KEY,
    )


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_legit_token_accepted():
    r = client.post("/introspect", content=json.dumps(legit_token()))
    assert r.status_code == 200
    assert r.json()["claims"]["sub"] == "alice"


def test_garbage_rejected():
    r = client.post("/introspect", content="not-a-jws")
    assert r.status_code == 401
