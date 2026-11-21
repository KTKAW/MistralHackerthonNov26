"""Suite for svc-07. Must pass on the vulnerable version (authlib 1.8.0) BEFORE any fix."""
import json

from fastapi.testclient import TestClient
from authlib.jose import JsonWebSignature

from svc_07.app import app
from svc_07.config import SIGNING_KEY

client = TestClient(app)
jws = JsonWebSignature(["HS256"])


def test_health():
    assert client.get("/health").status_code == 200


def test_sign_roundtrip():
    r = client.post("/sign", json={"hello": "world"})
    assert r.status_code == 200
    token = r.json()["token"]
    # a downstream consumer verifies the compact token we produced
    obj = jws.deserialize_compact(token, SIGNING_KEY)
    assert json.loads(obj.payload) == {"hello": "world"}
