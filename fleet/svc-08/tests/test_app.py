"""Suite for svc-08. Must pass on the vulnerable version (authlib 1.8.0) BEFORE any fix."""
import json

from fastapi.testclient import TestClient
from authlib.jose import JsonWebSignature

from svc_08.app import app
from svc_08.config import SIGNING_KEY

client = TestClient(app)
jws = JsonWebSignature(["HS256"])


def legit_compact():
    return jws.serialize_compact(
        {"alg": "HS256"}, json.dumps({"sub": "alice", "role": "user"}), SIGNING_KEY
    ).decode()


def test_health():
    assert client.get("/health").status_code == 200


def test_legit_compact_accepted():
    r = client.get("/profile", headers={"Authorization": f"Bearer {legit_compact()}"})
    assert r.status_code == 200
    assert r.json()["user"] == "alice"


def test_garbage_rejected():
    r = client.get("/profile", headers={"Authorization": "Bearer not-a-token"})
    assert r.status_code == 401
