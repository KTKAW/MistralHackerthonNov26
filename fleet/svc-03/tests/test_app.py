"""Suite for svc-03. Must pass on the vulnerable version (authlib 1.8.0) BEFORE any fix."""
from fastapi.testclient import TestClient
from authlib.jose import JsonWebSignature

from svc_03.app import app
from svc_03.config import WEBHOOK_SIGNING_KEY

client = TestClient(app)
jws = JsonWebSignature(["HS256"])


def legit_body():
    # general JSON serialization WITH a real signature
    return jws.serialize_json(
        [{"protected": {"alg": "HS256"}, "header": {"kid": "wh"}}],
        {"event": "payment.succeeded", "id": "evt_1"},
        WEBHOOK_SIGNING_KEY,
    )


def test_health():
    assert client.get("/health").status_code == 200


def test_legit_webhook_accepted():
    r = client.post("/hooks/payment", json=legit_body())
    assert r.status_code == 200
    assert r.json()["event"]["id"] == "evt_1"


def test_garbage_rejected():
    r = client.post("/hooks/payment", json={"payload": "zzz"})
    assert r.status_code == 401
