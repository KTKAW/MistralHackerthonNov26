"""svc-07 signer — outbound message signer.

Entry point: POST /sign. Signs an arbitrary payload with a compact JWS
(JsonWebSignature.serialize_compact) for downstream consumers. It never
DESERIALIZES untrusted input, so the flawed verification path is not
reachable from this service.
"""
import json

from fastapi import Body, FastAPI
from authlib.jose import JsonWebSignature

from .config import SIGNING_KEY

app = FastAPI(title="svc-07 signer")
jws = JsonWebSignature(["HS256"])


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/sign")
def sign(payload: dict = Body(...)):
    token = jws.serialize_compact({"alg": "HS256", "typ": "JWS"}, json.dumps(payload), SIGNING_KEY)
    return {"token": token.decode()}
