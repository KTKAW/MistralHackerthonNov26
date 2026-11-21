"""svc-05 legacy — legacy API key verification via compact JWS only.

Entry point: POST /verify with `Authorization: Bearer <compact JWS>`.
The service calls JsonWebSignature.deserialize_compact EXPLICITLY, so only
the compact serialization path is used; the flawed JSON-serialization path
(deserialize_json) is never invoked with attacker-controlled input.
"""
import json

from fastapi import FastAPI, Header, HTTPException
from authlib.jose import JsonWebSignature
from authlib.jose.errors import JoseError

from .config import SIGNING_KEY

app = FastAPI(title="svc-05 legacy")
jws = JsonWebSignature(["HS256"])


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/verify")
def verify(authorization: str = Header(...)):
    token = authorization.removeprefix("Bearer ").strip()
    try:
        obj = jws.deserialize_compact(token, SIGNING_KEY)
    except JoseError:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"valid": True, "claims": json.loads(obj.payload)}
