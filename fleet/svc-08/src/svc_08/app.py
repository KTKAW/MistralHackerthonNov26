"""svc-08 profiles — user profile API.

Entry point: GET /profile with `Authorization: Bearer <token>`. The bearer
token may be a compact JWS or a JSON-serialized JWS; the handler parses JSON
input and verifies it with JsonWebSignature.deserialize (dict input), which
routes to the library's JSON-serialization verification path.
"""
import json

from fastapi import FastAPI, Header, HTTPException
from authlib.jose import JsonWebSignature
from authlib.jose.errors import JoseError

from .config import SIGNING_KEY

app = FastAPI(title="svc-08 profiles")
jws = JsonWebSignature(["HS256"])


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/profile")
def profile(authorization: str = Header(...)):
    token = authorization.removeprefix("Bearer ").strip()
    try:
        if token.startswith("{"):
            obj = jws.deserialize(json.loads(token), SIGNING_KEY)
        else:
            obj = jws.deserialize_compact(token, SIGNING_KEY)
    except JoseError:
        raise HTTPException(status_code=401, detail="invalid token")
    claims = json.loads(obj.payload)
    return {"user": claims.get("sub"), "role": claims.get("role")}
