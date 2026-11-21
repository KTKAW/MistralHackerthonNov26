"""svc-04 sessions — session API using compact JWTs only.

Entry point: GET /me with `Authorization: Bearer <compact JWT>`.
Verification goes through JsonWebToken.decode, which only accepts compact
serializations (2 dots) or compact JWE (4 dots). A JWS in JSON serialization
is rejected with DecodeError before any signature check runs, so the flawed
JSON path in the library is NOT reachable from this service.
"""
from fastapi import FastAPI, Header, HTTPException
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError

from .config import SIGNING_KEY

app = FastAPI(title="svc-04 sessions")
jwt = JsonWebToken(["HS256"])


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/me")
def me(authorization: str = Header(...)):
    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = jwt.decode(token, SIGNING_KEY)
        claims.validate()
    except JoseError:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"user": claims["sub"], "role": claims.get("role")}
