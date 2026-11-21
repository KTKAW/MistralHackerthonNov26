"""svc-01 gateway — token introspection service.

Entry point: POST /introspect with a JWS in JSON serialization as the raw body.
The token is verified directly with JsonWebSignature.deserialize_json.
"""
import json

from fastapi import FastAPI, Request, Response
from authlib.jose import JsonWebSignature
from authlib.jose.errors import JoseError

from .config import SIGNING_KEY

app = FastAPI(title="svc-01 gateway")
jws = JsonWebSignature(["HS256"])


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/introspect")
async def introspect(request: Request):
    raw = (await request.body()).decode()
    try:
        obj = jws.deserialize_json(raw, SIGNING_KEY)
    except JoseError:
        return Response(status_code=401, content="invalid token")
    return {"valid": True, "claims": json.loads(obj.payload)}
