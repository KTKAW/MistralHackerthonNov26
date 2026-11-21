"""svc-03 webhooks — inbound payment webhook.

Entry point: POST /hooks/payment. The JSON body IS the provider's signed
payload: a JWS in (general) JSON serialization, verified with
JsonWebSignature.deserialize.
"""
import json

from fastapi import Body, FastAPI, HTTPException
from authlib.jose import JsonWebSignature
from authlib.jose.errors import JoseError

from .config import WEBHOOK_SIGNING_KEY

app = FastAPI(title="svc-03 webhooks")
jws = JsonWebSignature(["HS256"])


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/hooks/payment")
def payment_hook(body: dict = Body(...)):
    try:
        obj = jws.deserialize(body, WEBHOOK_SIGNING_KEY)
    except JoseError:
        raise HTTPException(status_code=401, detail="invalid webhook signature")
    return {"received": True, "event": json.loads(obj.payload)}
