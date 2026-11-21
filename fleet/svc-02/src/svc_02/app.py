"""svc-02 billing — charge endpoint.

Entry point: POST /charge with `Authorization: Bearer <token>` and a JSON body.
The handler does NOT call any authlib function itself; it uses the
general-purpose wrapper `security.verify_bearer`.
"""
from fastapi import Body, FastAPI, Header, HTTPException

from .security import JoseError, verify_bearer

app = FastAPI(title="svc-02 billing")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/charge")
def charge(authorization: str = Header(...), body: dict = Body(...)):
    token = authorization.removeprefix("Bearer ")
    try:
        claims = verify_bearer(token)
    except JoseError:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"status": "charged", "user": claims.get("sub"), "amount": body.get("amount")}
