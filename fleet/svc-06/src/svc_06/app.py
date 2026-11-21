"""svc-06 oauth-client — outbound OAuth2 login redirector.

Entry point: GET /login. Uses authlib ONLY to build an OAuth2 authorization
redirect URL (RFC 6749 grant URI). It never verifies an inbound JWS, so the
flawed signature-check path in the library is not reachable from this service.
"""
from fastapi import FastAPI
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri

app = FastAPI(title="svc-06 oauth-client")

IDP_AUTHORIZE = "https://idp.example/authorize"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/login")
def login():
    url = prepare_grant_uri(
        IDP_AUTHORIZE,
        client_id="demo-client",
        redirect_uri="http://localhost:8006/callback",
        scope="profile email",
        state="demo-state",
        response_type="code",
    )
    return {"authorize_url": url}
