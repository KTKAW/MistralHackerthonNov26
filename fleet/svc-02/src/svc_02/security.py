"""Generic bearer-token verification helper (shared utility)."""
import json

from authlib.jose import JsonWebSignature
from authlib.jose.errors import JoseError

from .config import SIGNING_KEY

_jws = JsonWebSignature(["HS256"])


def verify_bearer(token: str) -> dict:
    """Verify a bearer token and return its claims.

    General-purpose verifier: accepts any JWS serialization the library
    supports (compact or JSON).
    """
    obj = _jws.deserialize(token.strip(), SIGNING_KEY)
    return json.loads(obj.payload)


__all__ = ["verify_bearer", "JoseError"]
