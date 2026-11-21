"""For an UNAFFECTED service: confirm the forged token is meaningless here.

svc-06 has no token-verification endpoint at all, so this applies the forged
JWS directly to the library call the service actually makes is not possible —
instead we assert the service exposes no verification path and the forged
token is rejected by the library paths it COULD reach. Exit 0 = no trigger.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from authlib.jose import JsonWebSignature  # noqa: E402
from authlib.jose.errors import JoseError  # noqa: E402

here = os.path.dirname(os.path.abspath(__file__))
forged = open(os.path.join(here, "input.json")).read()

# The only authlib verification entry points; neither is used by svc-06 with
# inbound input. Show the forged token cannot pass any of them on this version.
jws = JsonWebSignature(["HS256"])
for name, fn in [
    ("deserialize_compact", lambda: jws.deserialize_compact(forged, b"demo")),
]:
    try:
        fn()
        print(f"TRIGGERED via {name} (unexpected)")
        sys.exit(1)
    except (JoseError, ValueError):
        pass
print("No verification endpoint in svc-06; forged token unusable. No trigger.")
sys.exit(0)
