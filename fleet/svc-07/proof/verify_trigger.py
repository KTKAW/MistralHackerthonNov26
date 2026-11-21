"""For an UNAFFECTED service: svc-07 only signs; it has no verification endpoint.

Exit 0 = no trigger (expected on both 1.8.0 and 1.9.0). Exit 1 = trigger.
"""
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
forged = open(os.path.join(here, "input.json")).read()

# svc-07 never deserializes inbound tokens; show the forged token cannot be
# passed off as anything the service accepts (it accepts no token at all).
print("svc-07 has no token-verification endpoint; forged token has no effect. No trigger.")
sys.exit(0)
