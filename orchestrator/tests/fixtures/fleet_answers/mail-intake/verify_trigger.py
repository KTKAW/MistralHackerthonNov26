"""Post a message whose Received date has an out-of-range year to mail-intake's /inbound.

Usage:  <app>/.venv/bin/python verify_trigger.py <app_dir>

Prints one line and sets the exit code:
  TRIGGERED OverflowError     exit 0  -> the parse blew up with an error the app does not handle
  NOT TRIGGERED <status>      exit 1  -> the app answered normally
"""
import os
import sys

app_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
sys.path.insert(0, os.path.join(app_dir, "src"))

from fastapi.testclient import TestClient  # noqa: E402

from mail_intake.app import app  # noqa: E402

RAW = (
    b"Received: from x ([1.2.3.4]) by mx.victim.example; Tue, 7 Mar 292277026596 14:29:24 +0000\r\n"
    b"Subject: hi\r\n"
    b"From: a@example.test\r\n"
    b"To: support@example.test\r\n"
    b"\r\n"
    b"body\r\n"
)

try:
    response = TestClient(app, raise_server_exceptions=True).post("/inbound", content=RAW, headers={"Content-Type": "message/rfc822"})
except (OverflowError, OSError) as error:
    print("TRIGGERED", type(error).__name__)
    sys.exit(0)
if response.status_code >= 500:
    print("TRIGGERED", response.status_code)
    sys.exit(0)
print("NOT TRIGGERED", response.status_code)
sys.exit(1)
