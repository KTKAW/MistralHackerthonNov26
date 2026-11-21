"""Send the trigger message to every input-taking endpoint of ticket-mailer.

Usage: <app>/.venv/bin/python verify_trigger.py <app_dir>
Exit 0 if an OverflowError came out of the app or `mailparser` got loaded, else 1.
"""

import sys
from pathlib import Path
from urllib.parse import quote

RAW = ("Received: from x ([1.2.3.4]) by mx.victim.example; Tue, 7 Mar 292277026596 14:29:24 +0000\r\n"
       "Subject: hi\r\nFrom: a@example.test\r\n\r\nbody\r\n")

BASE = {
    "event": "reply",
    "recipient": "user@example.test",
    "agent_name": "Dana",
    "summary": "hello",
    "subject": "Re: hello",
    "status": "open",
}


def _is_overflow(exc: BaseException | None) -> bool:
    while exc is not None:
        if isinstance(exc, OverflowError):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def main() -> int:
    app_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    sys.path.insert(0, str(app_dir / "src"))

    from fastapi.testclient import TestClient
    from ticket_mailer.app import app

    loaded_on_import = "mailparser" in sys.modules
    calls = []

    # Raw body, under the content types a mail-handling endpoint might accept.
    for ctype in ("message/rfc822", "text/plain", "application/json", "application/octet-stream"):
        calls.append(("POST", "/tickets/1/notify", {"content": RAW.encode(), "headers": {"content-type": ctype}}))
    # Inside each JSON string field, for every event type.
    for event in ("created", "reply", "status_changed", "closed"):
        for field in BASE:
            payload = {**BASE, "event": event, field: RAW}
            calls.append(("POST", "/tickets/1/notify", {"json": payload}))
    # Path parameters.
    calls.append(("POST", f"/tickets/{quote(RAW, safe='')}/notify", {"json": BASE}))
    calls.append(("GET", f"/outbox/{quote(RAW, safe='')}", {}))
    # Read back everything that was queued.
    calls.append(("GET", "/outbox", {}))

    triggered = []
    with TestClient(app, raise_server_exceptions=True) as client:
        for method, url, kwargs in calls:
            try:
                client.request(method, url, **kwargs)
            except BaseException as exc:  # noqa: BLE001
                if _is_overflow(exc):
                    triggered.append(f"{method} {url[:40]} -> {type(exc).__name__}")
                else:
                    print(f"note: {method} {url[:40]} raised {type(exc).__name__}: {exc}", file=sys.stderr)
        for item in client.get("/outbox").json():
            calls.append(("GET", f"/outbox/{item['id']}", {}))
            try:
                client.get(f"/outbox/{item['id']}")
            except BaseException as exc:  # noqa: BLE001
                if _is_overflow(exc):
                    triggered.append(f"GET /outbox/{item['id']} -> {type(exc).__name__}")

    loaded = loaded_on_import or "mailparser" in sys.modules
    if triggered or loaded:
        print(f"TRIGGERED ({len(calls)} requests, {len(triggered)} OverflowError, "
              f"mailparser loaded={loaded}) {'; '.join(triggered[:3])}")
        return 0
    print(f"NOT TRIGGERED ({len(calls)} requests, mailparser not loaded)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
