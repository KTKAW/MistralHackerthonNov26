"""Check whether link-redirector redirects /legacy///other-site.example/x off-site.

Usage: <app>/.venv/bin/python verify_trigger.py <app_dir>
Exit 0 if the response redirects to a Location starting with "//", else 1.
"""

import asyncio
import sys
from pathlib import Path

PATH = "/legacy///other-site.example/x"


async def probe(app_dir: Path) -> int:
    sys.path.insert(0, str(app_dir / "src"))
    import tornado.httpclient
    import tornado.httpserver
    import tornado.testing

    from link_redirector.app import make_app
    from link_redirector.config import Settings

    sock, port = tornado.testing.bind_unused_port()
    server = tornado.httpserver.HTTPServer(make_app(Settings()))
    server.add_sockets([sock])
    client = tornado.httpclient.AsyncHTTPClient()
    try:
        response = await client.fetch(
            f"http://127.0.0.1:{port}{PATH}", follow_redirects=False, raise_error=False
        )
    finally:
        server.stop()
        client.close()

    location = response.headers.get("Location", "")
    if 300 <= response.code < 400 and location.startswith("//"):
        print(f"TRIGGERED {response.code} Location: {location}")
        return 0
    print(f"NOT TRIGGERED {response.code}")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: verify_trigger.py <app_dir>", file=sys.stderr)
        sys.exit(2)
    sys.exit(asyncio.run(probe(Path(sys.argv[1]).resolve())))
