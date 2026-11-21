"""Check whether docs-portal can be made to redirect to another host.

Usage: <app>/.venv/bin/python verify_trigger.py <app_dir>
Exit 0 if any response redirects off-site (TRIGGERED), else 1.
"""

import asyncio
import http.client
import os
import sys
import threading
from urllib.parse import urlsplit

PROBES = [
    "/docs///other-site.example/x",
    "/docs/%2F%2Fother-site.example",
    "///other-site.example/x",
    "/%2F%2Fother-site.example",
    # each fixed redirect path with //other-site.example appended
    "///other-site.example",
    "/help//other-site.example",
    "/release-notes//other-site.example",
]


def off_site(location: str) -> bool:
    loc = location.strip().replace("\\", "/")
    if loc.startswith("//"):
        return True
    parts = urlsplit(loc)
    return bool(parts.scheme or parts.netloc)


def serve(app_dir: str):
    sys.path.insert(0, os.path.join(os.path.abspath(app_dir), "src"))
    import tornado.httpserver
    import tornado.netutil
    from docs_portal.app import make_app

    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    port = sockets[0].getsockname()[1]
    ready = threading.Event()

    def run():
        async def main():
            server = tornado.httpserver.HTTPServer(make_app())
            server.add_sockets(sockets)
            ready.set()
            await asyncio.Event().wait()

        asyncio.run(main())

    threading.Thread(target=run, daemon=True).start()
    ready.wait(10)
    return port


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_trigger.py <app_dir>")
        return 2
    port = serve(sys.argv[1])
    for path in PROBES:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", path)  # path sent verbatim; redirects not followed
        resp = conn.getresponse()
        resp.read()
        location = resp.getheader("Location")
        conn.close()
        if 300 <= resp.status < 400 and location and off_site(location):
            print(f"TRIGGERED {path} -> Location: {location}")
            return 0
    print(f"NOT TRIGGERED ({len(PROBES)} requests)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
