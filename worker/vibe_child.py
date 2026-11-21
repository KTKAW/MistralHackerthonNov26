"""Stands between the worker and Vibe, so Vibe never outlives the worker. Standard library only.

    python vibe_child.py <parent pid> <command> [arguments...]

run_repo starts this in a new session, so this process leads its own process group and the command
(Vibe) lives in that group. It then does three things:

  - waits for the command and exits with its exit code (128 + N if signal N ended it);
  - passes SIGTERM and SIGINT on to the command;
  - checks twice a second that its parent is still the worker that started it. If the worker has
    died, even from `kill -9`, it stops the command (SIGTERM, then SIGKILL for the whole group).
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

GRACE_SECONDS = 10.0  # Vibe writes its export.json when it gets SIGTERM; give it time to do so


def main(argv: list[str]) -> int:
    parent = int(argv[1])
    child = subprocess.Popen(argv[2:])

    def forward(signum: int, _frame: object) -> None:
        try:
            child.send_signal(signum)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)

    orphaned_at = None
    while True:
        try:
            code = child.wait(timeout=0.5)
            break
        except subprocess.TimeoutExpired:
            pass
        if orphaned_at is None and os.getppid() != parent:
            orphaned_at = time.monotonic()
            forward(signal.SIGTERM, None)
        if orphaned_at is not None and time.monotonic() - orphaned_at > GRACE_SECONDS:
            child.kill()
    if orphaned_at is not None:
        # The worker is gone and nobody else will clean up. Whatever the command left running in
        # this process group goes too. The last signal also ends this process, which is fine.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            os.killpg(os.getpgrp(), signal.SIGTERM)
            time.sleep(1.0)
            os.killpg(os.getpgrp(), signal.SIGKILL)
        except OSError:
            pass
    return 128 - code if code < 0 else code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
