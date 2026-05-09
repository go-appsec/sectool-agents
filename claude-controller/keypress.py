"""Spacebar listener for the controller's pause feature.

Opens /dev/tty in cbreak mode rather than touching sys.stdin so:
  - sys.stdin redirection (e.g. `< /dev/null`, CI) doesn't enable the feature
  - the Claude Agent SDK subprocess (which inherits stdout/stderr) isn't disturbed
  - cbreak state can't bleed into anyone else's stdin reads

Returns a stop() callable for the caller to invoke from the shutdown ladder
and an atexit hook so the terminal is always restored on crash.
"""

from __future__ import annotations

import asyncio
import atexit
import os
import sys
import termios
import tty
from typing import Callable


def start_spacebar_listener(
    loop: asyncio.AbstractEventLoop,
    on_space: Callable[[], None],
) -> Callable[[], None] | None:
    """Install a /dev/tty reader that calls on_space() for every space keypress.

    Returns a stop() callable, or None if no controlling TTY is available
    (caller should treat None as "pause feature disabled").
    """
    if not sys.stdin.isatty():
        return None
    try:
        tty_fd = os.open("/dev/tty", os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None

    try:
        old_attrs = termios.tcgetattr(tty_fd)
    except termios.error:
        os.close(tty_fd)
        return None

    try:
        tty.setcbreak(tty_fd)
    except termios.error:
        os.close(tty_fd)
        return None

    stopped = False

    def _restore() -> None:
        nonlocal stopped
        if stopped:
            return
        stopped = True
        try:
            loop.remove_reader(tty_fd)
        except (ValueError, OSError, RuntimeError):
            pass
        try:
            termios.tcsetattr(tty_fd, termios.TCSADRAIN, old_attrs)
        except termios.error:
            pass
        try:
            os.close(tty_fd)
        except OSError:
            pass

    atexit.register(_restore)

    def reader() -> None:
        try:
            data = os.read(tty_fd, 64)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            _restore()
            return
        if not data:
            return
        if b" " in data:
            try:
                on_space()
            except Exception:
                pass

    try:
        loop.add_reader(tty_fd, reader)
    except (NotImplementedError, RuntimeError):
        _restore()
        return None

    return _restore
