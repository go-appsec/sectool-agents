"""Shared runtime primitives: logging, status bar, pause gate, submit_query.

Every module that drives the SDK shares this state. Worker code, phase drivers,
and the main loop all funnel billed submissions through `submit_query` so the
spacebar pause has exactly one chokepoint to gate.
"""

import asyncio
import atexit
import json
import shutil
import sys


def log(tag: str, msg: str) -> None:
    print(f"[{tag:<8s}] {msg}", flush=True)


def _short(s: str, n: int) -> str:
    s = s.strip()
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


# ---------------------------------------------------------------------------
# Pause gate, in-flight tracking, status bar
# ---------------------------------------------------------------------------
#
# Spacebar pause: every billed API submission goes through `submit_query`,
# which awaits `_pause_gate` before forwarding to the SDK. Toggling pause
# from the spacebar listener clears/sets the event, halting new turns while
# letting in-flight `receive_response()` loops drain naturally.
#
# `_inflight` records currently-draining turns so the status bar can show
# what is still finishing during pause.

_pause_gate: asyncio.Event = asyncio.Event()
_pause_gate.set()  # set = "go"; clear = "pause"

# Auto-engaged when an AssistantMessage arrives with error="rate_limit". Shares
# the same `_pause_gate` as the spacebar pause so callers don't need a second
# wait point. Cleared only by the user pressing space (manual override) — there
# is no auto-resume timer; rate-limit windows from Anthropic are typically on
# the order of an hour and there's no machine-readable retry-after on the SDK
# error literal.
_rate_limited: bool = False


class InflightRegistry:
    """Tracks currently-draining receive_response() loops by label."""

    def __init__(self) -> None:
        self._next_id = 0
        self._entries: dict[int, str] = {}

    def enter(self, label: str) -> int:
        self._next_id += 1
        self._entries[self._next_id] = label
        _status_bar.refresh()
        return self._next_id

    def exit(self, entry_id: int) -> None:
        if self._entries.pop(entry_id, None) is not None:
            _status_bar.refresh()

    def snapshot(self) -> list[str]:
        return list(self._entries.values())

    def count(self) -> int:
        return len(self._entries)


class _InflightContext:
    """Async context manager for in-flight tracking."""

    def __init__(self, label: str) -> None:
        self._label = label
        self._id: int | None = None

    async def __aenter__(self) -> "_InflightContext":
        self._id = _inflight.enter(self._label)
        return self

    async def __aexit__(self, *exc) -> bool:
        if self._id is not None:
            _inflight.exit(self._id)
        return False


def inflight(label: str) -> _InflightContext:
    return _InflightContext(label)


class StatusBar:
    """Bottom-row status line via ANSI scroll region. No-op when not a TTY."""

    def __init__(self) -> None:
        self._enabled = False
        self._paused = False
        self._rate_limited = False
        self._iteration = 0
        self._height = 0
        self._width = 0

    def install(self) -> None:
        if not sys.stdout.isatty():
            return
        try:
            size = shutil.get_terminal_size()
        except OSError:
            return
        if size.lines < 5:
            return
        self._height = size.lines
        self._width = size.columns
        # Scroll region rows 1..(H-1); row H is the static status line.
        sys.stdout.write(f"\033[1;{self._height - 1}r")
        # Move cursor inside scroll region so the next print lands above status.
        sys.stdout.write(f"\033[{self._height - 1};1H")
        sys.stdout.flush()
        self._enabled = True
        atexit.register(self._safe_uninstall)
        self.refresh()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _safe_uninstall(self) -> None:
        try:
            self.uninstall()
        except Exception:
            pass

    def uninstall(self) -> None:
        if not self._enabled:
            return
        self._enabled = False
        # Reset scroll region; clear status row; show cursor.
        sys.stdout.write("\033[r")
        sys.stdout.write(f"\033[{self._height};1H\033[2K")
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

    def set_paused(self, paused: bool) -> None:
        self._paused = paused
        self.refresh()

    def set_rate_limited(self, rate_limited: bool) -> None:
        self._rate_limited = rate_limited
        self.refresh()

    def set_iteration(self, iteration: int) -> None:
        self._iteration = iteration
        self.refresh()

    def refresh(self) -> None:
        if not self._enabled:
            return
        # Re-read size every refresh — automatic resize handling.
        try:
            size = shutil.get_terminal_size()
        except OSError:
            return
        if (size.lines, size.columns) != (self._height, self._width):
            self._height, self._width = size.lines, size.columns
            sys.stdout.write(f"\033[1;{self._height - 1}r")
            # Reposition cursor inside new scroll region so a shrink doesn't
            # leave it parked below the status row.
            sys.stdout.write(f"\033[{self._height - 1};1H")
        snapshot = _inflight.snapshot()
        count = len(snapshot)
        if self._rate_limited or self._paused:
            tag = "RATE-LIMITED" if self._rate_limited else "PAUSED"
            if count == 0:
                msg = f" [{tag} — space to resume] idle "
            else:
                labels = ", ".join(snapshot[:5])
                more = f" +{count - 5} more" if count > 5 else ""
                msg = f" [{tag} — space to resume] {count} turn(s) finishing: {labels}{more} "
        else:
            iter_part = f"iter {self._iteration}" if self._iteration else "starting"
            msg = f" [RUNNING] {iter_part} · in-flight={count} · space to pause "
        msg = msg[: max(0, self._width)]
        sys.stdout.write(
            "\0337"
            f"\033[{self._height};1H"
            "\033[2K"
            "\033[7m"
            f"{msg}"
            "\033[0m"
            "\0338"
        )
        sys.stdout.flush()


_status_bar: StatusBar = StatusBar()
_inflight: InflightRegistry = InflightRegistry()


def toggle_pause() -> None:
    """Flip the pause gate; called from the spacebar listener.

    Spacebar also clears an auto-engaged rate-limit pause: when the controller
    is paused due to a `rate_limit` response, pressing space resumes
    immediately rather than toggling into a deeper "manual + rate-limited"
    state. Resuming is the only thing the user can usefully do here, so the
    keypress maps to that.
    """
    global _rate_limited
    if _rate_limited:
        _rate_limited = False
        _pause_gate.set()
        _status_bar.set_rate_limited(False)
        if not _status_bar.enabled:
            log("rate-lim", "Resumed (manual override).")
        return
    if _pause_gate.is_set():
        _pause_gate.clear()
        _status_bar.set_paused(True)
        if not _status_bar.enabled:
            log("paused", f"Paused — {_inflight.count()} turn(s) finishing. Press space to resume.")
    else:
        _pause_gate.set()
        _status_bar.set_paused(False)
        if not _status_bar.enabled:
            log("paused", "Resumed.")


def engage_rate_limit_pause(assistant_text: str = "") -> None:
    """Auto-pause on rate_limit response; spacebar is the only resume."""
    global _rate_limited
    if _rate_limited:
        return  # already engaged; don't double-log
    _rate_limited = True
    _pause_gate.clear()
    _status_bar.set_rate_limited(True)
    snippet = _short(assistant_text.strip().replace("\n", " "), 160) if assistant_text else ""
    detail = f" — {snippet}" if snippet else ""
    log("rate-lim", f"Rate-limited{detail}. Press space to resume.")


async def _status_tick() -> None:
    """Periodic refresh so in-flight count decays visibly during pause."""
    try:
        while True:
            await asyncio.sleep(0.5)
            _status_bar.refresh()
    except asyncio.CancelledError:
        return


async def submit_query(client, prompt: str) -> None:
    """Pause-gated wrapper around client.query().

    Every billed API submission in this module routes through here so the
    spacebar pause has exactly one chokepoint to gate. The pause check
    happens before submission; once query() returns, the turn is committed
    and the receive_response loop must be allowed to finish.
    """
    await _pause_gate.wait()
    await client.query(prompt)


def _clear_leaked_cancellations(tag: str = "") -> int:
    """Drain leaked cancellations from the current asyncio task.

    The Claude Agent SDK is anyio-backed. When `asyncio.wait_for` cancels
    a `receive_response()` stream mid-flight, the SDK's internal anyio
    cancel scope can propagate cancellation onto the task that originally
    called `client.__aenter__()` — usually our main task. Left alone,
    subsequent awaits in that task raise `CancelledError` (even outside
    the SDK code path).

    Python 3.11+ exposes `Task.uncancel()` / `Task.cancelling()` to clear
    this. We drain the counter down to zero and return how many we cleared
    for logging. On older Pythons (no `uncancel`) we return 0 (best-effort
    — the fallback relies on teardown_worker skipping `__aexit__` on
    poisoned clients).
    """
    try:
        task = asyncio.current_task()
    except RuntimeError:
        return 0
    if task is None:
        return 0
    uncancel = getattr(task, "uncancel", None)
    cancelling = getattr(task, "cancelling", None)
    if not callable(uncancel) or not callable(cancelling):
        return 0
    cleared = 0
    while cancelling() > 0:
        uncancel()
        cleared += 1
    if cleared and tag:
        log(tag, f"Cleared {cleared} leaked cancel scope(s) on current task.")
    return cleared


def _summarize_input(tool_input: dict) -> str:
    try:
        serialized = json.dumps(tool_input, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        serialized = repr(tool_input)
    return _short(serialized, 240)


def _summarize_result(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return _short(content, 300)
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(repr(item))
        return _short("\n".join(parts), 300)
    return _short(repr(content), 300)
