"""Tests for the spacebar pause feature.

Covers the pause gate (submit_query), the in-flight registry, the status
bar's TTY-detection no-op behaviour, and a regex audit that every
client.query call site routes through submit_query so the chokepoint
discipline holds across future edits.

Also covers the auto-engaged rate-limit pause: detection in
collect_worker_turn / run_phase_substep, idempotent engage, spacebar
override via toggle_pause, and substep retry once the gate clears.
"""

import asyncio
import os
import re
import unittest

from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock

import controller
from tools import CandidatePool


def _run(coro):
    return asyncio.run(coro)


class _RecorderClient:
    """Minimal stand-in for ClaudeSDKClient.query."""

    def __init__(self) -> None:
        self.queries: list[str] = []

    async def query(self, prompt: str) -> None:
        self.queries.append(prompt)


class TestPauseGate(unittest.TestCase):
    def setUp(self) -> None:
        # Reset module-level state between tests.
        controller._pause_gate = asyncio.Event()
        controller._pause_gate.set()
        controller._inflight = controller.InflightRegistry()

    def test_gate_passes_when_unpaused(self):
        client = _RecorderClient()

        async def go():
            await controller.submit_query(client, "hello")

        _run(go())
        self.assertEqual(client.queries, ["hello"])

    def test_gate_blocks_when_paused(self):
        client = _RecorderClient()

        async def go():
            controller._pause_gate.clear()
            task = asyncio.create_task(controller.submit_query(client, "hello"))
            # Give the task a chance to hit the gate.
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertEqual(client.queries, [])
            controller._pause_gate.set()
            await task
            self.assertEqual(client.queries, ["hello"])

        _run(go())

    def test_resume_releases_all_waiters(self):
        clients = [_RecorderClient() for _ in range(5)]

        async def go():
            controller._pause_gate.clear()
            tasks = [
                asyncio.create_task(controller.submit_query(c, f"q{i}"))
                for i, c in enumerate(clients)
            ]
            await asyncio.sleep(0)
            for t in tasks:
                self.assertFalse(t.done())
            controller._pause_gate.set()
            await asyncio.gather(*tasks)
            for i, c in enumerate(clients):
                self.assertEqual(c.queries, [f"q{i}"])

        _run(go())

    def test_toggle_pause_flips_event(self):
        # toggle_pause emits a log line in non-TTY mode; capture stdout to
        # keep test output clean.
        controller._status_bar = controller.StatusBar()  # fresh, not installed
        self.assertTrue(controller._pause_gate.is_set())
        controller.toggle_pause()
        self.assertFalse(controller._pause_gate.is_set())
        controller.toggle_pause()
        self.assertTrue(controller._pause_gate.is_set())


class TestInflightRegistry(unittest.TestCase):
    def setUp(self) -> None:
        controller._inflight = controller.InflightRegistry()
        # Reset status bar so refresh() called by enter/exit is a no-op.
        controller._status_bar = controller.StatusBar()

    def test_enter_exit_round_trip(self):
        reg = controller._inflight
        self.assertEqual(reg.count(), 0)
        a = reg.enter("worker 1")
        b = reg.enter("verifier")
        self.assertEqual(reg.count(), 2)
        self.assertEqual(set(reg.snapshot()), {"worker 1", "verifier"})
        reg.exit(a)
        self.assertEqual(reg.snapshot(), ["verifier"])
        reg.exit(b)
        self.assertEqual(reg.count(), 0)

    def test_exit_with_unknown_id_is_safe(self):
        reg = controller._inflight
        reg.exit(999)  # must not raise
        self.assertEqual(reg.count(), 0)

    def test_inflight_context_manager(self):
        reg = controller._inflight

        async def go():
            async with controller.inflight("director sub 1"):
                self.assertEqual(reg.snapshot(), ["director sub 1"])
            self.assertEqual(reg.count(), 0)

        _run(go())


class TestStatusBarNoTTY(unittest.TestCase):
    def test_install_no_op_without_tty(self):
        # In unittest, sys.stdout is captured (not a TTY).
        bar = controller.StatusBar()
        bar.install()
        self.assertFalse(bar.enabled)
        # refresh() and uninstall() must be safe even when never installed.
        bar.refresh()
        bar.uninstall()


class TestChokepointAudit(unittest.TestCase):
    """Guard rail: every client.query call must route through submit_query."""

    def test_no_unwrapped_query_calls_in_controller(self):
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "controller.py",
        )
        with open(path) as f:
            source = f.read()

        # Strip out string literals and comments to avoid false positives
        # from docstrings / explanatory comments.
        stripped_lines = []
        for line in source.splitlines():
            code, _, _ = line.partition("#")
            stripped_lines.append(code)
        code_only = "\n".join(stripped_lines)
        # Collapse triple-quoted blocks (very rough but adequate here).
        code_only = re.sub(r'""".*?"""', '""', code_only, flags=re.DOTALL)
        code_only = re.sub(r"'''.*?'''", "''", code_only, flags=re.DOTALL)

        offending: list[str] = []
        for m in re.finditer(r"\b\w+\.client\.query\(|\bclient\.query\(", code_only):
            line_start = code_only.rfind("\n", 0, m.start()) + 1
            line_end = code_only.find("\n", m.end())
            line = code_only[line_start:line_end if line_end != -1 else len(code_only)]
            # The submit_query helper is the one allowed call site.
            if "await client.query(prompt)" in line:
                continue
            offending.append(line.strip())

        self.assertEqual(
            offending, [],
            "Found client.query call(s) bypassing submit_query — pause gate "
            "would leak. Wrap with submit_query(client, ...).",
        )


def _assistant(text: str, error: str | None = None) -> AssistantMessage:
    return AssistantMessage(content=[TextBlock(text=text)], model="claude", error=error)


def _result(cost: float | None = 0.0) -> ResultMessage:
    return ResultMessage(
        subtype="success" if cost is not None else "error",
        duration_ms=0,
        duration_api_ms=0,
        is_error=cost is None,
        num_turns=1,
        session_id="s",
        total_cost_usd=cost,
    )


class _ScriptedClient:
    """Fake ClaudeSDKClient that yields a scripted batch per query() call.

    Each call to query() pops the next batch off `batches`; receive_response()
    then yields that batch. Used for collect_worker_turn / _run_phase_substep
    drive-throughs without the real SDK.
    """

    def __init__(self, batches: list[list]) -> None:
        self._batches = list(batches)
        self.queries: list[str] = []
        self._current: list = []
        # When set, the client unblocks the rate-limit pause after yielding
        # the current batch — used by tests that expect the substep loop to
        # retry once the gate clears.
        self.auto_resume: bool = False

    async def query(self, prompt: str) -> None:
        self.queries.append(prompt)
        self._current = self._batches.pop(0) if self._batches else []

    async def receive_response(self):
        # `try/finally` is load-bearing: the substep loop `break`s on the
        # ResultMessage, which runs aclose() on this generator. Without the
        # finally, the auto-resume code below would never execute and the
        # retry test would deadlock waiting on the gate.
        try:
            for msg in self._current:
                yield msg
        finally:
            if self.auto_resume and self._batches:
                controller._rate_limited = False
                controller._pause_gate.set()


def _reset_pause_state() -> None:
    controller._pause_gate = asyncio.Event()
    controller._pause_gate.set()
    controller._rate_limited = False
    controller._inflight = controller.InflightRegistry()
    controller._status_bar = controller.StatusBar()


class TestRateLimitGate(unittest.TestCase):
    def setUp(self) -> None:
        _reset_pause_state()

    def test_engage_rate_limit_clears_gate(self):
        controller.engage_rate_limit_pause("try again at 4:30pm")
        self.assertTrue(controller._rate_limited)
        self.assertFalse(controller._pause_gate.is_set())

    def test_engage_is_idempotent(self):
        controller.engage_rate_limit_pause("first")
        controller.engage_rate_limit_pause("second")
        self.assertTrue(controller._rate_limited)
        self.assertFalse(controller._pause_gate.is_set())

    def test_spacebar_clears_rate_limit_pause(self):
        controller.engage_rate_limit_pause("rate-limited")
        self.assertTrue(controller._rate_limited)
        controller.toggle_pause()
        self.assertFalse(controller._rate_limited)
        self.assertTrue(controller._pause_gate.is_set())

    def test_collect_worker_turn_flags_rate_limited(self):
        client = _ScriptedClient([
            [
                _assistant("Service rate-limited; try again at 4:30pm.", error="rate_limit"),
                _result(cost=None),
            ],
        ])

        async def go():
            await client.query("ignored")
            candidates = CandidatePool()
            return await controller.collect_worker_turn(client, 1, 1, candidates)

        summary = _run(go())
        self.assertTrue(summary.rate_limited)
        self.assertIn("try again at 4:30pm", summary.rate_limit_text)

    def test_substep_retries_after_resume(self):
        """First batch is rate-limited, second succeeds; the substep loop
        must retry without the caller resending."""
        client = _ScriptedClient([
            [
                _assistant("rate-limited; try again at 5:00pm", error="rate_limit"),
                _result(cost=None),
            ],
            [
                _assistant("verification done"),
                _result(cost=0.01),
            ],
        ])
        # The scripted client clears the gate after the first batch yields,
        # simulating a user pressing space to resume.
        client.auto_resume = True

        async def go():
            return await controller.run_phase_substep(
                client,
                "verify candidates",
                controller.PHASE_VERIFICATION,
                iteration=1,
                substep=1,
                verbose=False,
            )

        ok, cost = _run(go())
        self.assertTrue(ok)
        self.assertEqual(cost, 0.01)
        self.assertEqual(len(client.queries), 2)
        # Second submit reuses the same prompt.
        self.assertEqual(client.queries[0], client.queries[1])
        self.assertFalse(controller._rate_limited)
        self.assertTrue(controller._pause_gate.is_set())


if __name__ == "__main__":
    unittest.main()
