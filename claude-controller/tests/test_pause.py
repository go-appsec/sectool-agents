"""Tests for the spacebar pause feature.

Covers the pause gate (submit_query), the in-flight registry, the status
bar's TTY-detection no-op behaviour, and a regex audit that every
client.query call site routes through submit_query so the chokepoint
discipline holds across future edits.

Also covers the auto-engaged rate-limit pause: detection in
collect_worker_turn / run_phase_substep, idempotent engage, spacebar
override via toggle_pause, and substep retry once the gate clears.
"""

import ast
import asyncio
import os
import unittest

from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock

import controller
import runtime
import worker
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
        runtime._pause_gate = asyncio.Event()
        runtime._pause_gate.set()
        runtime._inflight = runtime.InflightRegistry()

    def test_gate_passes_when_unpaused(self):
        client = _RecorderClient()

        async def go():
            await runtime.submit_query(client, "hello")

        _run(go())
        self.assertEqual(client.queries, ["hello"])

    def test_gate_blocks_when_paused(self):
        client = _RecorderClient()

        async def go():
            runtime._pause_gate.clear()
            task = asyncio.create_task(runtime.submit_query(client, "hello"))
            # Give the task a chance to hit the gate.
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertEqual(client.queries, [])
            runtime._pause_gate.set()
            await task
            self.assertEqual(client.queries, ["hello"])

        _run(go())

    def test_resume_releases_all_waiters(self):
        clients = [_RecorderClient() for _ in range(5)]

        async def go():
            runtime._pause_gate.clear()
            tasks = [
                asyncio.create_task(runtime.submit_query(c, f"q{i}"))
                for i, c in enumerate(clients)
            ]
            await asyncio.sleep(0)
            for t in tasks:
                self.assertFalse(t.done())
            runtime._pause_gate.set()
            await asyncio.gather(*tasks)
            for i, c in enumerate(clients):
                self.assertEqual(c.queries, [f"q{i}"])

        _run(go())

    def test_toggle_pause_flips_event(self):
        # toggle_pause emits a log line in non-TTY mode; capture stdout to
        # keep test output clean.
        runtime._status_bar = runtime.StatusBar()  # fresh, not installed
        self.assertTrue(runtime._pause_gate.is_set())
        runtime.toggle_pause()
        self.assertFalse(runtime._pause_gate.is_set())
        runtime.toggle_pause()
        self.assertTrue(runtime._pause_gate.is_set())


class TestInflightRegistry(unittest.TestCase):
    def setUp(self) -> None:
        runtime._inflight = runtime.InflightRegistry()
        # Reset status bar so refresh() called by enter/exit is a no-op.
        runtime._status_bar = runtime.StatusBar()

    def test_enter_exit_round_trip(self):
        reg = runtime._inflight
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
        reg = runtime._inflight
        reg.exit(999)  # must not raise
        self.assertEqual(reg.count(), 0)

    def test_inflight_context_manager(self):
        reg = runtime._inflight

        async def go():
            async with runtime.inflight("director sub 1"):
                self.assertEqual(reg.snapshot(), ["director sub 1"])
            self.assertEqual(reg.count(), 0)

        _run(go())


class TestChokepointAudit(unittest.TestCase):
    """Guard rail: every client.query call must route through submit_query.

    Scans controller.py, worker.py, and runtime.py — the three modules that
    handle SDK clients. The single allowed call site is `submit_query`'s
    body in runtime.py.
    """

    def test_no_unwrapped_query_calls(self):
        pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        targets = ["controller.py", "worker.py", "runtime.py"]
        offending: list[str] = []
        for fname in targets:
            path = os.path.join(pkg_dir, fname)
            with open(path) as f:
                source = f.read()
            tree = ast.parse(source)

            # The submit_query body is the one allowed call site (only in runtime.py).
            submit_range: tuple[int, int] | None = None
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and node.name == "submit_query":
                    submit_range = (node.lineno, node.end_lineno or node.lineno)
                    break

            source_lines = source.splitlines()
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if not (isinstance(func, ast.Attribute) and func.attr == "query"):
                    continue
                target = func.value
                # Match `client.query(...)` or `<x>.client.query(...)`.
                is_bare = isinstance(target, ast.Name) and target.id == "client"
                is_attr = isinstance(target, ast.Attribute) and target.attr == "client"
                if not (is_bare or is_attr):
                    continue
                if submit_range and submit_range[0] <= node.lineno <= submit_range[1]:
                    continue
                offending.append(
                    f"{fname}:{node.lineno}: {source_lines[node.lineno - 1].strip()}",
                )

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
                runtime._rate_limited = False
                runtime._pause_gate.set()


def _reset_pause_state() -> None:
    runtime._pause_gate = asyncio.Event()
    runtime._pause_gate.set()
    runtime._rate_limited = False
    runtime._inflight = runtime.InflightRegistry()
    runtime._status_bar = runtime.StatusBar()


class TestRateLimitGate(unittest.TestCase):
    def setUp(self) -> None:
        _reset_pause_state()

    def test_engage_rate_limit_clears_gate(self):
        runtime.engage_rate_limit_pause("try again at 4:30pm")
        self.assertTrue(runtime._rate_limited)
        self.assertFalse(runtime._pause_gate.is_set())

    def test_engage_is_idempotent(self):
        runtime.engage_rate_limit_pause("first")
        runtime.engage_rate_limit_pause("second")
        self.assertTrue(runtime._rate_limited)
        self.assertFalse(runtime._pause_gate.is_set())

    def test_spacebar_clears_rate_limit_pause(self):
        runtime.engage_rate_limit_pause("rate-limited")
        self.assertTrue(runtime._rate_limited)
        runtime.toggle_pause()
        self.assertFalse(runtime._rate_limited)
        self.assertTrue(runtime._pause_gate.is_set())

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
            return await worker.collect_worker_turn(client, 1, 1, candidates)

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
        self.assertFalse(runtime._rate_limited)
        self.assertTrue(runtime._pause_gate.is_set())


if __name__ == "__main__":
    unittest.main()
