"""Tests for the spacebar pause feature.

Covers the pause gate (submit_query), the in-flight registry, the status
bar's TTY-detection no-op behaviour, and a regex audit that every
client.query call site routes through submit_query so the chokepoint
discipline holds across future edits.
"""

import asyncio
import os
import re
import unittest

import controller


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


if __name__ == "__main__":
    unittest.main()
