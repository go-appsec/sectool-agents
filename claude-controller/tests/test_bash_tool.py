"""Unit tests for bash_tool.py — foreground dispatch, background tracking, kill_all."""

import asyncio
import os
import re
import signal
import unittest

from bash_tool import BashBackground, dispatch_bash

_BG_PID_RE = re.compile(r"pid (\d+)")
_BG_PATH_RE = re.compile(r"(stdout|stderr) log: (.+)\n")
_STOPPED_RE = re.compile(r"=== background process stopped")


def _extract(text):
    """Pull the pid and both log paths out of a background start message."""
    m = _BG_PID_RE.search(text)
    assert m is not None, text
    pid = int(m.group(1))
    matches = _BG_PATH_RE.findall(text)
    assert len(matches) == 2, text
    paths = {name: path for name, path in matches}
    return pid, paths["stdout"], paths["stderr"]


def _wait_stopped(path, timeout=5.0):
    """Poll a log file until the stopped line appears; return full contents."""
    import time

    deadline = time.monotonic() + timeout
    contents = ""
    while time.monotonic() < deadline:
        try:
            with open(path, "r", encoding="utf-8") as f:
                contents = f.read()
            if _STOPPED_RE.search(contents):
                return contents
        except OSError:
            pass
        time.sleep(0.01)
    raise AssertionError(f"stopped line never appeared in {path}: {contents!r}")


class TestBashBackground(unittest.TestCase):
    def test_logs_output_and_stopped_line(self):
        bg = BashBackground()
        text = bg.start("echo hello-bg")
        pid, stdout_path, stderr_path = _extract(text)

        stdout_log = _wait_stopped(stdout_path)
        self.assertIn("hello-bg", stdout_log)
        self.assertIn("stopped", stdout_log)
        self.assertIn("stopped", _wait_stopped(stderr_path))
        self.assertEqual(bg.active_count(), 0)

        # Process fully reaped
        with self.assertRaises(OSError):
            os.kill(pid, 0)

    def test_kill_all_terminates_process(self):
        bg = BashBackground()
        text = bg.start("tail -f /dev/null")
        pid, stdout_path, stderr_path = _extract(text)
        self.assertEqual(bg.active_count(), 1)

        # SIGKILL to the process group guarantees exit, so this returns promptly
        bg.kill_all()

        self.assertEqual(bg.active_count(), 0)
        with self.assertRaises(OSError):
            os.kill(pid, 0)
        self.assertIn("stopped", _wait_stopped(stdout_path))
        self.assertIn("stopped", _wait_stopped(stderr_path))

    def test_start_after_kill_all_rejected(self):
        bg = BashBackground()
        bg.kill_all()
        with self.assertRaises(RuntimeError):
            bg.start("echo nope")

    def test_kill_all_idempotent_empty(self):
        bg = BashBackground()
        bg.kill_all()
        bg.kill_all()
        self.assertEqual(bg.active_count(), 0)


class TestDispatchBash(unittest.TestCase):
    def test_returns_pid_and_log_paths(self):
        bg = BashBackground()
        res = asyncio.run(dispatch_bash(
            {"command": "echo bg-tool", "background": True}, bg,
        ))
        self.assertFalse(res.get("is_error"), res)
        text = res["content"][0]["text"]
        _, stdout_path, stderr_path = _extract(text)
        self.assertTrue(os.path.exists(stdout_path))
        self.assertTrue(os.path.exists(stderr_path))

        # echo already exited; kill_all is a fast no-kill join
        bg.kill_all()
        self.assertIn("stopped", _wait_stopped(stdout_path))

    def test_nil_tracker_rejects_background(self):
        res = asyncio.run(dispatch_bash(
            {"command": "echo hi", "background": True}, None,
        ))
        self.assertTrue(res["is_error"])
        self.assertIn("unavailable", res["content"][0]["text"])

    def test_foreground_unchanged(self):
        bg = BashBackground()
        res = asyncio.run(dispatch_bash({"command": "echo plain"}, bg))
        self.assertFalse(res.get("is_error"), res)
        self.assertIn("plain", res["content"][0]["text"])
        self.assertEqual(bg.active_count(), 0)

    def test_foreground_nonzero_exit_is_error(self):
        res = asyncio.run(dispatch_bash({"command": "exit 3"}, None))
        self.assertTrue(res["is_error"])
        self.assertIn("exit status 3", res["content"][0]["text"])

    def test_empty_command_rejected(self):
        res = asyncio.run(dispatch_bash({"command": "  "}, None))
        self.assertTrue(res["is_error"])
        self.assertIn("non-empty", res["content"][0]["text"])

    def test_signal_death_reports_signal(self):
        bg = BashBackground()
        text = bg.start("kill -TERM $$")
        _, stdout_path, _ = _extract(text)
        self.assertIn("SIGTERM", _wait_stopped(stdout_path))
        bg.kill_all()


if __name__ == "__main__":
    unittest.main()
