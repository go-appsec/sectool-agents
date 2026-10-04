"""Tests for MCP startup probe and readiness-wait semantics (issue 16).

Any received HTTP response counts as a running server; probing and the
readiness wait must never block the event loop.
"""

import asyncio
import http.server
import socket
import threading
import unittest
from contextlib import contextmanager

import controller


def _run(coro):
    return asyncio.run(coro)


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class _Handler(http.server.BaseHTTPRequestHandler):
    status = 200

    def do_GET(self):
        self.send_response(self.status)
        self.end_headers()

    def log_message(self, *_args):
        pass


@contextmanager
def _http_server(status: int):
    class Handler(_Handler):
        pass

    Handler.status = status
    srv = http.server.HTTPServer(("127.0.0.1", _free_port()), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        thread.join()
        srv.server_close()


class _FakeProc:
    """Duck-typed subprocess.Popen for wait_for_server."""

    def __init__(self, exit_code=None):
        self._exit_code = exit_code

    def poll(self):
        return self._exit_code


class IsServerRunningTests(unittest.TestCase):
    def test_error_status_counts_as_running(self):
        """A 405 from the streamable-HTTP endpoint still means attachable."""
        with _http_server(405) as port:
            self.assertTrue(_run(controller.is_server_running(port)))

    def test_ok_status_counts_as_running(self):
        with _http_server(200) as port:
            self.assertTrue(_run(controller.is_server_running(port)))

    def test_no_listener_reports_down(self):
        self.assertFalse(_run(controller.is_server_running(_free_port())))


class WaitForServerTests(unittest.TestCase):
    def test_returns_once_ready(self):
        with _http_server(200) as port:
            _run(controller.wait_for_server(port, _FakeProc()))

    def test_timeout_exits_fatal(self):
        # Closed port: probes fail fast; the deadline must end the wait.
        with self.assertRaises(SystemExit) as cm:
            _run(controller.wait_for_server(_free_port(), _FakeProc(), timeout=0.2))
        self.assertEqual(cm.exception.code, 1)

    def test_child_death_exits_fatal(self):
        proc = _FakeProc(exit_code=3)
        with self.assertRaises(SystemExit) as cm:
            _run(controller.wait_for_server(_free_port(), proc, timeout=5))
        self.assertEqual(cm.exception.code, 1)

    def test_yields_to_event_loop(self):
        """A concurrent task keeps ticking while the readiness wait runs."""

        async def body():
            ticked: list[bool] = []

            async def ticker():
                while True:
                    await asyncio.sleep(0.02)
                    ticked.append(True)

            task = asyncio.create_task(ticker())
            try:
                with self.assertRaises(SystemExit):
                    await controller.wait_for_server(
                        _free_port(), _FakeProc(), timeout=0.3,
                    )
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            return ticked

        self.assertTrue(_run(body()), "event loop starved during wait_for_server")


if __name__ == "__main__":
    unittest.main()
