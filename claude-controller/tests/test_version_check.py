"""Unit tests for the sectool version-check helper."""

import http.server
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import state
import version_check as vc


class ParseInstalledVersionTests(unittest.TestCase):
    def test_clean_release(self):
        self.assertEqual(vc._parse_installed_version("sectool version v0.1.15"), (0, 1, 15))

    def test_git_suffix_rejected(self):
        self.assertIsNone(vc._parse_installed_version("sectool version v0.1.15-1-g1ae5950"))

    def test_devel_rejected(self):
        self.assertIsNone(vc._parse_installed_version("sectool version (devel)"))

    def test_empty_input(self):
        self.assertIsNone(vc._parse_installed_version(""))

    def test_trailing_newline(self):
        self.assertEqual(vc._parse_installed_version("sectool version v1.2.3\n"), (1, 2, 3))


class ParseAvailableVersionsTests(unittest.TestCase):
    def test_filters_to_clean(self):
        out = "v0.1.0\nv0.1.1\nv0.2.0-rc1\nv0.2.0\nv0.3.0\n"
        got = vc._parse_available_versions(out)
        self.assertEqual(got, [(0, 1, 0), (0, 1, 1), (0, 2, 0), (0, 3, 0)])

    def test_empty(self):
        self.assertEqual(vc._parse_available_versions(""), [])


class ExpiredTests(unittest.TestCase):
    def test_fresh_ok_not_expired(self):
        now = time.time()
        self.assertFalse(vc._expired({"status": "ok", "checked_at": now - 3600}, now))

    def test_stale_ok_expired(self):
        now = time.time()
        self.assertTrue(vc._expired({"status": "ok", "checked_at": now - 25 * 3600}, now))

    def test_fresh_failure_not_expired(self):
        now = time.time()
        self.assertFalse(vc._expired({"status": "failed", "checked_at": now - 1800}, now))

    def test_stale_failure_expired(self):
        now = time.time()
        self.assertTrue(vc._expired({"status": "failed", "checked_at": now - 2 * 3600}, now))


class RunTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_path = os.path.join(self._tmp.name, "state.json")

    def _which_real(self, _name):
        path = os.path.join(self._tmp.name, "sectool")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(path, 0o755)
        return path

    def _fake_bin_path(self):
        return os.path.join(self._tmp.name, "sectool")

    def test_missing_binary_exits(self):
        with patch.object(vc.shutil, "which", return_value=None):
            with self.assertRaises(SystemExit) as cm:
                vc.run("sectool", self.state_path, skip_version=False, fatal_on_stale=True)
            self.assertEqual(cm.exception.code, 1)

    def test_skip_version_bypasses_staleness(self):
        with patch.object(vc.shutil, "which", side_effect=self._which_real), \
                patch.object(vc, "_read_installed_version") as read_mock, \
                patch.object(vc, "_fetch_latest") as fetch_mock:
            resolved = vc.run("sectool", self.state_path, skip_version=True, fatal_on_stale=True)
            self.assertEqual(resolved, self._fake_bin_path())
            read_mock.assert_not_called()
            fetch_mock.assert_not_called()

    def test_dirty_installed_skips_silently(self):
        with patch.object(vc.shutil, "which", side_effect=self._which_real), \
                patch.object(vc, "_read_installed_version", return_value=None), \
                patch.object(vc, "_fetch_latest") as fetch_mock:
            resolved = vc.run("sectool", self.state_path, skip_version=False, fatal_on_stale=True)
            self.assertEqual(resolved, self._fake_bin_path())
            fetch_mock.assert_not_called()

    def test_up_to_date_passes(self):
        with patch.object(vc.shutil, "which", side_effect=self._which_real), \
                patch.object(vc, "_read_installed_version", return_value=(0, 4, 0)), \
                patch.object(vc, "_fetch_latest", return_value=(0, 4, 0)):
            resolved = vc.run("sectool", self.state_path, skip_version=False, fatal_on_stale=True)
            self.assertEqual(resolved, self._fake_bin_path())

    def test_absolute_path_preferred_without_path_lookup(self):
        # absolute path that exists: returned directly, shutil.which never called
        bin_path = self._which_real(None)
        with patch.object(vc.shutil, "which") as which_mock, \
                patch.object(vc, "_read_installed_version", return_value=(0, 4, 0)), \
                patch.object(vc, "_fetch_latest", return_value=(0, 4, 0)):
            resolved = vc.run(bin_path, self.state_path, skip_version=False, fatal_on_stale=True)
            self.assertEqual(resolved, bin_path)
            which_mock.assert_not_called()

    def test_absolute_path_missing_exits_without_path_lookup(self):
        missing = os.path.join(self._tmp.name, "nope")
        with patch.object(vc.shutil, "which") as which_mock:
            with self.assertRaises(SystemExit) as cm:
                vc.run(missing, self.state_path, skip_version=False, fatal_on_stale=True)
            self.assertEqual(cm.exception.code, 1)
            which_mock.assert_not_called()

    def test_stale_fatal_exits_with_install_command(self):
        with patch.object(vc.shutil, "which", side_effect=self._which_real), \
                patch.object(vc, "_read_installed_version", return_value=(0, 3, 1)), \
                patch.object(vc, "_fetch_latest", return_value=(0, 4, 0)):
            with self.assertRaises(SystemExit) as cm:
                vc.run("sectool", self.state_path, skip_version=False, fatal_on_stale=True)
            self.assertEqual(cm.exception.code, 1)

    def test_stale_nonfatal_logs_only(self):
        with patch.object(vc.shutil, "which", side_effect=self._which_real), \
                patch.object(vc, "_read_installed_version", return_value=(0, 3, 1)), \
                patch.object(vc, "_fetch_latest", return_value=(0, 4, 0)), \
                patch.object(vc, "log") as log_mock:
            vc.run("sectool", self.state_path, skip_version=False, fatal_on_stale=False)
            log_mock.assert_called_once()
            msg = log_mock.call_args.args[1]
            self.assertIn("newer sectool available", msg)
            self.assertIn("v0.3.1", msg)
            self.assertIn("v0.4.0", msg)

    def test_fetch_failure_continues_silently_and_caches(self):
        with patch.object(vc.shutil, "which", side_effect=self._which_real), \
                patch.object(vc, "_read_installed_version", return_value=(0, 3, 1)), \
                patch.object(vc, "_fetch_latest", return_value=None):
            vc.run("sectool", self.state_path, skip_version=False, fatal_on_stale=True)

        st = state.load(self.state_path)
        self.assertEqual(st["sectool_version_check"]["status"], "failed")

    def test_cache_hit_avoids_fetch(self):
        state.save(self.state_path, {"sectool_version_check": {
            "status": "ok", "latest_version": "v0.4.0", "checked_at": int(time.time()),
        }})

        with patch.object(vc.shutil, "which", side_effect=self._which_real), \
                patch.object(vc, "_read_installed_version", return_value=(0, 4, 0)), \
                patch.object(vc, "_fetch_latest") as fetch_mock:
            vc.run("sectool", self.state_path, skip_version=False, fatal_on_stale=True)
            fetch_mock.assert_not_called()

    def test_failure_cache_within_ttl_skips_refetch(self):
        state.save(self.state_path, {"sectool_version_check": {
            "status": "failed", "checked_at": int(time.time() - 1800),
        }})

        with patch.object(vc.shutil, "which", side_effect=self._which_real), \
                patch.object(vc, "_read_installed_version", return_value=(0, 0, 1)), \
                patch.object(vc, "_fetch_latest") as fetch_mock:
            vc.run("sectool", self.state_path, skip_version=False, fatal_on_stale=True)
            fetch_mock.assert_not_called()


class ReadInstalledVersionTests(unittest.TestCase):
    def test_returncode_nonzero_returns_none(self):
        with patch.object(vc.subprocess, "run") as run_mock:
            run_mock.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="err")
            self.assertIsNone(vc._read_installed_version("/fake/sectool"))

    def test_timeout_returns_none(self):
        with patch.object(vc.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=5)):
            self.assertIsNone(vc._read_installed_version("/fake/sectool"))

    def test_missing_binary_returns_none(self):
        with patch.object(vc.subprocess, "run", side_effect=FileNotFoundError):
            self.assertIsNone(vc._read_installed_version("/fake/sectool"))


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    body = b"v0.1.0\nv0.2.0\nv0.3.0-rc1\nv0.4.0\n"
    status = 200

    def do_GET(self):
        if self.path != f"/{vc.TOOLBOX_MODULE}/@v/list":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(self.status)
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *_args):
        pass


class FetchLatestTests(unittest.TestCase):
    def _serve(self, status: int = 200, body: bytes | None = None):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        class Handler(_ProxyHandler):
            pass

        Handler.status = status
        if body is not None:
            Handler.body = body
        srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        # cleanup runs LIFO: server_close -> join -> shutdown
        self.addCleanup(srv.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{port}"

    def test_returns_max_clean_version(self):
        base = self._serve()
        with patch.object(vc, "_PROXY_BASE_URL", base):
            self.assertEqual(vc._fetch_latest(), (0, 4, 0))

    def test_non_2xx_returns_none(self):
        base = self._serve(status=500)
        with patch.object(vc, "_PROXY_BASE_URL", base):
            self.assertIsNone(vc._fetch_latest())

    def test_empty_body_returns_none(self):
        base = self._serve(body=b"")
        with patch.object(vc, "_PROXY_BASE_URL", base):
            self.assertIsNone(vc._fetch_latest())


if __name__ == "__main__":
    unittest.main()
