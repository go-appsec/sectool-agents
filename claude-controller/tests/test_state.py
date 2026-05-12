"""Unit tests for the shared state module."""

import os
import tempfile
import threading
import unittest

import state


class LoadTests(unittest.TestCase):
    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(state.load(os.path.join(d, "nope.json")), {})

    def test_corrupt_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.json")
            with open(path, "w") as f:
                f.write("not json")
            self.assertEqual(state.load(path), {})

    def test_non_object_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.json")
            with open(path, "w") as f:
                f.write("[1, 2, 3]")
            self.assertEqual(state.load(path), {})


class SaveTests(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.json")
            payload = {"sectool_version_check": {
                "latest_version": "v0.4.0",
                "checked_at": 1700000000,
                "status": "ok",
            }}
            state.save(path, payload)
            self.assertEqual(state.load(path), payload)

    def test_concurrent_save_never_corrupt(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.json")

            def writer(i):
                state.save(path, {"sectool_version_check": {
                    "latest_version": "v0.4.0",
                    "checked_at": 1700000000 + i,
                    "status": "ok",
                }})

            threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            loaded = state.load(path)
            self.assertIn("sectool_version_check", loaded)
            self.assertEqual(loaded["sectool_version_check"]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
