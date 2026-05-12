"""Persisted agent-wide state across runs.

Single JSON object on disk with per-feature top-level keys. New keys can be
added without migrations; missing keys read back as absent. Today the only
key is ``sectool_version_check`` (the staleness-check cache).
"""

from __future__ import annotations

import json
import os
import tempfile


def load(path: str) -> dict:
    """Return the dict at path; missing or corrupt files yield ``{}``."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (FileNotFoundError, OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def save(path: str, state: dict) -> None:
    """Write state to path atomically via tmp + rename."""
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=os.path.basename(path) + ".tmp-",
        dir=directory,
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp_path, path)
    except OSError:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
