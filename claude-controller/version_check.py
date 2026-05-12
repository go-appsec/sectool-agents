"""Sectool presence + best-effort staleness check at controller startup.

Missing-binary exits the process. Confirmed staleness exits only when the
caller passes ``fatal_on_stale=True`` (i.e. when the controller will spawn
sectool itself); in attach mode the result is logged and the controller
continues. Transient failures (network error, unparseable output) are
logged and ignored. The latest-release lookup hits the Go module proxy
directly so no local Go toolchain is required.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

import state
from runtime import log

TOOLBOX_MODULE = "github.com/go-appsec/toolbox"
INSTALL_COMMAND = f"go install {TOOLBOX_MODULE}/sectool@latest"

_PROXY_BASE_URL = "https://proxy.golang.org"
_STATE_KEY = "sectool_version_check"

_SUCCESS_TTL_SECONDS = 24 * 60 * 60
_FAILURE_TTL_SECONDS = 60 * 60
_SUBPROCESS_TIMEOUT_SECONDS = 5
_FETCH_TIMEOUT_SECONDS = 5

_CLEAN_VERSION = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
_VERSION_TOKEN = re.compile(r"\bv\d+\.\d+\.\d+\S*")

Version = tuple[int, int, int]


def run(sectool_bin: str, state_path: str, skip_version: bool, fatal_on_stale: bool) -> str:
    """Resolve sectool, exit if missing, run staleness check unless skipped.

    Returns the absolute path of the resolved binary. Exits(1) when no
    usable binary is found, or on a strictly newer release when
    ``fatal_on_stale`` is True. ``fatal_on_stale`` False downgrades a
    stale-binary result to a log line. Best-effort failures (network,
    parse) are logged and tolerated.
    """
    resolved = _resolve_or_exit(sectool_bin)

    if skip_version:
        return resolved

    installed = _read_installed_version(resolved)
    if installed is None:
        log("setup", "skipping sectool staleness check: installed version not a clean vX.Y.Z")
        return resolved

    latest = _latest_from_state_or_fetch(state_path, time.time())
    if latest is None:
        return resolved

    if installed >= latest:
        return resolved

    if fatal_on_stale:
        msg = (
            f"sectool {_version_str(installed)} installed; {_version_str(latest)} available.\n"
            f"Run: {INSTALL_COMMAND}\n"
            "(Use --skip-version-check to bypass.)"
        )
        print(msg, file=sys.stderr)
        sys.exit(1)
    log("setup", f"newer sectool available ({_version_str(installed)} -> {_version_str(latest)}); attached to running MCP so continuing. Install: {INSTALL_COMMAND}")
    return resolved


def _resolve_or_exit(sectool_bin: str) -> str:
    if os.path.isabs(sectool_bin):
        if os.path.isfile(sectool_bin):
            return sectool_bin
    else:
        resolved = shutil.which(sectool_bin)
        if resolved and os.path.isfile(resolved):
            return resolved
    log("setup", f"sectool binary not found: {sectool_bin!r}. Install with: {INSTALL_COMMAND}")
    sys.exit(1)


def _latest_from_state_or_fetch(state_path: str, now: float) -> Version | None:
    st = state.load(state_path)
    entry = st.get(_STATE_KEY)
    if isinstance(entry, dict) and not _expired(entry, now):
        if entry.get("status") == "ok":
            return _parse_version(entry.get("latest_version", ""))
        return None  # failure entry within TTL — skip silently

    latest = _fetch_latest()
    if latest is None:
        st[_STATE_KEY] = {"status": "failed", "checked_at": int(now)}
        state.save(state_path, st)
        return None
    st[_STATE_KEY] = {
        "latest_version": _version_str(latest),
        "checked_at": int(now),
        "status": "ok",
    }
    state.save(state_path, st)
    return latest


def _read_installed_version(sectool_bin: str) -> Version | None:
    try:
        result = subprocess.run(
            [sectool_bin, "--version"],
            capture_output=True, text=True,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    return _parse_installed_version(result.stdout or result.stderr)


def _fetch_latest() -> Version | None:
    url = f"{_PROXY_BASE_URL}/{TOOLBOX_MODULE}/@v/list"
    try:
        with urllib.request.urlopen(url, timeout=_FETCH_TIMEOUT_SECONDS) as resp:
            if resp.status // 100 != 2:
                log("setup", f"could not check sectool version: proxy status {resp.status}")
                return None
            body = resp.read(1 << 20).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        log("setup", f"could not check sectool version: {exc}")
        return None
    versions = _parse_available_versions(body)
    if not versions:
        log("setup", "could not check sectool version: no clean vX.Y.Z tags returned")
        return None
    return max(versions)


def _parse_installed_version(stdout: str) -> Version | None:
    match = _VERSION_TOKEN.search(stdout.strip())
    if not match:
        return None
    return _parse_version(match.group(0))


def _parse_available_versions(stdout: str) -> list[Version]:
    out: list[Version] = []
    for tok in stdout.split():
        v = _parse_version(tok)
        if v is not None:
            out.append(v)
    return out


def _parse_version(s: str) -> Version | None:
    m = _CLEAN_VERSION.match(s)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _version_str(v: Version) -> str:
    return f"v{v[0]}.{v[1]}.{v[2]}"


def _expired(entry: dict, now: float) -> bool:
    ttl = _SUCCESS_TTL_SECONDS if entry.get("status") == "ok" else _FAILURE_TTL_SECONDS
    try:
        return now - float(entry.get("checked_at", 0)) >= ttl
    except (TypeError, ValueError):
        return True
