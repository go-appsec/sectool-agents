"""Unrestricted `bash` tool plus background-process tracking.

Mirrors secagent's `orchestrator.BashBackground` / `BashToolDef`. Foreground
commands run via `bash -c` with stdout and stderr combined; backgrounded
commands run detached in their own process group with stdout and stderr in
os-level temp files. A stopped line is appended to both log files when a
background process exits or is killed, and `kill_all()` reaps everything when
the controller winds down.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import tempfile
import threading
import time
from typing import Any

from claude_agent_sdk import tool

from sdk_mcp import build_sdk_mcp_server


# Bounded kill_all wait so shutdown can never hang on a process stuck in
# uninterruptible sleep (D state ignores SIGKILL).
KILL_WAIT_TIMEOUT = 5.0

BASH_TOOL_DESCRIPTION = (
    "Execute an arbitrary shell command on the host running the controller via "
    "bash -c. There are no command restrictions. Stdout and stderr are returned "
    "combined; the result flags non-zero exit codes as errors. "
    "Set background=true only when necessary (a command that must outlive this "
    "call); it then returns the pid and stdout/stderr log file paths immediately. "
    "Use when the sectool tools cannot accomplish the task or the instruction "
    "calls for it."
)

BASH_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "command": {
            "type": "string",
            "description": "Shell command line to execute (interpreted by bash)",
        },
        "background": {
            "type": "boolean",
            "description": (
                "Run detached and return immediately with the pid plus "
                "stdout/stderr log file paths. Only use when necessary — when a "
                "command must outlive this tool call (long polls, listeners, "
                "servers). Tail the returned logs to review progress and kill "
                "the pid when done."
            ),
        },
    },
    "required": ["command"],
}

# Public allowed-tool name (use with ClaudeAgentOptions.allowed_tools).
BASH_TOOL_ALLOWED = "mcp__bash_tools__bash"

# Built-in CLI Bash tool name, denied on every client. Shell access runs through
# the tracked mcp__bash_tools__bash tool or not at all; denying built-in Bash
# outright also keeps ambient settings files from re-opening untracked access.
BASH_BUILTIN_DENIED = "Bash"


def _create_temp_log(suffix: str) -> tuple[Any, str]:
    """Open an os-level temp file for one background log stream."""
    fd, path = tempfile.mkstemp(prefix="claude-controller-bash-", suffix=suffix)
    return os.fdopen(fd, "w", encoding="utf-8"), path


def _timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _wait_status(returncode: int) -> str:
    if returncode == 0:
        return "exit status 0"
    if returncode < 0:
        return f"signal {signal.Signals(-returncode).name}"
    return f"exit status {returncode}"


class _BgProcess:
    """One tracked background process plus its log files."""

    def __init__(
        self,
        proc: subprocess.Popen,
        stdout_file: Any,
        stderr_file: Any,
    ) -> None:
        self.proc = proc
        self.stdout_file = stdout_file
        self.stderr_file = stderr_file
        self.done = threading.Event()


class BashBackground:
    """Owns backgrounded `bash` tool processes.

    Each runs detached in its own process group with stdout/stderr in temp
    files, gets a stopped line appended to both log files on exit, and is
    killed by `kill_all()`. Create one per run; call `kill_all()` on every
    exit path so no backgrounded command outlives the controller.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: list[_BgProcess] = []
        self._stopping = False

    def active_count(self) -> int:
        with self._lock:
            return len(self._active)

    def kill_all(self) -> None:
        """Kill every tracked process group and wait for the stopped lines to
        land in the log files. Idempotent; the wait is bounded by
        KILL_WAIT_TIMEOUT — stopped lines are best-effort."""
        with self._lock:
            self._stopping = True
            pending = list(self._active)
        for entry in pending:
            try:
                # start_new_session makes pgid == pid, so this takes out the
                # whole child tree.
                os.killpg(entry.proc.pid, signal.SIGKILL)
            except OSError:
                pass  # already gone; the watcher thread reaps it
        deadline = time.monotonic() + KILL_WAIT_TIMEOUT
        for entry in pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            entry.done.wait(remaining)

    def start(self, command: str) -> str:
        """Run command via `bash -c` detached, with stdout and stderr
        redirected to separate temp files. Returns the tool-result text naming
        the pid and both log paths."""
        with self._lock:
            if self._stopping:
                raise RuntimeError("background execution is shut down")
        stdout_file, stdout_path = _create_temp_log(".out")
        stderr_file, stderr_path = _create_temp_log(".err")
        header = f"=== started {_timestamp()}\n$ {command}\n"
        stdout_file.write(header)
        stderr_file.write(header)
        stdout_file.flush()
        stderr_file.flush()
        entry: _BgProcess | None = None
        try:
            # Register under the lock so kill_all can never miss this process.
            with self._lock:
                if self._stopping:
                    raise RuntimeError("background execution is shut down")
                proc = subprocess.Popen(
                    ["bash", "-c", command],
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=True,
                )
                entry = _BgProcess(proc, stdout_file, stderr_file)
                self._active.append(entry)
        except Exception:
            for f, path in ((stdout_file, stdout_path), (stderr_file, stderr_path)):
                f.close()
                os.remove(path)
            raise
        threading.Thread(target=self._reap, args=(entry,), daemon=True).start()
        return (
            f"Background process started: pid {proc.pid}\n"
            f"stdout log: {stdout_path}\n"
            f"stderr log: {stderr_path}\n"
            f"Tail the log files to review progress; `kill {proc.pid}` stops it "
            f"(children share process group {proc.pid})."
        )


    def _reap(self, entry: _BgProcess) -> None:
        """Wait for the process to exit or be killed, then append the stopped
        line to both log files. Parent and child share the file offset, so
        these writes land after the child's output."""
        returncode = entry.proc.wait()
        line = (
            f"=== background process stopped ({_wait_status(returncode)}) "
            f"at {_timestamp()}\n"
        )
        for f in (entry.stdout_file, entry.stderr_file):
            try:
                f.write(line)
                f.flush()
            except OSError:
                pass
            finally:
                f.close()
        with self._lock:
            try:
                self._active.remove(entry)
            except ValueError:
                pass
        entry.done.set()


def _err(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "is_error": True}


def _run_foreground(command: str) -> tuple[str, bool]:
    """Run a foreground command; returns (text, is_error)."""
    try:
        proc = subprocess.run(
            ["bash", "-c", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        return f"Command failed to run: {exc}", True
    out = proc.stdout.decode(errors="replace").strip() or "(no output)"
    if proc.returncode != 0:
        return f"Command exited with status {_wait_status(proc.returncode)}:\n{out}", True
    return out, False


async def dispatch_bash(
    args: dict[str, Any], bg: BashBackground | None = None,
) -> dict[str, Any]:
    """Handle one `bash` tool call. bg (optional) enables background=true;
    when None the background flag is rejected."""
    command = str(args.get("command", "")).strip()
    if not command:
        return _err("Rejected: 'command' must be a non-empty shell command line.")
    if args.get("background"):
        if bg is None:
            return _err("Rejected: background execution is unavailable in this run.")
        try:
            text = await asyncio.to_thread(bg.start, command)
        except Exception as exc:
            return _err(f"Command failed to start: {exc}")
        return {"content": [{"type": "text", "text": text}]}
    text, is_error = await asyncio.to_thread(_run_foreground, command)
    if is_error:
        return _err(text)
    return {"content": [{"type": "text", "text": text}]}


def build_bash_mcp_server(bg: BashBackground | None = None) -> Any:
    """SDK MCP server exposing the unrestricted `bash` tool.

    One shared server is fine for every role — unlike `worker_tools` there is
    no per-worker state in the handler.
    """

    @tool("bash", BASH_TOOL_DESCRIPTION, BASH_TOOL_SCHEMA)
    async def bash(args: dict[str, Any]) -> dict[str, Any]:
        return await dispatch_bash(args, bg)

    return build_sdk_mcp_server(
        name="bash_tools",
        version="1.0.0",
        tools=[bash],
    )
