"""Main orchestrator loop for autonomous security exploration.

Iteration anatomy (see README):
  1) Autonomous worker phase — each alive worker runs up to its autonomous
     budget of turns concurrently, escalating on candidate / silent / budget.
  2) Verification phase — verifier client, multi-substep; reproduces and files
     or dismisses each pending candidate.
  3) Direction phase — director client, multi-substep; decides next move per
     alive worker (continue/expand/stop) and the autonomous budget.
"""

import asyncio
import io
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

from config import Config, parse_args
from findings import FindingWriter, match_pending_candidates
from prompts import orchestrator_director as director_prompts
from prompts import orchestrator_verifier as verifier_prompts
from prompts import worker as worker_prompts
from tools import (
    DEFAULT_AUTONOMOUS_BUDGET,
    DIRECTION_SELF_REVIEW_MAX_ROUNDS,
    DIRECTOR_TOOL_ALLOWED,
    MAX_AUTONOMOUS_BUDGET,
    MIN_ITERATIONS_FOR_DONE,
    PHASE_DIRECTION,
    PHASE_VERIFICATION,
    VERIFIER_TOOL_ALLOWED,
    WORKER_TOOL_ALLOWED,
    CandidateDismissal,
    CandidatePool,
    DecisionQueue,
    FindingCandidate,
    FindingFiled,
    PlanEntry,
    ToolCallRecord,
    WorkerDecision,
    WorkerTurnSummary,
    build_orch_mcp_server,
    build_worker_mcp_server,
    coalesce_decisions,
    extract_flow_ids,
    reset_active_worker,
    set_active_worker,
)


# Glob granting the verifier access to every sectool tool so it can reproduce
# candidates with the same surface workers use (including mutating tools like
# proxy_rule_*, crawl_*, oast_*, proxy_respond_*).
ORCH_SECTOOL_TOOLS_GLOB = "mcp__sectool__*"

# Stall thresholds — counted against escalation_reason == "silent".
STALL_WARN_AFTER = 3
STALL_STOP_AFTER = 4

# Phase substep caps.
VERIFICATION_MAX_SUBSTEPS = 6
DIRECTION_MAX_SUBSTEPS = 4

def log(tag: str, msg: str) -> None:
    print(f"[{tag:<8s}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Build and server lifecycle
# ---------------------------------------------------------------------------


def start_mcp_server(
    sectool_bin: str, proxy_port: int, mcp_port: int, workflow: str,
) -> tuple[subprocess.Popen, "io.TextIOWrapper"]:
    cmd = [
        sectool_bin, "mcp",
        f"--proxy-port={proxy_port}",
        f"--port={mcp_port}",
        f"--workflow={workflow}",
    ]
    log_path = os.path.abspath("sectool-mcp.log")
    log_file = open(log_path, "w")  # noqa: SIM115
    log("server", f"Starting sectool MCP server on :{mcp_port} (proxy :{proxy_port}, workflow: {workflow})")
    log("server", f"Server stderr → {log_path}")
    try:
        proc = subprocess.Popen(cmd, stderr=log_file, stdout=subprocess.DEVNULL)
    except FileNotFoundError:
        log("server", f"sectool binary not found: {sectool_bin!r}. Install sectool and either put it on PATH or pass --sectool-bin.")
        log_file.close()
        sys.exit(1)
    return proc, log_file


def is_server_running(mcp_port: int, timeout: float = 1.0) -> bool:
    url = f"http://127.0.0.1:{mcp_port}/mcp"
    try:
        urllib.request.urlopen(
            urllib.request.Request(url, method="GET"), timeout=timeout,
        )
        return True
    except (urllib.error.URLError, ConnectionError, OSError):
        return False


def wait_for_server(mcp_port: int, proc: subprocess.Popen, timeout: float = 10.0) -> None:
    url = f"http://127.0.0.1:{mcp_port}/mcp"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        exit_code = proc.poll()
        if exit_code is not None:
            log("server", f"MCP server exited early (code {exit_code}). See sectool-mcp.log.")
            sys.exit(1)
        try:
            urllib.request.urlopen(
                urllib.request.Request(url, method="GET"), timeout=2,
            )
            log("server", "MCP server ready.")
            return
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.5)
    log("server", f"MCP server failed to become ready within {timeout}s.")
    sys.exit(1)


def terminate_process(proc: subprocess.Popen, log_file: io.TextIOWrapper | None = None) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    if log_file is not None:
        log_file.close()


# ---------------------------------------------------------------------------
# Managed SDK client — isolates the SDK's internal anyio cancel scope
# ---------------------------------------------------------------------------


class ManagedSDKClient:
    """Owns a ClaudeSDKClient's lifecycle in a dedicated asyncio task.

    The SDK's `ClaudeSDKClient.__aenter__` calls `anyio.create_task_group()`
    and enters it on whatever task is awaiting. That task group's cancel
    scope gets pushed onto that task's anyio scope stack and stays there
    until `__aexit__` runs. Because anyio enforces strict LIFO exit order
    and we create many SDK clients at different points (worker 1, verifier,
    director, then more workers via plan_workers), we can't cleanly pop
    intermediate scopes when one worker gets cancelled mid-iteration.

    A cancelled scope that stays in a task's stack permanently cancels
    everything the task does afterward — anyio re-schedules `task.cancel()`
    every event-loop tick via `_deliver_cancellation`, so draining the
    asyncio cancellation counter doesn't help.

    By running each SDK client inside its own asyncio task, the scope is
    localized to that task. Calls like `client.query()` and
    `client.receive_response()` are safe to invoke from the main task
    because their anyio primitives (Lock, memory_object_stream) check the
    calling task's own scope stack, which stays clean.
    """

    def __init__(self, options: ClaudeAgentOptions):
        self._options = options
        self._client: ClaudeSDKClient | None = None
        self._runner: asyncio.Task | None = None
        self._ready: asyncio.Event = asyncio.Event()
        self._stop: asyncio.Event = asyncio.Event()
        self._enter_exc: BaseException | None = None

    @property
    def client(self) -> ClaudeSDKClient | None:
        return self._client

    async def connect(self) -> ClaudeSDKClient:
        """Start the runner task and return the entered underlying client."""
        self._runner = asyncio.create_task(self._run())
        try:
            await self._ready.wait()
        except BaseException:
            # Caller cancelled us mid-connect; make sure the runner doesn't leak.
            self._stop.set()
            if self._runner is not None and not self._runner.done():
                self._runner.cancel()
                await asyncio.wait([self._runner])
            self._runner = None
            raise
        if self._enter_exc is not None:
            # Propagate a failed __aenter__ so the caller can handle it.
            self._runner = None
            raise self._enter_exc
        assert self._client is not None
        return self._client

    async def aclose(self) -> None:
        """Signal the runner to exit and await its completion.

        Uses `asyncio.wait` rather than `await runner` so a CancelledError
        raised inside the runner is captured as a task result instead of
        propagating to the caller.
        """
        if self._runner is None:
            self._client = None
            return
        self._stop.set()
        runner = self._runner
        self._runner = None
        if not runner.done():
            await asyncio.wait([runner])
        self._client = None

    async def _run(self) -> None:
        try:
            async with ClaudeSDKClient(options=self._options) as c:
                self._client = c
                self._ready.set()
                await self._stop.wait()
        except BaseException as exc:
            # Either __aenter__ failed or we were force-cancelled. Capture
            # so connect() can surface real errors; swallow CancelledError
            # because the task itself is expected to terminate cleanly.
            if not isinstance(exc, asyncio.CancelledError):
                self._enter_exc = exc
            self._ready.set()


# ---------------------------------------------------------------------------
# Worker state
# ---------------------------------------------------------------------------


@dataclass
class WorkerState:
    worker_id: int
    options: ClaudeAgentOptions
    client: ClaudeSDKClient | None = None
    managed: ManagedSDKClient | None = None
    last_instruction: str | None = None
    alive: bool = True
    assignment: str = ""
    progress_none_streak: int = 0
    stall_warned: bool = False
    autonomous_budget: int = DEFAULT_AUTONOMOUS_BUDGET
    escalation_reason: str | None = None
    autonomous_turns: list[WorkerTurnSummary] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Text shortening helpers
# ---------------------------------------------------------------------------


def _short(s: str, n: int) -> str:
    s = s.strip()
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def _is_premature_done(iteration: int, findings_count: int) -> bool:
    """Reject `done` when the run has made no visible progress yet.

    Mirrors secagent's MinIterationsForDone guard: local/weak models routinely
    conflate `done` with `direction_done` on early iterations.
    """
    return iteration < MIN_ITERATIONS_FOR_DONE and findings_count == 0


def _clear_leaked_cancellations(tag: str = "") -> int:
    """Drain leaked cancellations from the current asyncio task.

    The Claude Agent SDK is anyio-backed. When `asyncio.wait_for` cancels
    a `receive_response()` stream mid-flight, the SDK's internal anyio
    cancel scope can propagate cancellation onto the task that originally
    called `client.__aenter__()` — usually our main task. Left alone,
    subsequent awaits in that task raise `CancelledError` (even outside
    the SDK code path).

    Python 3.11+ exposes `Task.uncancel()` / `Task.cancelling()` to clear
    this. We drain the counter down to zero and return how many we cleared
    for logging. On older Pythons (no `uncancel`) we return 0 (best-effort
    — the fallback relies on teardown_worker skipping `__aexit__` on
    poisoned clients).
    """
    try:
        task = asyncio.current_task()
    except RuntimeError:
        return 0
    if task is None:
        return 0
    uncancel = getattr(task, "uncancel", None)
    cancelling = getattr(task, "cancelling", None)
    if not callable(uncancel) or not callable(cancelling):
        return 0
    cleared = 0
    while cancelling() > 0:
        uncancel()
        cleared += 1
    if cleared and tag:
        log(tag, f"Cleared {cleared} leaked cancel scope(s) on current task.")
    return cleared


def _summarize_input(tool_input: dict) -> str:
    try:
        serialized = json.dumps(tool_input, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        serialized = repr(tool_input)
    return _short(serialized, 240)


def _summarize_result(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return _short(content, 300)
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(repr(item))
        return _short("\n".join(parts), 300)
    return _short(repr(content), 300)


# ---------------------------------------------------------------------------
# Worker turn collection
# ---------------------------------------------------------------------------


async def collect_worker_turn(
    client: ClaudeSDKClient,
    worker_id: int,
    iteration: int,
    candidates: CandidatePool,
    verbose_tag: str | None = None,
) -> WorkerTurnSummary:
    """Drain one turn from a worker into a WorkerTurnSummary.

    Sets the `_ACTIVE_WORKER_ID` ContextVar so any `report_finding_candidate`
    calls attribute to this worker even under concurrent drains.

    No per-turn timeout: the SDK's `receive_response` generator is consumed
    to completion. Connection errors and external cancellations are handled
    by the caller (`run_worker_autonomous_turn`).
    """
    candidates_before = candidates.counter
    token = set_active_worker(worker_id)

    summary = WorkerTurnSummary(worker_id=worker_id, iteration=iteration)
    pending_calls: dict[str, ToolCallRecord] = {}

    try:
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        summary.assistant_text += (block.text or "")
                        if verbose_tag:
                            first = (block.text or "").strip().split("\n", 1)[0]
                            if first:
                                log(verbose_tag, f"text: {_short(first, 120)}")
                    elif isinstance(block, ToolUseBlock):
                        rec = ToolCallRecord(
                            name=block.name,
                            input_summary=_summarize_input(block.input or {}),
                        )
                        pending_calls[block.id] = rec
                        summary.tool_calls.append(rec)
                        for fid in extract_flow_ids(block.input or {}):
                            if fid not in summary.flow_ids_touched:
                                summary.flow_ids_touched.append(fid)
                        if verbose_tag:
                            log(verbose_tag, f"tool: {block.name}")
            elif isinstance(message, UserMessage):
                blocks = message.content if isinstance(message.content, list) else []
                for block in blocks:
                    if isinstance(block, ToolResultBlock):
                        rec = pending_calls.pop(block.tool_use_id, None)
                        if rec is not None:
                            rec.result_summary = _summarize_result(block.content)
                            rec.is_error = bool(block.is_error)
                        for fid in extract_flow_ids(block.content):
                            if fid not in summary.flow_ids_touched:
                                summary.flow_ids_touched.append(fid)
            elif isinstance(message, ResultMessage):
                summary.cost_usd = message.total_cost_usd
                break
    finally:
        reset_active_worker(token)

    # Scope candidates to this worker so concurrent drains don't cross-attribute.
    summary.candidate_ids = candidates.ids_since_for_worker(candidates_before, worker_id)

    for fid in extract_flow_ids(summary.assistant_text):
        if fid not in summary.flow_ids_touched:
            summary.flow_ids_touched.append(fid)

    if verbose_tag:
        cost_str = f"${summary.cost_usd:.4f}" if summary.cost_usd else "n/a"
        log(
            verbose_tag,
            f"done ({len(summary.tool_calls)} tools, "
            f"{len(summary.flow_ids_touched)} flow IDs, "
            f"{len(summary.candidate_ids)} candidates, cost: {cost_str})",
        )

    return summary


# ---------------------------------------------------------------------------
# Worker lifecycle
# ---------------------------------------------------------------------------


def _build_worker_options(
    base: ClaudeAgentOptions,
    worker_tools_server,
    mcp_url: str,
    worker_id: int,
    num_workers: int,
    stderr_cb,
) -> ClaudeAgentOptions:
    return ClaudeAgentOptions(
        mcp_servers={
            "sectool": {"type": "http", "url": mcp_url},
            "worker_tools": worker_tools_server,
        },
        allowed_tools=[
            "mcp__sectool__*",
            WORKER_TOOL_ALLOWED,
            "Read", "Glob", "Grep", "Bash",
        ],
        disallowed_tools=["Write", "Edit"],
        permission_mode="acceptEdits",
        cwd=base.cwd,
        max_turns=base.max_turns,
        model=base.model,
        stderr=stderr_cb,
        system_prompt=worker_prompts.build_system_prompt(worker_id, num_workers),
    )


async def create_worker(
    worker_id: int,
    num_workers: int,
    worker_tools_server,
    mcp_url: str,
    base: ClaudeAgentOptions,
    stderr_cb,
) -> WorkerState:
    opts = _build_worker_options(base, worker_tools_server, mcp_url, worker_id, num_workers, stderr_cb)
    managed = ManagedSDKClient(options=opts)
    client = await managed.connect()
    return WorkerState(worker_id=worker_id, options=opts, client=client, managed=managed)


async def teardown_worker(state: WorkerState) -> None:
    state.alive = False
    if state.managed is not None:
        await state.managed.aclose()
    state.client = None
    state.managed = None


async def attempt_worker_recovery(state: WorkerState) -> bool:
    await teardown_worker(state)
    for attempt in range(1, 3):
        try:
            await asyncio.sleep(2)
            managed = ManagedSDKClient(options=state.options)
            client = await managed.connect()
            state.managed = managed
            state.client = client
            state.alive = True
            log(f"worker {state.worker_id}", f"Recovery succeeded (attempt {attempt})")
            if state.last_instruction:
                await client.query(state.last_instruction)
            return True
        except Exception as exc:
            log(f"worker {state.worker_id}", f"Recovery attempt {attempt} failed: {exc}")
    state.alive = False
    return False


async def attempt_client_recovery(
    old_managed: ManagedSDKClient | None,
    options: ClaudeAgentOptions,
    tag: str,
) -> ManagedSDKClient | None:
    """Recover a long-lived orchestrator client (verifier or director)."""
    if old_managed is not None:
        await old_managed.aclose()
    for attempt in range(1, 3):
        try:
            await asyncio.sleep(2)
            managed = ManagedSDKClient(options=options)
            await managed.connect()
            log(tag, f"Recovery succeeded (attempt {attempt})")
            return managed
        except Exception as exc:
            log(tag, f"Recovery attempt {attempt} failed: {exc}")
    return None


# ---------------------------------------------------------------------------
# Autonomous worker runs
# ---------------------------------------------------------------------------


def _classify_escalation(summary: WorkerTurnSummary) -> str | None:
    """Return an escalation reason, or None if the turn was productive."""
    if summary.candidate_ids:
        return "candidate"
    if not summary.tool_calls and not summary.flow_ids_touched:
        return "silent"
    return None


async def run_worker_autonomous_turn(
    worker: WorkerState,
    iteration: int,
    candidates: CandidatePool,
    verbose: bool,
) -> tuple[WorkerTurnSummary | None, str | None]:
    """Drain one turn from the worker; classify as candidate/silent/None/error.

    Returns (summary, escalation_reason). On connection error returns
    (None, "error"); the turn otherwise runs to completion. External
    cancellations (Ctrl+C / task cancel) propagate up as CancelledError
    and are caught in per_worker().
    """
    tag = f"w{worker.worker_id}" if verbose else None
    try:
        summary = await collect_worker_turn(
            worker.client, worker.worker_id, iteration, candidates, tag,
        )
    except (ConnectionError, OSError) as exc:
        log(f"worker {worker.worker_id}", f"Connection lost: {exc}")
        return None, "error"

    return summary, _classify_escalation(summary)


async def run_worker_until_escalation(
    worker: WorkerState,
    iteration: int,
    candidates: CandidatePool,
    verbose: bool,
) -> list[WorkerTurnSummary]:
    """Run a worker for up to autonomous_budget turns or until it escalates.

    Mutates `worker.escalation_reason` with the terminating reason.
    Appends each turn's summary to `worker.autonomous_turns`.
    """
    run_turns: list[WorkerTurnSummary] = []
    budget = max(1, min(MAX_AUTONOMOUS_BUDGET, worker.autonomous_budget))

    for attempt in range(budget):
        if attempt > 0:
            try:
                # Intra-iteration between-turn requery: tokens precious,
                # skip the findings roster.
                await worker.client.query(
                    _build_worker_continue_prompt(findings_summary=""),
                )
            except (ConnectionError, OSError) as exc:
                log(f"worker {worker.worker_id}", f"Continue query failed: {exc}")
                worker.escalation_reason = "error"
                return run_turns

        summary, reason = await run_worker_autonomous_turn(
            worker, iteration, candidates, verbose,
        )
        if summary is not None:
            run_turns.append(summary)
            worker.autonomous_turns.append(summary)
        if reason is not None:
            worker.escalation_reason = reason
            return run_turns

    worker.escalation_reason = "budget"
    return run_turns


async def run_all_workers_until_escalation(
    workers: list[WorkerState],
    iteration: int,
    candidates: CandidatePool,
    verbose: bool = False,
) -> dict[int, list[WorkerTurnSummary]]:
    """Run every alive worker concurrently until all have escalated.

    A CancelledError in one worker's task (e.g. from a leaked SDK cancel
    scope after a prior timeout) is isolated: that worker is marked
    escalation_reason="error" for the main-loop recovery path, but the
    other workers' results are preserved.
    """
    async def per_worker(w: WorkerState) -> tuple[int, list[WorkerTurnSummary]]:
        w.escalation_reason = None
        w.autonomous_turns = []
        try:
            runs = await run_worker_until_escalation(w, iteration, candidates, verbose)
            return w.worker_id, runs
        except asyncio.CancelledError:
            # The client's internal anyio scope got cancelled (timeout or
            # gather propagation). With ManagedSDKClient that scope lives
            # on the runner task, not main, so we can tear down cleanly
            # and rebuild on the next iteration's error-recovery pass.
            log(f"worker {w.worker_id}",
                "Autonomous task cancelled; marking for recovery next iteration.")
            w.escalation_reason = "error"
            # Drop the broken client reference so the main-loop recovery path
            # (`if w.escalation_reason == "error" and w.client is None`) fires.
            # Keep alive=True — the worker slot is conceptually still occupied.
            if w.managed is not None:
                await w.managed.aclose()
            w.managed = None
            w.client = None
            return w.worker_id, list(w.autonomous_turns)

    alive = [w for w in workers if w.alive and w.client is not None]
    if not alive:
        return {}
    tasks = [asyncio.create_task(per_worker(w)) for w in alive]
    results: dict[int, list[WorkerTurnSummary]] = {}
    for t in tasks:
        try:
            wid, runs = await t
            results[wid] = runs
        except asyncio.CancelledError:
            # Defence in depth — per_worker already catches, but if the await
            # itself is cancelled we still don't want to crash the whole run.
            log("worker", "Task await cancelled; continuing with remaining workers.")
            _clear_leaked_cancellations("worker")
    # Always drain leaked cancellations before returning to the main task.
    # A cancel-scope leak from one worker's timeout can otherwise poison the
    # main loop's next await (e.g. attempt_worker_recovery's asyncio.sleep).
    _clear_leaked_cancellations("worker")
    return results


# ---------------------------------------------------------------------------
# Prompt formatting
# ---------------------------------------------------------------------------


def _format_tool_calls(calls: list[ToolCallRecord], limit: int = 20) -> str:
    if not calls:
        return "  (no tool calls)"
    lines: list[str] = []
    shown = calls[:limit]
    for i, c in enumerate(shown, 1):
        status = " [ERROR]" if c.is_error else ""
        line = f"  {i}. {c.name}({c.input_summary}){status}"
        if c.result_summary:
            line += f"\n     → {c.result_summary}"
        lines.append(line)
    if len(calls) > limit:
        lines.append(f"  … and {len(calls) - limit} more tool call(s) omitted.")
    return "\n".join(lines)


def _format_autonomous_run(
    worker_id: int,
    turns: list[WorkerTurnSummary],
    escalation_reason: str | None,
) -> str:
    if not turns:
        return (
            f"### Worker {worker_id}\n"
            f"(No autonomous turns this iteration. escalation_reason={escalation_reason or 'unknown'})"
        )
    parts = [
        f"### Worker {worker_id} — {len(turns)} autonomous turn(s), "
        f"escalated: {escalation_reason or 'unknown'}",
    ]
    for i, s in enumerate(turns, 1):
        calls = ", ".join(c.name for c in s.tool_calls) or "(no tool calls)"
        flows = ", ".join(s.flow_ids_touched) if s.flow_ids_touched else "(no flows)"
        cands = ", ".join(s.candidate_ids) if s.candidate_ids else "(no candidates)"
        first_line = (s.assistant_text.strip().split("\n", 1)[0]) or "(no text)"
        parts.append(
            f"  Turn {i}: tools=[{_short(calls, 200)}] flows=[{flows}] cands=[{cands}]\n"
            f"    text: {_short(first_line, 240)}"
        )
    last = turns[-1]
    parts.append("")
    parts.append(f"Last turn tool calls ({len(last.tool_calls)}):")
    parts.append(_format_tool_calls(last.tool_calls, limit=10))
    return "\n".join(parts)


def _format_pending_candidates_list(pending: list[FindingCandidate]) -> str:
    if not pending:
        return "No pending finding candidates."
    lines = ["**Pending finding candidates (awaiting verification):**"]
    for c in pending:
        lines.append(
            f"- `{c.candidate_id}` [{c.severity}] {c.title} — {c.endpoint}\n"
            f"  worker: {c.worker_id}\n"
            f"  flows: {', '.join(c.flow_ids) or '(none)'}\n"
            f"  summary: {_short(c.summary, 200)}\n"
            f"  reproduction hint: {_short(c.reproduction_hint, 200)}"
        )
    return "\n".join(lines)


def _format_pending_candidates(candidates: CandidatePool) -> str:
    return _format_pending_candidates_list(candidates.pending())


def _format_status_line(
    iteration: int, max_iter: int,
    total_cost: float, max_cost: float | None,
    findings_count: int,
) -> str:
    cost_part = f"${total_cost:.2f}"
    if max_cost is not None:
        cost_part += f"/${max_cost:.2f}"
    return f"**Status:** iteration {iteration}/{max_iter}, cost {cost_part}, findings filed: {findings_count}"


def _format_stall_warnings(workers: list[WorkerState]) -> str:
    warnings: list[str] = []
    for w in workers:
        if not w.alive:
            continue
        if w.progress_none_streak >= STALL_WARN_AFTER and not w.stall_warned:
            warnings.append(
                f"- Worker {w.worker_id} has had {w.progress_none_streak} consecutive "
                "silent autonomous runs. Either expand its plan or stop it."
            )
    if not warnings:
        return ""
    return "**Stall warnings:**\n" + "\n".join(warnings)


def _build_verifier_prompt(
    *,
    workers: list[WorkerState],
    worker_runs: dict[int, list[WorkerTurnSummary]],
    pending: list[FindingCandidate],
    findings_summary: str,
    iteration: int, max_iter: int,
    total_cost: float, max_cost: float | None,
    findings_count: int,
) -> str:
    parts = [
        _format_status_line(iteration, max_iter, total_cost, max_cost, findings_count),
        "",
        findings_summary,
        "",
        _format_pending_candidates_list(pending),
        "",
        "**Worker autonomous runs this iteration:**",
        "",
    ]
    for w in workers:
        if not w.alive:
            continue
        parts.append(_format_autonomous_run(
            w.worker_id, worker_runs.get(w.worker_id, []), w.escalation_reason,
        ))
        parts.append("")
    parts.append(
        "Reproduce and dispose of every pending candidate. "
        "`verification_done(summary)` when all are filed or dismissed."
    )
    return "\n".join(parts)


def _build_verifier_continue_prompt(
    *,
    pending: list[FindingCandidate],
    filed_this_phase: list[FindingFiled],
    dismissed_this_phase: list[CandidateDismissal],
    substep: int,
    max_substeps: int,
) -> str:
    """Continue-prompt for the verifier between substeps.

    Lists actual titles filed and candidate ids dismissed this phase so the
    model stops re-announcing the same dispositions each substep.
    """
    parts = [
        (
            f"**Verification substep {substep}/{max_substeps}.** "
            f"Filed {len(filed_this_phase)}, "
            f"dismissed {len(dismissed_this_phase)} so far."
        ),
    ]
    if filed_this_phase:
        parts.append("")
        parts.append("Already filed this phase (do not re-file):")
        for f in filed_this_phase:
            parts.append(f"- {f.title}")
    if dismissed_this_phase:
        parts.append("")
        parts.append("Already dismissed this phase:")
        for d in dismissed_this_phase:
            parts.append(f"- {d.candidate_id}")
    parts.append("")
    parts.append(_format_pending_candidates_list(pending))
    return "\n".join(parts)


def _format_follow_up_hints(
    findings: list[FindingFiled],
    dismissals: list[CandidateDismissal],
) -> str:
    """Collate optional verifier follow-up hints into a labeled block.

    Returns "" when no hints are present so the caller can suppress the block.
    """
    lines: list[str] = []
    for f in findings:
        h = f.follow_up_hint.strip()
        if h:
            lines.append(f"- (filed: {_short(f.title, 80)}) {h}")
    for d in dismissals:
        h = d.follow_up_hint.strip()
        if h:
            lines.append(f"- (dismissed: {d.candidate_id}) {h}")
    if not lines:
        return ""
    return (
        "**Verifier follow-up hints (advisory — you decide whether to act):**\n"
        + "\n".join(lines)
    )


def _build_director_prompt(
    *,
    workers: list[WorkerState],
    worker_runs: dict[int, list[WorkerTurnSummary]],
    verification_summary: str,
    findings_summary: str,
    iteration: int, max_iter: int,
    total_cost: float, max_cost: float | None,
    findings_count: int,
    stall_warnings: str,
    follow_up_hints: str,
    max_workers: int,
    user_prompt: str,
) -> str:
    parts = [
        _format_status_line(iteration, max_iter, total_cost, max_cost, findings_count),
        "",
        f"**Assignment (user prompt):** {user_prompt}",
        "",
        findings_summary,
        "",
        f"**Verification:** {verification_summary}",
    ]
    if stall_warnings:
        parts.append("")
        parts.append(stall_warnings)
    if follow_up_hints:
        parts.append("")
        parts.append(follow_up_hints)
    parts.append("")
    parts.append("**Worker autonomous runs this iteration:**")
    parts.append("")
    alive_ids = []
    alive_count = 0
    for w in workers:
        if not w.alive:
            continue
        alive_count += 1
        alive_ids.append(str(w.worker_id))
        parts.append(_format_autonomous_run(
            w.worker_id, worker_runs.get(w.worker_id, []), w.escalation_reason,
        ))
        parts.append("")
    alive_str = ", ".join(alive_ids) if alive_ids else "(none)"
    parts.append(
        f"**Alive:** [{alive_str}]  **Parallelism:** {alive_count}/{max_workers}."
    )
    stopped_ids = [str(w.worker_id) for w in workers if not w.alive]
    if stopped_ids:
        parts.append(
            f"Stopped this run: [{', '.join(stopped_ids)}] "
            "(do not re-plan around these; pick fresh worker_ids for new workers)."
        )

    # Iteration 1 is the attack-surface dispatch moment. Fan-out is the
    # default; a single worker is only correct for manifestly narrow
    # assignments (single endpoint / single flow).
    if iteration == 1 and alive_count < max_workers:
        parts.append("")
        parts.append(
            "**Iteration 1 fan-out is mandatory for non-trivial assignments.** "
            "Slice the assignment above into 3–4 disjoint specialised workers "
            "and spawn them via `plan_workers` with fresh worker_ids NOW. "
            "Only stay at one worker if the assignment names a single "
            "endpoint or a single flow. Worker 1 being silent, timed-out, or "
            "escalating `error` is NOT a reason to stay at one worker — it's "
            "a reason to stop worker 1 and fan out in its place."
        )
    return "\n".join(parts)


def _build_director_continue_prompt(
    *,
    pending_wids: set[int],
    substep: int,
    max_substeps: int,
) -> str:
    pending_str = (
        ", ".join(str(w) for w in sorted(pending_wids)) if pending_wids else "(none)"
    )
    return (
        f"**Direction substep {substep}/{max_substeps}.** "
        f"Workers still uncovered: [{pending_str}]."
    )


def _build_director_self_review_prompt() -> str:
    return (
        "**Self-review.** Any alive worker uncovered or misassigned? "
        "Make final adjustments, then `direction_done(summary)`."
    )


_BARE_WORKER_CONTINUE = (
    "Continue your current testing plan. Take the next concrete step."
)


def _build_worker_continue_prompt(findings_summary: str) -> str:
    """Build a continue directive, prepending the findings-filed roster.

    Used at iteration boundaries (implicit-continue after direction) so the
    worker knows what's already been filed and doesn't re-report it. Intra-
    iteration turns pass an empty `findings_summary` to keep tokens cheap.
    """
    summary = (findings_summary or "").strip()
    if not summary:
        return _BARE_WORKER_CONTINUE
    return f"{summary}\n\n{_BARE_WORKER_CONTINUE}"


# ---------------------------------------------------------------------------
# Phase substep runner and printing
# ---------------------------------------------------------------------------


def _phase_tag(phase: str) -> str:
    return "verify" if phase == PHASE_VERIFICATION else "direct"


def _print_phase_turn(
    phase: str,
    text: str,
    tool_calls: list[str],
    iteration: int,
    substep: int,
    verbose: bool,
) -> None:
    print(flush=True)
    label = "Verifier" if phase == PHASE_VERIFICATION else "Director"
    print(f"=== {label} (iter {iteration}, substep {substep}) ===", flush=True)
    if verbose and text:
        print(text, flush=True)
    elif text:
        print(_short(text, 500), flush=True)
    if tool_calls:
        counts: dict[str, int] = {}
        for n in tool_calls:
            counts[n] = counts.get(n, 0) + 1
        ordered = sorted(counts.items())
        summary = ", ".join(f"{n}×{c}" for n, c in ordered)
        print(f"Tool calls: {summary}", flush=True)
    else:
        print("Tool calls: (none)", flush=True)
    print("=" * 50, flush=True)
    print(flush=True)


async def run_phase_substep(
    client: ClaudeSDKClient,
    user_content: str,
    phase: str,
    iteration: int,
    substep: int,
    verbose: bool,
) -> tuple[bool, float | None]:
    """Send a substep message and drain. Returns (ok, cost). On error ok=False."""
    text_parts: list[str] = []
    tool_calls: list[str] = []
    cost: float | None = None
    try:
        await client.query(user_content)
        async for msg in client.receive_response():
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        text_parts.append(block.text or "")
                    elif isinstance(block, ToolUseBlock):
                        tool_calls.append(block.name)
                        if verbose:
                            log(_phase_tag(phase), f"tool: {block.name}")
            elif isinstance(msg, ResultMessage):
                cost = msg.total_cost_usd
                break
    except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
        log(_phase_tag(phase), f"Substep error iter {iteration} sub {substep}: {exc}")
        return False, None

    _print_phase_turn(phase, "\n".join(text_parts).strip(), tool_calls, iteration, substep, verbose)
    return True, cost


# ---------------------------------------------------------------------------
# Verification phase
# ---------------------------------------------------------------------------


async def run_verification_phase(
    managed: ManagedSDKClient,
    options: ClaudeAgentOptions,
    decisions: DecisionQueue,
    candidates: CandidatePool,
    finding_writer: FindingWriter,
    worker_runs: dict[int, list[WorkerTurnSummary]],
    workers: list[WorkerState],
    iteration: int,
    max_iter: int,
    total_cost: float,
    max_cost: float | None,
    verbose: bool,
) -> tuple[ManagedSDKClient, float, str]:
    """Drive the verifier over up to VERIFICATION_MAX_SUBSTEPS substeps.

    Applies findings/dismissals incrementally so each substep's prompt
    reflects the current state. Exits when the verifier calls
    `verification_done`, when no pending candidates remain, or at the cap.
    """
    decisions.begin_phase(PHASE_VERIFICATION)
    phase_cost = 0.0

    if not candidates.pending():
        log("verify", "No pending candidates; skipping verification phase.")
        return managed, phase_cost, "No pending candidates this iteration."

    applied_findings = 0
    applied_dismissals = 0

    for substep in range(1, VERIFICATION_MAX_SUBSTEPS + 1):
        pending = candidates.pending()
        if not pending:
            break

        if substep == 1:
            user_content = _build_verifier_prompt(
                workers=workers,
                worker_runs=worker_runs,
                pending=pending,
                findings_summary=finding_writer.summary_for_orchestrator(),
                iteration=iteration, max_iter=max_iter,
                total_cost=total_cost + phase_cost,
                max_cost=max_cost,
                findings_count=finding_writer.count,
            )
        else:
            user_content = _build_verifier_continue_prompt(
                pending=pending,
                filed_this_phase=decisions.findings[:applied_findings],
                dismissed_this_phase=decisions.dismissals[:applied_dismissals],
                substep=substep,
                max_substeps=VERIFICATION_MAX_SUBSTEPS,
            )

        ok, cost = await run_phase_substep(
            managed.client, user_content, PHASE_VERIFICATION, iteration, substep, verbose,
        )
        if not ok:
            new_managed = await attempt_client_recovery(managed, options, "verify")
            if new_managed is not None:
                managed = new_managed
            log("verify", f"Aborting verification phase at substep {substep}.")
            break
        if cost is not None:
            phase_cost += cost

        # Apply new findings this substep produced. `seen_titles` dedups
        # burst `file_finding` calls within one response — `is_duplicate`
        # still catches cross-substep dupes on disk.
        seen_titles: set[str] = set()
        for filed in decisions.findings[applied_findings:]:
            title_key = filed.title.strip().lower()
            if title_key and title_key in seen_titles:
                log("finding", f"Duplicate (same substep) skipped: {filed.title}")
                continue
            if title_key:
                seen_titles.add(title_key)
            if finding_writer.is_duplicate(filed):
                log("finding", f"Duplicate skipped: {filed.title}")
            else:
                path = finding_writer.write(filed)
                log("finding", f"Written: {path}")
            resolved = list(filed.supersedes_candidate_ids)
            if not resolved:
                pending_now = candidates.pending()
                auto = match_pending_candidates(filed, pending_now)
                for cid in auto:
                    log("finding",
                        f"Auto-resolved candidate {cid} (matched endpoint+title)")
                if not auto and pending_now:
                    log("finding",
                        "finding orphan — no pending candidate matched "
                        f"title={_short(filed.title, 80)!r} "
                        f"endpoint={filed.endpoint!r} "
                        f"pending={[c.candidate_id for c in pending_now]}")
                resolved = auto
            for cid in resolved:
                candidates.mark(cid, "verified")
        applied_findings = len(decisions.findings)

        for dm in decisions.dismissals[applied_dismissals:]:
            existing = candidates.get(dm.candidate_id)
            if existing is None:
                log("finding",
                    f"Candidate {dm.candidate_id} dismissal ignored "
                    "(unknown candidate_id).")
                continue
            if existing.status != "pending":
                # Skip the log-each-time loop when the verifier repeatedly
                # dismisses the same candidate in one substep burst.
                continue
            if candidates.mark(dm.candidate_id, "dismissed"):
                log("finding",
                    f"Candidate {dm.candidate_id} dismissed: "
                    f"{_short(dm.reason, 80)}")
        applied_dismissals = len(decisions.dismissals)

        if decisions.verification_done_summary is not None:
            break

    summary = (
        decisions.verification_done_summary
        or f"Verification phase ended with {applied_findings} filed, "
           f"{applied_dismissals} dismissed, {len(candidates.pending())} still pending."
    )
    return managed, phase_cost, summary


# ---------------------------------------------------------------------------
# Direction phase
# ---------------------------------------------------------------------------


async def run_direction_phase(
    managed: ManagedSDKClient,
    options: ClaudeAgentOptions,
    decisions: DecisionQueue,
    workers: list[WorkerState],
    worker_runs: dict[int, list[WorkerTurnSummary]],
    verification_summary: str,
    findings_summary: str,
    iteration: int,
    max_iter: int,
    total_cost: float,
    max_cost: float | None,
    findings_count: int,
    stall_warnings: str,
    follow_up_hints: str,
    verbose: bool,
    max_workers: int,
    user_prompt: str,
) -> tuple[ManagedSDKClient, float]:
    """Drive the director over up to DIRECTION_MAX_SUBSTEPS substeps, then a
    mandatory self-review substep."""
    decisions.begin_phase(PHASE_DIRECTION)
    phase_cost = 0.0
    alive_ids = {w.worker_id for w in workers if w.alive}
    aborted = False

    def _decision_total() -> int:
        plan_len = len(decisions.plan) if decisions.plan is not None else 0
        return len(decisions.worker_decisions) + plan_len

    prev_total = _decision_total()
    no_progress_streak = 0

    for substep in range(1, DIRECTION_MAX_SUBSTEPS + 1):
        covered = {d.worker_id for d in decisions.worker_decisions}
        if decisions.plan is not None:
            covered |= {p.worker_id for p in decisions.plan}
        pending_wids = alive_ids - covered

        if substep == 1:
            user_content = _build_director_prompt(
                workers=workers,
                worker_runs=worker_runs,
                verification_summary=verification_summary,
                findings_summary=findings_summary,
                iteration=iteration, max_iter=max_iter,
                total_cost=total_cost + phase_cost,
                max_cost=max_cost,
                findings_count=findings_count,
                stall_warnings=stall_warnings,
                follow_up_hints=follow_up_hints,
                max_workers=max_workers,
                user_prompt=user_prompt,
            )
        else:
            user_content = _build_director_continue_prompt(
                pending_wids=pending_wids,
                substep=substep,
                max_substeps=DIRECTION_MAX_SUBSTEPS,
            )

        ok, cost = await run_phase_substep(
            managed.client, user_content, PHASE_DIRECTION, iteration, substep, verbose,
        )
        if not ok:
            new_managed = await attempt_client_recovery(managed, options, "direct")
            if new_managed is not None:
                managed = new_managed
            log("direct", f"Aborting direction phase at substep {substep}.")
            aborted = True
            break
        if cost is not None:
            phase_cost += cost

        if (
            decisions.direction_done_summary is not None
            or decisions.done_summary is not None
        ):
            break

        covered = {d.worker_id for d in decisions.worker_decisions}
        if decisions.plan is not None:
            covered |= {p.worker_id for p in decisions.plan}
        if not (alive_ids - covered):
            break

        # C2: early-exit when the director stops producing new decisions.
        total_now = _decision_total()
        if total_now == prev_total:
            no_progress_streak += 1
        else:
            no_progress_streak = 0
        prev_total = total_now
        if no_progress_streak >= 2:
            log("direct",
                f"direct early-exit no progress after substep {substep}.")
            break

    # Mandatory self-review substep unless the director already ended the run
    # or the phase aborted from a connection error.
    if not aborted and decisions.done_summary is None:
        ok, cost = await run_phase_substep(
            managed.client, _build_director_self_review_prompt(),
            PHASE_DIRECTION, iteration, DIRECTION_MAX_SUBSTEPS + 1, verbose,
        )
        if ok and cost is not None:
            phase_cost += cost

    return managed, phase_cost


# ---------------------------------------------------------------------------
# Apply decisions
# ---------------------------------------------------------------------------


async def apply_plan_diff(
    plan: list[PlanEntry],
    workers: list[WorkerState],
    worker_tools_server,
    mcp_url: str,
    base_options: ClaudeAgentOptions,
    stderr_cb,
    max_workers: int,
) -> None:
    by_id = {w.worker_id: w for w in workers}
    existing_ids = {w.worker_id for w in workers if w.alive}
    plan_ids = {p.worker_id for p in plan}
    total_after = len(existing_ids | plan_ids)
    spawn_ids = sorted(plan_ids - existing_ids)
    retarget_ids = sorted(plan_ids & existing_ids)
    log("plan",
        f"Applying plan: {len(plan)} entries — "
        f"spawn {spawn_ids if spawn_ids else '[]'}, "
        f"retarget {retarget_ids if retarget_ids else '[]'} "
        f"(existing alive={sorted(existing_ids)}, max={max_workers})")
    if total_after > max_workers:
        log("plan", f"Plan requested {total_after} workers; capped at {max_workers}.")

    for p in plan:
        snippet = _short(p.assignment, 120)
        if p.worker_id in by_id and by_id[p.worker_id].alive:
            w = by_id[p.worker_id]
            log(f"worker {p.worker_id}", f"Retargeting: {snippet}")
            w.assignment = p.assignment
            w.last_instruction = p.assignment
            w.progress_none_streak = 0
            w.stall_warned = False
            try:
                await w.client.query(p.assignment)
            except (ConnectionError, OSError):
                await attempt_worker_recovery(w)
        else:
            if len(existing_ids) >= max_workers:
                log(f"worker {p.worker_id}", f"Spawn skipped: max_workers={max_workers} reached.")
                continue
            num_workers_total = max(1, total_after)
            log(f"worker {p.worker_id}", f"Spawning: {snippet}")
            try:
                new_w = await create_worker(
                    p.worker_id, num_workers_total, worker_tools_server, mcp_url, base_options, stderr_cb,
                )
                new_w.assignment = p.assignment
                new_w.last_instruction = p.assignment
                await new_w.client.query(p.assignment)
                workers.append(new_w)
                existing_ids.add(p.worker_id)
                log(f"worker {p.worker_id}", "Connected and assigned.")
            except Exception as exc:
                log(f"worker {p.worker_id}", f"Spawn failed: {exc}")


async def apply_decision(
    decision: WorkerDecision,
    worker: WorkerState,
    iteration: int,
) -> None:
    """Dispatch a single director decision to the target worker.

    No longer touches stall tracking (that is done from escalation_reason in
    the main loop). Copies the director's `autonomous_budget` onto the worker.
    """
    if decision.kind == "stop":
        log(f"iter {iteration}", f"Worker {worker.worker_id}: stop — {decision.reason}")
        await teardown_worker(worker)
        return

    worker.autonomous_budget = max(1, min(MAX_AUTONOMOUS_BUDGET, decision.autonomous_budget))

    snippet = _short(decision.instruction, 120)
    log(f"iter {iteration}",
        f"Worker {worker.worker_id}: {decision.kind} "
        f"(budget={worker.autonomous_budget}) — \"{snippet}\"")

    worker.last_instruction = decision.instruction
    try:
        await worker.client.query(decision.instruction)
    except (ConnectionError, OSError):
        await attempt_worker_recovery(worker)


def update_worker_streaks(workers: list[WorkerState]) -> None:
    """Update progress_none_streak from escalation_reason after autonomous runs."""
    for w in workers:
        if not w.alive:
            continue
        produced_flows = any(t.flow_ids_touched for t in w.autonomous_turns)
        if w.escalation_reason == "silent":
            w.progress_none_streak += 1
        elif w.escalation_reason == "candidate" or produced_flows:
            w.progress_none_streak = 0
            w.stall_warned = False


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


async def run(config: Config) -> None:
    cwd = os.getcwd()
    server_proc = None
    server_log = None

    if is_server_running(config.mcp_port):
        log("server", f"Detected existing MCP server on :{config.mcp_port}; reusing.")
    else:
        server_proc, server_log = start_mcp_server(
            config.sectool_bin, config.proxy_port, config.mcp_port, config.workflow,
        )

    iteration = 0
    finding_writer = FindingWriter(config.findings_dir)
    candidates = CandidatePool()
    decisions = DecisionQueue()
    total_cost = 0.0

    try:
        if server_proc is not None:
            wait_for_server(config.mcp_port, server_proc)

        for key in [k for k in os.environ if k.startswith("CLAUDE")]:
            os.environ.pop(key, None)

        mcp_url = f"http://127.0.0.1:{config.mcp_port}/mcp"
        stderr_cb = (lambda line: log("claude", line.rstrip())) if config.verbose else None

        worker_tools_server = build_worker_mcp_server(candidates)
        orch_tools_server = build_orch_mcp_server(decisions)

        base_options = ClaudeAgentOptions(cwd=cwd, max_turns=100)
        if config.worker_model_id:
            base_options.model = config.worker_model_id

        verifier_options = ClaudeAgentOptions(
            mcp_servers={
                "sectool": {"type": "http", "url": mcp_url},
                "orch_tools": orch_tools_server,
            },
            allowed_tools=[ORCH_SECTOOL_TOOLS_GLOB] + list(VERIFIER_TOOL_ALLOWED),
            permission_mode="acceptEdits",
            cwd=cwd,
            max_turns=100,
            model=config.orchestrator_model_id,
            stderr=stderr_cb,
            system_prompt=verifier_prompts.build_system_prompt(config.max_workers),
        )

        director_options = ClaudeAgentOptions(
            mcp_servers={
                "orch_tools": orch_tools_server,
            },
            allowed_tools=list(DIRECTOR_TOOL_ALLOWED),
            permission_mode="acceptEdits",
            cwd=cwd,
            max_turns=100,
            model=config.orchestrator_model_id,
            stderr=stderr_cb,
            system_prompt=director_prompts.build_system_prompt(config.max_workers),
        )

        workers: list[WorkerState] = []
        verifier_managed: ManagedSDKClient | None = None
        director_managed: ManagedSDKClient | None = None

        try:
            # Initial worker
            log("worker", "Connecting Claude Code worker 1...")
            try:
                w1 = await create_worker(
                    1, 1, worker_tools_server, mcp_url, base_options, stderr_cb,
                )
                workers.append(w1)
            except Exception as exc:
                log("worker", f"Failed to connect worker 1: {exc}")
                raise SystemExit(1) from exc
            log("worker", "Worker 1 connected.")

            # Verifier and director clients
            try:
                verifier_managed = ManagedSDKClient(options=verifier_options)
                await verifier_managed.connect()
                log("verify", "Verifier connected.")
            except Exception as exc:
                await teardown_worker(workers[0])
                log("verify", f"Failed to connect verifier: {exc}")
                raise SystemExit(1) from exc

            try:
                director_managed = ManagedSDKClient(options=director_options)
                await director_managed.connect()
                log("direct", "Director connected.")
            except Exception as exc:
                await teardown_worker(workers[0])
                log("direct", f"Failed to connect director: {exc}")
                raise SystemExit(1) from exc

            # Initial prompt to worker 1
            workers[0].last_instruction = config.prompt
            workers[0].assignment = config.prompt
            try:
                await workers[0].client.query(config.prompt)
            except (ConnectionError, OSError) as exc:
                log("worker", f"Initial prompt failed: {exc}. Recovery...")
                if not await attempt_worker_recovery(workers[0]):
                    raise SystemExit(1)

            # Main loop
            for iteration in range(1, config.max_iterations + 1):
                alive = [w for w in workers if w.alive]
                if not alive:
                    log(f"iter {iteration}", "No alive workers. Stopping.")
                    break

                # 1) Autonomous worker phase
                budgets = ", ".join(f"w{w.worker_id}={w.autonomous_budget}" for w in alive)
                log(f"iter {iteration}",
                    f"Running {len(alive)} worker(s) autonomously ({budgets})...")
                worker_runs = await run_all_workers_until_escalation(
                    alive, iteration, candidates, verbose=config.verbose,
                )

                # Recover any connection-errored workers. With ManagedSDKClient
                # isolating each client's anyio scope on its own runner task,
                # the main task stays clean through cancellations and no
                # special draining is required here.
                for w in alive:
                    if w.escalation_reason == "error" and w.client is None:
                        recovered = await attempt_worker_recovery(w)
                        if recovered:
                            log(f"worker {w.worker_id}", "Recovered after autonomous run error.")

                # 2) Update stall tracking
                update_worker_streaks(alive)

                # 3) Cost + per-worker log
                for w in alive:
                    cost_this = sum((t.cost_usd or 0.0) for t in w.autonomous_turns)
                    total_cost += cost_this
                    log(f"iter {iteration}",
                        f"Worker {w.worker_id}: turns={len(w.autonomous_turns)} "
                        f"escalation={w.escalation_reason} cost=${cost_this:.4f}")

                if config.verbose:
                    for w in alive:
                        if not w.autonomous_turns:
                            continue
                        print(f"\n--- Worker {w.worker_id} autonomous run (iter {iteration}) ---")
                        for i, s in enumerate(w.autonomous_turns, 1):
                            print(f"[turn {i}] {s.assistant_text}")
                        print(f"--- End Worker {w.worker_id} autonomous run ---\n")

                if config.max_cost is not None and total_cost >= config.max_cost:
                    log(f"iter {iteration}", f"Cost ceiling reached (${total_cost:.2f}). Stopping.")
                    break

                # 4) Reset decisions for this iteration
                decisions.reset()

                # 5) Verification phase
                verifier_managed, v_cost, v_summary = await run_verification_phase(
                    verifier_managed, verifier_options, decisions, candidates,
                    finding_writer, worker_runs, workers, iteration,
                    config.max_iterations, total_cost, config.max_cost, config.verbose,
                )
                total_cost += v_cost

                if config.max_cost is not None and total_cost >= config.max_cost:
                    log(f"iter {iteration}", f"Cost ceiling reached (${total_cost:.2f}). Stopping.")
                    break

                # 6) Direction phase
                stall_warnings = _format_stall_warnings(workers)
                follow_up_hints = _format_follow_up_hints(
                    decisions.findings, decisions.dismissals,
                )
                director_managed, d_cost = await run_direction_phase(
                    director_managed, director_options, decisions, workers, worker_runs,
                    v_summary, finding_writer.summary_for_orchestrator(),
                    iteration, config.max_iterations, total_cost, config.max_cost,
                    finding_writer.count, stall_warnings, follow_up_hints, config.verbose,
                    config.max_workers,
                    config.prompt,
                )
                total_cost += d_cost

                for w in workers:
                    if w.alive and w.progress_none_streak >= STALL_WARN_AFTER:
                        w.stall_warned = True

                # 7) Done? — guard against premature termination on weak models
                # that conflate `done` with `direction_done`.
                if decisions.done_summary is not None:
                    if _is_premature_done(iteration, finding_writer.count):
                        log(f"iter {iteration}",
                            f"done ignored: premature "
                            f"(iter {iteration} < {MIN_ITERATIONS_FOR_DONE}, "
                            f"0 findings). Summary: "
                            f"{_short(decisions.done_summary, 120)}")
                        decisions.done_summary = None
                    else:
                        log(f"iter {iteration}",
                            f"Director: done — {_short(decisions.done_summary, 120)}")
                        break

                # 8) Plan diff
                if decisions.plan is not None:
                    await apply_plan_diff(
                        decisions.plan, workers, worker_tools_server, mcp_url,
                        base_options, stderr_cb, config.max_workers,
                    )

                # 9) Per-worker decisions
                #
                # Coalesce duplicate decisions the director may have issued
                # across substeps (continue_worker + expand_worker for the
                # same worker; stop after continue; etc). The apply loop
                # below then sees at most one decision per worker.
                original_decisions = list(decisions.worker_decisions)
                effective_decisions = coalesce_decisions(
                    original_decisions, decisions.plan,
                )
                if len(effective_decisions) != len(original_decisions):
                    log(f"iter {iteration}",
                        f"decision coalesced original={len(original_decisions)} "
                        f"effective={len(effective_decisions)}")
                decided_wids: set[int] = set()
                for d in effective_decisions:
                    worker = next((w for w in workers if w.worker_id == d.worker_id), None)
                    if worker is None or not worker.alive:
                        log(f"iter {iteration}",
                            f"Decision for unknown/dead worker {d.worker_id} — skipped.")
                        continue
                    await apply_decision(d, worker, iteration)
                    decided_wids.add(d.worker_id)

                # 10) Implicit continue for undirected alive workers
                worker_findings_summary = finding_writer.summary_for_worker()
                for w in workers:
                    if not w.alive or w.worker_id in decided_wids:
                        continue
                    if decisions.plan is not None and any(p.worker_id == w.worker_id for p in decisions.plan):
                        continue
                    log(f"iter {iteration}",
                        f"Worker {w.worker_id}: no explicit decision — implicit continue "
                        f"(budget={w.autonomous_budget}).")
                    try:
                        await w.client.query(_build_worker_continue_prompt(
                            findings_summary=worker_findings_summary,
                        ))
                    except (ConnectionError, OSError):
                        await attempt_worker_recovery(w)

                # 11) Forced stop for stalled workers
                for w in list(workers):
                    if w.alive and w.progress_none_streak >= STALL_STOP_AFTER:
                        log(f"iter {iteration}",
                            f"Worker {w.worker_id}: stalled past threshold "
                            f"({w.progress_none_streak} silent escalations). Stopping.")
                        await teardown_worker(w)

            else:
                log("summary", f"Max iterations ({config.max_iterations}) reached.")

        finally:
            alive_count = sum(1 for w in workers if w.alive)
            for w in workers:
                if w.alive:
                    await teardown_worker(w)
            for managed in (verifier_managed, director_managed):
                if managed is not None:
                    await managed.aclose()

        print()
        log("summary",
            f"Workers: {alive_count}/{len(workers)} | Iterations: {iteration} | "
            f"Findings: {finding_writer.count} | Cost: ${total_cost:.2f}")
        if finding_writer.paths:
            log("summary", "Finding files:")
            for path in finding_writer.paths:
                print(f"              {path}")

    finally:
        if server_proc is not None:
            terminate_process(server_proc, server_log)
            log("server", "MCP server terminated.")


def main() -> None:
    config = parse_args()
    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:
        print()
        log("ctrl-c", "Interrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
