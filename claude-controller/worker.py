"""Worker subsystem: SDK client lifecycle, turn collection, autonomous loop.

The worker is the LLM-facing role that drives sectool to find candidates.
Each worker owns a `ManagedSDKClient` (running the SDK in its own asyncio
task to isolate anyio cancel scopes) and a `WorkerState` of accumulated
context. The autonomous loop runs each alive worker for up to its budget of
turns, escalating on candidate / silent / infra / error / rate_limit.
"""

import asyncio
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

from prompts import worker as worker_prompts
from runtime import (
    _clear_leaked_cancellations,
    _short,
    _summarize_input,
    _summarize_result,
    engage_rate_limit_pause,
    inflight,
    log,
    submit_query,
)
from tools import (
    DEFAULT_AUTONOMOUS_BUDGET,
    MAX_AUTONOMOUS_BUDGET,
    WORKER_TOOL_ALLOWED,
    CandidatePool,
    ToolCallRecord,
    WorkerTurnSummary,
    build_worker_mcp_server,
    extract_flow_ids,
)
from bash_tool import BASH_BUILTIN_DENIED, BASH_TOOL_ALLOWED


# ---------------------------------------------------------------------------
# Managed SDK client — isolates the SDK's internal anyio cancel scope
# ---------------------------------------------------------------------------

# Runner-task wait bounds (seconds). The runner's entry and exit paths are
# SDK transport setup/teardown, which can hang on a stalled CLI process;
# every wait is bounded so the event loop never blocks indefinitely.
RUNNER_CONNECT_TIMEOUT = 60.0
RUNNER_CLOSE_TIMEOUT = 30.0


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
        """Start the runner task and return the entered underlying client.

        Raises TimeoutError when the SDK subprocess doesn't come up within
        RUNNER_CONNECT_TIMEOUT — the runner is drained so nothing leaks.
        """
        self._runner = asyncio.create_task(self._run())
        try:
            await asyncio.wait_for(self._ready.wait(), timeout=RUNNER_CONNECT_TIMEOUT)
        except BaseException:
            # Caller cancelled us or connect timed out; make sure the runner
            # doesn't leak.
            self._stop.set()
            runner = self._runner
            self._runner = None
            if runner is not None:
                await _await_runner(runner, RUNNER_CLOSE_TIMEOUT, cancel_first=True)
            raise
        if self._enter_exc is not None:
            # Propagate a failed __aenter__ so the caller can handle it.
            self._runner = None
            raise self._enter_exc
        assert self._client is not None
        return self._client

    async def aclose(self) -> None:
        """Signal the runner to exit and await its completion, bounded.

        Uses `asyncio.wait` rather than awaiting the runner directly so a
        CancelledError raised inside the runner is captured as a task result
        instead of propagating. Past RUNNER_CLOSE_TIMEOUT the runner is
        cancelled; if teardown still doesn't finish it's abandoned with a log
        and this method proceeds rather than hanging the event loop.
        """
        if self._runner is None:
            self._client = None
            return
        self._stop.set()
        runner = self._runner
        self._runner = None
        await _await_runner(runner, RUNNER_CLOSE_TIMEOUT)
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


async def _await_runner(
    runner: asyncio.Task, timeout: float, *, cancel_first: bool = False,
) -> bool:
    """Await a runner task up to `timeout`, cancelling it when it overruns.

    Uses `asyncio.wait` so a CancelledError raised inside the runner is
    captured as a task result instead of propagating. `cancel_first` skips
    the stop-signal grace period — used when aborting an SDK entry that never
    completed and only cancellation unwinds. Returns False when the runner had
    to be abandoned (still pending past cancel + timeout); callers proceed
    rather than hanging the event loop.
    """
    if not runner.done() and not cancel_first:
        await asyncio.wait([runner], timeout=timeout)
    if runner.done():
        return True
    log("sdk", f"Runner task hung; cancelling (deadline {timeout:.0f}s).")
    runner.cancel()
    await asyncio.wait([runner], timeout=timeout)
    if not runner.done():
        log("sdk", "Runner task still hung after cancel; abandoning it.")
        return False
    return True


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
    # Per-worker hard cap on autonomous_budget. None = use MAX_AUTONOMOUS_BUDGET.
    # The recon worker is initialised with a low cap so the director cannot
    # later expand it past the configured --recon-budget.
    max_autonomous_budget: int | None = None
    escalation_reason: str | None = None
    autonomous_turns: list[WorkerTurnSummary] = field(default_factory=list)
    # True for the iter-1 recon worker. Survives teardown so the director's
    # stopped-list can label it and avoid conflating it with a real worker
    # that was stopped mid-run.
    is_recon: bool = False


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

    Worker attribution for finding candidates is closure-bound on the
    per-worker MCP server (see `build_worker_mcp_server`), so it survives
    the SDK dispatching tool handlers on its own runner task.

    No per-turn timeout: the SDK's `receive_response` generator is consumed
    to completion. Connection errors and external cancellations are handled
    by the caller (`run_worker_autonomous_turn`).
    """
    candidates_before = candidates.counter

    summary = WorkerTurnSummary(worker_id=worker_id, iteration=iteration)
    pending_calls: dict[str, ToolCallRecord] = {}

    async with inflight(f"worker {worker_id}"):
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        summary.assistant_text += (block.text or "")
                        if verbose_tag:
                            first = (block.text or "").strip().split("\n", 1)[0]
                            if first:
                                log(verbose_tag, _short(first, 120))
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
                if message.error == "rate_limit":
                    summary.rate_limited = True
                    summary.rate_limit_text = "".join(
                        b.text for b in message.content if isinstance(b, TextBlock)
                    )
                elif message.error:
                    # Auth/billing/server literals: the turn died on
                    # infrastructure rather than idling.
                    summary.infra_error = f"assistant {message.error}"
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
                if message.is_error and not summary.infra_error:
                    # Error-flagged results carry the CLI failure subtype
                    # (execution failure, max-turns) plus a detail string.
                    detail = _short(" ".join(str(message.result or "").split()), 200)
                    summary.infra_error = (
                        f"result {message.subtype}" + (f": {detail}" if detail else "")
                    )
                break

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
    *,
    is_recon: bool = False,
    user_prompt: str | None = None,
    bash_tools_server=None,
) -> ClaudeAgentOptions:
    allow_bash = bash_tools_server is not None
    mcp_servers = {
        "sectool": {"type": "http", "url": mcp_url},
        "worker_tools": worker_tools_server,
    }
    allowed_tools = [
        "mcp__sectool__*",
        WORKER_TOOL_ALLOWED,
        "Read", "Glob", "Grep",
    ]
    if allow_bash:
        mcp_servers["bash_tools"] = bash_tools_server
        allowed_tools.append(BASH_TOOL_ALLOWED)
    return ClaudeAgentOptions(
        mcp_servers=mcp_servers,
        allowed_tools=allowed_tools,
        disallowed_tools=["Write", "Edit", BASH_BUILTIN_DENIED],
        permission_mode="acceptEdits",
        cwd=base.cwd,
        max_turns=base.max_turns,
        model=base.model,
        stderr=stderr_cb,
        system_prompt=worker_prompts.build_system_prompt(
            worker_id, num_workers, is_recon=is_recon, user_prompt=user_prompt,
            allow_bash=allow_bash,
        ),
    )


async def create_worker(
    worker_id: int,
    num_workers: int,
    candidates: CandidatePool,
    mcp_url: str,
    base: ClaudeAgentOptions,
    stderr_cb,
    *,
    is_recon: bool = False,
    user_prompt: str | None = None,
    bash_tools_server=None,
) -> WorkerState:
    worker_tools_server = build_worker_mcp_server(candidates, worker_id)
    opts = _build_worker_options(
        base, worker_tools_server, mcp_url, worker_id, num_workers, stderr_cb,
        is_recon=is_recon, user_prompt=user_prompt,
        bash_tools_server=bash_tools_server,
    )
    managed = ManagedSDKClient(options=opts)
    client = await managed.connect()
    return WorkerState(worker_id=worker_id, options=opts, client=client, managed=managed)


async def teardown_worker(state: WorkerState) -> None:
    state.alive = False
    if state.managed is not None:
        await state.managed.aclose()
    state.client = None
    state.managed = None


async def attempt_worker_recovery(
    state: WorkerState,
    shutdown_event: asyncio.Event | None = None,
) -> bool:
    """Tear down and rebuild an errored worker, resubmitting its last instruction.

    Returns True when the worker is usable again. Refused without any query
    once `shutdown_event` (when provided) has fired — recovery re-bills the
    last instruction, whose answer would be discarded after shutdown.
    """
    if shutdown_event is not None and shutdown_event.is_set():
        return False
    await teardown_worker(state)
    for attempt in range(1, 3):
        managed: ManagedSDKClient | None = None
        try:
            await asyncio.sleep(2)
            managed = ManagedSDKClient(options=state.options)
            client = await managed.connect()
            # Resubmit before committing state so a failed resubmission can
            # never strand the freshly connected client. Re-check at the
            # billing gate too: Ctrl-C can land mid-recovery.
            shutting_down = shutdown_event is not None and shutdown_event.is_set()
            if state.last_instruction and not shutting_down:
                await submit_query(client, state.last_instruction)
        except Exception as exc:
            log(f"worker {state.worker_id}", f"Recovery attempt {attempt} failed: {exc}")
            # The client was never committed to `state`; close it here or its
            # runner task and subprocess leak for the rest of the run.
            if managed is not None:
                await managed.aclose()
            continue
        state.managed = managed
        state.client = client
        state.alive = True
        log(f"worker {state.worker_id}", f"Recovery succeeded (attempt {attempt})")
        return True
    state.alive = False
    return False


_RECON_SYNTHESIS_QUERY = (
    "Output your recon synthesis now. Two sections only — "
    "`## Surface map` and `## Recommended worker focuses`. "
    "No tool calls; do not narrate. End immediately after the second section."
)

_RECON_SUMMARY_PLACEHOLDER = (
    "(Recon worker produced no synthesis output. "
    "Slice the surface from the user assignment.)"
)


async def synthesize_and_teardown_recon(
    worker: WorkerState,
    candidates: CandidatePool,
    iteration: int,
    verbose: bool,
) -> tuple[str, float]:
    """Drive a final synthesis turn from the recon worker, then tear it down.

    Sends an explicit synthesis query, drains the response with
    `collect_worker_turn`, and returns the captured assistant text plus the
    turn cost. The worker's SDK client is closed regardless of synthesis
    success so its conversation history is dropped before iter 2.

    Returns (summary, cost). On any failure, falls back to the worker's
    last autonomous-turn assistant_text, then to a placeholder string.
    """
    cost = 0.0
    summary_text = ""

    if worker.client is None or not worker.alive:
        # Recon worker died during the autonomous run; salvage what we can.
        if worker.autonomous_turns:
            summary_text = worker.autonomous_turns[-1].assistant_text.strip()
        return summary_text or _RECON_SUMMARY_PLACEHOLDER, cost

    log(f"worker {worker.worker_id}", "Synthesizing recon report...")
    tag = f"w{worker.worker_id}" if verbose else None
    try:
        await submit_query(worker.client, _RECON_SYNTHESIS_QUERY)
        synth_turn = await collect_worker_turn(
            worker.client, worker.worker_id, iteration, candidates, tag,
        )
        summary_text = synth_turn.assistant_text.strip()
        if synth_turn.cost_usd:
            cost += synth_turn.cost_usd
    except Exception as exc:
        log(f"worker {worker.worker_id}", f"Synthesis failed: {exc}")

    if not summary_text and worker.autonomous_turns:
        # Synthesis returned empty (refusal, max_turns exhaustion, connection
        # blip): salvage the worker's last autonomous-turn narration. Any
        # non-empty synthesis is preserved verbatim — formatting varies
        # across models (## vs **bold** vs plain text) and the director can
        # work with imperfect shape better than with raw tool-call narration.
        fallback = worker.autonomous_turns[-1].assistant_text.strip()
        if fallback:
            summary_text = fallback

    await teardown_worker(worker)
    log(f"worker {worker.worker_id}", "Recon worker torn down.")

    return summary_text or _RECON_SUMMARY_PLACEHOLDER, cost


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


async def _race_with_abort(
    coro,
    abort_event: asyncio.Event | None,
):
    """Await `coro`; if `abort_event` fires first, cancel coro and return (None, True).

    On normal completion returns (result, False). When `abort_event` is None
    this just awaits coro and returns (result, False) — the no-abort path.
    Caller cancellation cancels and awaits both raced tasks before propagating,
    so a raced substep never outlives its caller unowned.
    """
    if abort_event is None:
        return await coro, False
    task = asyncio.create_task(coro)
    waiter = asyncio.create_task(abort_event.wait())
    try:
        done, _ = await asyncio.wait(
            [task, waiter], return_when=asyncio.FIRST_COMPLETED,
        )
    except BaseException:
        # Caller cancelled mid-race: settle both children so the substep
        # never runs unowned, then let cancellation propagate.
        task.cancel()
        waiter.cancel()
        await asyncio.gather(task, waiter, return_exceptions=True)
        raise
    if task in done:
        waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)
        return task.result(), False
    # Abort won: cancel the substep and settle it before reporting.
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return None, True


async def reset_orchestrator_client(
    old_managed: ManagedSDKClient | None,
    options: ClaudeAgentOptions,
    tag: str,
) -> ManagedSDKClient | None:
    """Tear down and rebuild an orchestrator client to drop accumulated context.

    Builds the new client first; only closes the old one on successful
    connect. Returns None on failure so the caller can fall back to the
    existing client.
    """
    try:
        managed = ManagedSDKClient(options=options)
        await managed.connect()
    except Exception as exc:
        log(tag, f"Reset failed (keeping old client): {exc}")
        return None
    if old_managed is not None:
        # The new client is already live, so an aclose failure on the old
        # one is non-fatal — we just leak its resources for the rest of the
        # run rather than crashing the phase.
        try:
            await old_managed.aclose()
        except Exception as exc:
            log(tag, f"Old client aclose failed (continuing): {exc}")
    return managed


# ---------------------------------------------------------------------------
# Autonomous worker runs
# ---------------------------------------------------------------------------

# Termination reasons surfaced to the director via WorkerState.escalation_reason.
ESCALATION_CANDIDATE = "candidate"
ESCALATION_SILENT = "silent"
ESCALATION_INFRA = "infra"
ESCALATION_ERROR = "error"
ESCALATION_RATE_LIMIT = "rate_limit"
ESCALATION_BUDGET = "budget"

# Every observable value; the director prompt legend documents each.
ESCALATION_REASONS = (
    ESCALATION_CANDIDATE,
    ESCALATION_SILENT,
    ESCALATION_INFRA,
    ESCALATION_ERROR,
    ESCALATION_RATE_LIMIT,
    ESCALATION_BUDGET,
)


def _classify_escalation(summary: WorkerTurnSummary) -> str | None:
    """Return an escalation reason, or None if the turn was productive."""
    if summary.candidate_ids:
        return ESCALATION_CANDIDATE
    if summary.infra_error:
        # Infrastructure failures must not read as silent stalls.
        return ESCALATION_INFRA
    if not summary.tool_calls and not summary.flow_ids_touched:
        return ESCALATION_SILENT
    return None


async def run_worker_autonomous_turn(
    worker: WorkerState,
    iteration: int,
    candidates: CandidatePool,
    verbose: bool,
) -> tuple[WorkerTurnSummary | None, str | None]:
    """Drain one turn from the worker; classify as candidate/infra/silent/None.

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
    except Exception as exc:
        log(f"worker {worker.worker_id}", f"Connection lost: {exc}")
        return None, ESCALATION_ERROR

    if summary.rate_limited:
        engage_rate_limit_pause(summary.rate_limit_text)
        # Drop this worker's remaining autonomous budget for the iteration.
        # The iteration's verify+direct still runs on whatever candidates the
        # surviving turns produced; the pause holds before the next iteration.
        return summary, ESCALATION_RATE_LIMIT

    reason = _classify_escalation(summary)
    if reason == ESCALATION_INFRA:
        log(f"worker {worker.worker_id}", f"Infrastructure failure: {summary.infra_error}")
    return summary, reason


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
    # Lazy import: _build_worker_continue_prompt lives in controller.py with
    # the rest of the prompt-formatting cluster. Importing at module level
    # would create a worker↔controller cycle. This seam goes away when the
    # prompt cluster is extracted in a follow-up split.
    from controller import _build_worker_continue_prompt

    run_turns: list[WorkerTurnSummary] = []
    budget = max(1, min(MAX_AUTONOMOUS_BUDGET, worker.autonomous_budget))

    for attempt in range(budget):
        if attempt > 0:
            try:
                # Intra-iteration between-turn requery: tokens precious,
                # skip the findings roster.
                await submit_query(
                    worker.client,
                    _build_worker_continue_prompt(findings_summary=""),
                )
            except Exception as exc:
                log(f"worker {worker.worker_id}", f"Continue query failed: {exc}")
                worker.escalation_reason = ESCALATION_ERROR
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

    worker.escalation_reason = ESCALATION_BUDGET
    return run_turns


async def run_all_workers_until_escalation(
    workers: list[WorkerState],
    iteration: int,
    candidates: CandidatePool,
    verbose: bool = False,
    shutdown_event: asyncio.Event | None = None,
) -> dict[int, list[WorkerTurnSummary]]:
    """Run every alive worker concurrently until all have escalated.

    A CancelledError in one worker's task (e.g. from a leaked SDK cancel
    scope after a prior timeout) is isolated: that worker is marked
    escalation_reason="error" for the main-loop recovery path, but the
    other workers' results are preserved.

    When `shutdown_event` is provided and fires, all in-flight worker
    tasks are cancelled — the per_worker handler treats this as the
    same recovery path as a leaked cancel scope.

    Cancellation delivered into the calling task itself (an external stop)
    is not a worker-level event: the remaining workers are cancelled and
    settled, then the cancellation propagates without draining standard
    cancel bookkeeping.

    Any other exception escaping a worker task is collected and reported
    once all tasks settle, with the failed worker marked
    escalation_reason="error" like the cancellation path. Sibling runs
    finish untouched and their results are preserved.
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
            w.escalation_reason = ESCALATION_ERROR
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

    watcher: asyncio.Task | None = None
    if shutdown_event is not None:
        async def _watch_shutdown() -> None:
            await shutdown_event.wait()
            for t in tasks:
                if not t.done():
                    t.cancel()
        watcher = asyncio.create_task(_watch_shutdown())

    results: dict[int, list[WorkerTurnSummary]] = {}
    failures: list[str] = []
    # First cancellation delivered into this task (children absorb their own,
    # so those never reach this frame). Re-raised after settlement.
    own_cancel: asyncio.CancelledError | None = None

    def _note_task_cancellation(exc: asyncio.CancelledError) -> None:
        """Record a cancellation genuinely delivered into the current task.

        An escaping CancelledError belongs to this task only when the task
        has pending cancel counts; otherwise it re-raises a child that died
        mid-cleanup. The first genuine hit stops the remaining children so
        nothing outlives us; it is re-raised below, never drained.
        """
        nonlocal own_cancel
        if own_cancel is not None:
            return
        task = asyncio.current_task()
        cancelling = getattr(task, "cancelling", None)
        if callable(cancelling) and cancelling() > 0:
            log("worker", "Worker run interrupted by external cancellation.")
            for extra in tasks:
                if not extra.done():
                    extra.cancel()
            own_cancel = exc

    # Settle every task before returning: one worker's exception must never
    # leave siblings running into teardown and the next phase.
    for w, t in zip(alive, tasks):
        try:
            wid, runs = await t
            results[wid] = runs
        except asyncio.CancelledError as exc:
            _note_task_cancellation(exc)
        except Exception as exc:
            w.escalation_reason = ESCALATION_ERROR
            failures.append(f"worker {w.worker_id} failed: {_short(repr(exc), 160)}")

    if failures:
        log("worker", f"{len(failures)} worker task(s) raised; siblings settled: "
                      + "; ".join(failures))

    if watcher is not None and not watcher.done():
        watcher.cancel()
        try:
            await watcher
        except asyncio.CancelledError as exc:
            _note_task_cancellation(exc)
        except Exception:
            pass

    if own_cancel is not None:
        # Settle the children cancelled above, then propagate untouched —
        # draining here would erase the caller's cancellation signal.
        await asyncio.gather(*tasks, return_exceptions=True)
        raise own_cancel

    # No cancellation was delivered into this task on any path above, so any
    # residual counts are SDK cancel-scope leaks from a worker timeout. Drain
    # them before returning or they poison the main loop's next await (e.g.
    # attempt_worker_recovery's asyncio.sleep).
    _clear_leaked_cancellations("worker")
    return results
