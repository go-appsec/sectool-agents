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
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
)

from config import Config, parse_args
from findings import FindingWriter, match_pending_candidates
from keypress import start_spacebar_listener
from prompts import orchestrator_director as director_prompts
from prompts import orchestrator_verifier as verifier_prompts
from runtime import (
    _short,
    _status_bar,
    _status_tick,
    engage_rate_limit_pause,
    inflight,
    log,
    submit_query,
    toggle_pause,
)
from tools import (
    DIRECTION_SELF_REVIEW_MAX_ROUNDS,
    DIRECTOR_TOOL_ALLOWED,
    MAX_AUTONOMOUS_BUDGET,
    MIN_ITERATIONS_FOR_DONE,
    PHASE_DIRECTION,
    PHASE_VERIFICATION,
    VERIFIER_TOOL_ALLOWED,
    CandidateDismissal,
    CandidatePool,
    DecisionQueue,
    FindingCandidate,
    FindingFiled,
    FindingMerged,
    PlanEntry,
    ToolCallRecord,
    WorkerDecision,
    WorkerTurnSummary,
    build_orch_mcp_server,
    coalesce_decisions,
)
from worker import (
    ManagedSDKClient,
    WorkerState,
    _race_with_abort,
    attempt_client_recovery,
    attempt_worker_recovery,
    create_worker,
    reset_orchestrator_client,
    run_all_workers_until_escalation,
    synthesize_and_teardown_recon,
    teardown_worker,
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


# ---------------------------------------------------------------------------
# Build and server lifecycle
# ---------------------------------------------------------------------------


def start_mcp_server(
    sectool_bin: str, proxy_port: int, mcp_port: int,
) -> tuple[subprocess.Popen, "io.TextIOWrapper"]:
    cmd = [
        sectool_bin, "mcp",
        f"--proxy-port={proxy_port}",
        f"--port={mcp_port}",
        "--workflow=multi",
    ]
    log_path = os.path.abspath("sectool-mcp.log")
    log_file = open(log_path, "w")  # noqa: SIM115
    log("server", f"Starting sectool MCP server on :{mcp_port} (proxy :{proxy_port})")
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


def _is_premature_done(iteration: int, findings_count: int) -> bool:
    """Reject `done` when the run has made no visible progress yet.

    Mirrors secagent's MinIterationsForDone guard: local/weak models routinely
    conflate `done` with `direction_done` on early iterations.
    """
    return iteration < MIN_ITERATIONS_FOR_DONE and findings_count == 0


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


def _format_pending_candidates_brief(pending: list[FindingCandidate]) -> str:
    """One-line-per-candidate roster for the director.

    Bounded and cheap: a busy run with 20 pending candidates is ~1.6KB.
    The director uses this to write `DO NOT TEST:` exclusion blocks into
    worker assignments — it does not need full reproduction hints.
    """
    if not pending:
        return ""
    lines = ["**Pending candidates (filed but not yet verified — keep workers off these):**"]
    for c in pending:
        lines.append(
            f"- `{c.candidate_id}` [{c.severity}] {c.title} — {c.endpoint} (worker {c.worker_id})"
        )
    return "\n".join(lines)


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
        "Reproduce and dispose of every pending candidate. "
        "`verification_done(summary)` when all are filed or dismissed.",
    ]
    return "\n".join(parts)


def _build_verifier_continue_prompt(
    *,
    pending: list[FindingCandidate],
    filed_this_phase: list[FindingFiled],
    merged_this_phase: list[FindingMerged],
    dismissed_this_phase: list[CandidateDismissal],
    substep: int,
    max_substeps: int,
) -> str:
    """Continue-prompt for the verifier between substeps.

    Lists actual titles filed, finding_ids merged into, and candidate ids
    dismissed this phase so the model stops re-announcing the same
    dispositions each substep.
    """
    parts = [
        (
            f"**Verification substep {substep}/{max_substeps}.** "
            f"Filed {len(filed_this_phase)}, "
            f"merged {len(merged_this_phase)}, "
            f"dismissed {len(dismissed_this_phase)} so far."
        ),
    ]
    if filed_this_phase:
        parts.append("")
        parts.append("Already filed this phase (do not re-file):")
        for f in filed_this_phase:
            parts.append(f"- {f.title}")
    if merged_this_phase:
        parts.append("")
        parts.append("Already merged this phase:")
        for m in merged_this_phase:
            parts.append(f"- into {m.finding_id}: {_short(m.rationale, 80)}")
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
    merges: list[FindingMerged],
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
    for m in merges:
        h = m.follow_up_hint.strip()
        if h:
            lines.append(f"- (merged into {m.finding_id}) {h}")
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
    pending_candidates: list[FindingCandidate],
    verification_summary: str,
    findings_summary: str,
    iteration: int, max_iter: int,
    total_cost: float, max_cost: float | None,
    findings_count: int,
    stall_warnings: str,
    follow_up_hints: str,
    max_workers: int,
    user_prompt: str,
    recon_summary: str | None = None,
) -> str:
    parts = [
        _format_status_line(iteration, max_iter, total_cost, max_cost, findings_count),
        "",
        f"**Assignment (user prompt):** {user_prompt}",
    ]
    # The recon report is sent only on iter 1 — the director's SDK client
    # carries it forward in conversation history for subsequent iterations,
    # so re-sending would just burn tokens.
    if iteration == 1 and recon_summary:
        parts.extend([
            "",
            "## Recon report (from initial recon worker — already torn down; you have no live workers)",
            recon_summary,
        ])
    parts.extend([
        "",
        findings_summary,
        "",
        f"**Verification:** {verification_summary}",
    ])
    pending_brief = _format_pending_candidates_brief(pending_candidates)
    if pending_brief:
        parts.append("")
        parts.append(pending_brief)
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
    stopped_labels: list[str] = []
    for w in workers:
        if w.alive:
            continue
        label = f"{w.worker_id} (recon)" if w.is_recon else str(w.worker_id)
        stopped_labels.append(label)
    if stopped_labels:
        parts.append(
            f"Stopped this run: [{', '.join(stopped_labels)}] "
            "(do not re-plan around these; pick fresh worker_ids for new workers)."
        )

    # Iteration 1 is the attack-surface dispatch moment. The recon worker
    # is gone; fan-out via plan_workers is the only way to start work.
    if iteration == 1:
        parts.append("")
        parts.append(
            "**Iteration 1: no live workers — `plan_workers` is mandatory.** "
            "Use the `## Recon report` above (especially `Recommended worker focuses`) "
            "to spawn 3–4 disjoint specialised workers with fresh worker_ids NOW. "
            "Only stay at one worker if the assignment names a single endpoint or "
            "a single flow. Recon recommendations are priors, not directives — "
            "override or ignore them where the user's assignment dictates."
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


async def run_phase_substep(
    client: ClaudeSDKClient,
    user_content: str,
    phase: str,
    iteration: int,
    substep: int,
    verbose: bool,  # noqa: ARG001 — kept for API stability
) -> tuple[bool, float | None]:
    """Send a substep message and drain, streaming assistant text live.

    Returns (ok, cost). On error ok=False. Tool calls are silent — the user
    sees the verifier/director's reasoning text as it arrives, with a
    closing line carrying the substep cost.
    """
    label = "Verifier" if phase == PHASE_VERIFICATION else "Director"
    tag = _phase_tag(phase)
    print(flush=True)
    print(f"=== {label} (iter {iteration}, substep {substep}) ===", flush=True)
    cost: float | None = None
    saw_text = False
    # Retry on rate_limit: submit_query at the top blocks on the gate, so
    # after engage_rate_limit_pause clears it (manual spacebar resume), the
    # next loop iteration re-issues the same prompt. Other errors fall through
    # to the existing exception path.
    while True:
        saw_rate_limit = False
        try:
            await submit_query(client, user_content)
            async with inflight(f"{label.lower()} sub {substep}"):
                async for msg in client.receive_response():
                    if isinstance(msg, AssistantMessage):
                        for block in msg.content:
                            if isinstance(block, TextBlock):
                                chunk = (block.text or "").strip()
                                if chunk:
                                    # Print first line live, truncate the rest
                                    lines = chunk.splitlines()
                                    if len(lines) == 1:
                                        print(_short(lines[0], 200), flush=True)
                                    else:
                                        print(_short(lines[0], 200), flush=True)
                                        print(f"  ... ({len(lines) - 1} more lines)", flush=True)
                                    saw_text = True
                        if msg.error == "rate_limit":
                            saw_rate_limit = True
                            text = "".join(
                                b.text for b in msg.content if isinstance(b, TextBlock)
                            )
                            engage_rate_limit_pause(text)
                    elif isinstance(msg, ResultMessage):
                        cost = msg.total_cost_usd
                        break
        except Exception as exc:
            log(tag, f"Substep error iter {iteration} sub {substep}: {exc}")
            return False, None
        if not saw_rate_limit:
            break

    if not saw_text:
        print("(no text output)", flush=True)
    cost_str = f" cost=${cost:.4f}" if cost is not None else ""
    print(f"=== end {label} substep{cost_str} ===", flush=True)
    print(flush=True)
    return True, cost


# ---------------------------------------------------------------------------
# Verification phase
# ---------------------------------------------------------------------------


async def run_verification_phase(
    managed: ManagedSDKClient,
    options: ClaudeAgentOptions | None,
    decisions: DecisionQueue,
    candidates: CandidatePool,
    finding_writer: FindingWriter,
    iteration: int,
    max_iter: int,
    total_cost: float,
    max_cost: float | None,
    verbose: bool,
    abort_event: asyncio.Event | None = None,
) -> tuple[ManagedSDKClient, float, str]:
    """Drive the verifier over up to VERIFICATION_MAX_SUBSTEPS substeps.

    Applies findings/dismissals incrementally so each substep's prompt
    reflects the current state. Exits when the verifier calls
    `verification_done`, when no pending candidates remain, or at the cap.

    Resets the verifier client before iteration ≥ 2 to drop the prior
    iteration's context. This is a cost-vs-context trade-off: carrying
    the prior iteration's transcript would help the verifier recognise
    re-reports of an already-dismissed candidate, but each candidate
    arrives with self-contained evidence (flow_ids, reproduction_hint,
    summary) and the per-iteration context cost grows quickly. We
    favour reset; if false-positive recurrence becomes a real problem,
    revisit this trade-off rather than the comment.
    """
    decisions.begin_phase(PHASE_VERIFICATION)
    phase_cost = 0.0

    if not candidates.pending():
        log("verify", "No pending candidates; skipping verification phase.")
        return managed, phase_cost, "No pending candidates this iteration."

    # Per-iteration verifier reset to prevent context compounding. Iter 1
    # uses the freshly-spawned verifier from run() startup. options=None
    # is the test-mode signal — skip reset.
    if options is not None and iteration > 1:
        fresh = await reset_orchestrator_client(managed, options, "verify")
        if fresh is not None:
            managed = fresh
            log("verify", f"Verifier client reset for iteration {iteration}.")

    applied_findings = 0
    applied_dismissals = 0
    processed_merges = 0
    successful_merges: list[FindingMerged] = []

    for substep in range(1, VERIFICATION_MAX_SUBSTEPS + 1):
        if abort_event is not None and abort_event.is_set():
            log("verify",
                f"Aborted by user at substep {substep}; "
                f"{len(candidates.pending())} candidate(s) still pending.")
            break

        pending = candidates.pending()
        if not pending:
            break

        if substep == 1:
            user_content = _build_verifier_prompt(
                pending=pending,
                findings_summary=finding_writer.summary_for_verifier(),
                iteration=iteration, max_iter=max_iter,
                total_cost=total_cost + phase_cost,
                max_cost=max_cost,
                findings_count=finding_writer.count,
            )
        else:
            user_content = _build_verifier_continue_prompt(
                pending=pending,
                filed_this_phase=decisions.findings[:applied_findings],
                merged_this_phase=successful_merges,
                dismissed_this_phase=decisions.dismissals[:applied_dismissals],
                substep=substep,
                max_substeps=VERIFICATION_MAX_SUBSTEPS,
            )

        result, aborted = await _race_with_abort(
            run_phase_substep(
                managed.client, user_content, PHASE_VERIFICATION, iteration, substep, verbose,
            ),
            abort_event,
        )
        if aborted:
            log("verify", f"Substep {substep} aborted by user mid-flight.")
            break
        ok, cost = result
        if not ok:
            new_managed = await attempt_client_recovery(managed, options, "verify")
            if new_managed is not None:
                managed = new_managed
            log("verify", f"Aborting verification phase at substep {substep}.")
            break
        if cost is not None:
            phase_cost += cost

        # Apply new findings this substep produced. `seen_titles` dedups
        # burst `file_finding` calls within one response — cross-finding dedup
        # is the verifier's call (it can `merge_into_finding` instead of
        # filing a near-duplicate; see verifier prompt).
        seen_titles: set[str] = set()
        for filed in decisions.findings[applied_findings:]:
            title_key = filed.title.strip().lower()
            if title_key and title_key in seen_titles:
                log("finding", f"Duplicate (same substep) skipped: {filed.title}")
                continue
            if title_key:
                seen_titles.add(title_key)
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

        for mg in decisions.merges[processed_merges:]:
            path = finding_writer.merge(
                mg.finding_id,
                rationale=mg.rationale,
                additional_endpoint=mg.additional_endpoint,
                evidence_note=mg.evidence_note,
            )
            if path is None:
                log("finding",
                    f"Merge skipped: unknown finding_id {mg.finding_id!r}.")
                continue
            log("finding",
                f"Merged into {mg.finding_id}: {_short(mg.rationale, 80)} → {path}")
            successful_merges.append(mg)
            for cid in mg.supersedes_candidate_ids:
                if candidates.mark(cid, "verified"):
                    log("finding",
                        f"Candidate {cid} marked verified via merge into {mg.finding_id}.")
        processed_merges = len(decisions.merges)

        if decisions.verification_done_summary is not None:
            break

    summary = (
        decisions.verification_done_summary
        or f"Verification phase ended with {applied_findings} filed, "
           f"{len(successful_merges)} merged, {applied_dismissals} dismissed, "
           f"{len(candidates.pending())} still pending."
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
    pending_candidates: list[FindingCandidate],
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
    recon_summary: str | None = None,
    abort_event: asyncio.Event | None = None,
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
        if abort_event is not None and abort_event.is_set():
            log("direct", f"Aborted by user at substep {substep}.")
            aborted = True
            break

        covered = {d.worker_id for d in decisions.worker_decisions}
        if decisions.plan is not None:
            covered |= {p.worker_id for p in decisions.plan}
        pending_wids = alive_ids - covered

        if substep == 1:
            user_content = _build_director_prompt(
                workers=workers,
                worker_runs=worker_runs,
                pending_candidates=pending_candidates,
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
                recon_summary=recon_summary,
            )
        else:
            user_content = _build_director_continue_prompt(
                pending_wids=pending_wids,
                substep=substep,
                max_substeps=DIRECTION_MAX_SUBSTEPS,
            )

        result, raced = await _race_with_abort(
            run_phase_substep(
                managed.client, user_content, PHASE_DIRECTION, iteration, substep, verbose,
            ),
            abort_event,
        )
        if raced:
            log("direct", f"Substep {substep} aborted by user mid-flight.")
            aborted = True
            break
        ok, cost = result
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
    candidates: CandidatePool,
    mcp_url: str,
    base_options: ClaudeAgentOptions,
    stderr_cb,
    max_workers: int,
    recon_summary: str | None = None,
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
                await submit_query(w.client, p.assignment)
            except Exception:
                await attempt_worker_recovery(w)
        else:
            if len(existing_ids) >= max_workers:
                log(f"worker {p.worker_id}", f"Spawn skipped: max_workers={max_workers} reached.")
                continue
            num_workers_total = max(1, total_after)
            log(f"worker {p.worker_id}", f"Spawning: {snippet}")
            try:
                new_w = await create_worker(
                    p.worker_id, num_workers_total, candidates, mcp_url, base_options, stderr_cb,
                )
                new_w.assignment = p.assignment
                new_w.last_instruction = p.assignment
                # Fresh SDK client — prepend the recon report so the worker
                # starts with the surface map in its context. Existing workers
                # being retargeted (above) already have it from their first
                # query, so they only need the bare assignment.
                if recon_summary:
                    kickoff = (
                        "## Recon context (from the initial recon worker)\n"
                        f"{recon_summary}\n\n"
                        "## Your assignment\n"
                        f"{p.assignment}"
                    )
                else:
                    kickoff = p.assignment
                await submit_query(new_w.client, kickoff)
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

    cap = worker.max_autonomous_budget or MAX_AUTONOMOUS_BUDGET
    requested = max(1, min(MAX_AUTONOMOUS_BUDGET, decision.autonomous_budget))
    worker.autonomous_budget = min(requested, cap)

    snippet = _short(decision.instruction, 120)
    capped_note = (
        f" (capped from {requested} by recon limit)"
        if requested > worker.autonomous_budget else ""
    )
    log(f"iter {iteration}",
        f"Worker {worker.worker_id}: {decision.kind} "
        f"(budget={worker.autonomous_budget}{capped_note}) — \"{snippet}\"")

    worker.last_instruction = decision.instruction
    try:
        await submit_query(worker.client, decision.instruction)
    except Exception:
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
# Shutdown helpers
# ---------------------------------------------------------------------------


def _dump_unverified_candidates(
    candidates: CandidatePool, finding_writer: FindingWriter,
) -> int:
    """Write every still-pending candidate to disk as an UNVERIFIED finding.

    Used by the double-Ctrl-C abort path: when the user aborts before the
    verifier finishes, the candidate evidence the workers reported would
    otherwise be lost. Returns the number of candidates dumped.
    """
    pending = candidates.pending()
    if not pending:
        return 0
    log("ctrl-c", f"Dumping {len(pending)} unverified candidate(s) to disk.")
    for c in pending:
        path = finding_writer.write_unverified_candidate(c)
        log("ctrl-c", f"Wrote unverified {c.candidate_id} → {path}")
    return len(pending)


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
            config.sectool_bin, config.proxy_port, config.mcp_port,
        )

    iteration = 0
    finding_writer = FindingWriter(config.findings_dir)
    candidates = CandidatePool()
    decisions = DecisionQueue()
    total_cost = 0.0

    _status_bar.install()
    stop_spacebar = start_spacebar_listener(
        asyncio.get_running_loop(), toggle_pause,
    )
    if stop_spacebar is not None:
        log("controls", "Press space to pause/resume (graceful — finishes in-flight turns).")
    status_tick_task = asyncio.create_task(_status_tick())

    try:
        if server_proc is not None:
            wait_for_server(config.mcp_port, server_proc)

        for key in [k for k in os.environ if k.startswith("CLAUDE")]:
            os.environ.pop(key, None)

        mcp_url = f"http://127.0.0.1:{config.mcp_port}/mcp"
        stderr_cb = (lambda line: log("claude", line.rstrip())) if config.verbose else None

        # `workers` is mutated below as workers spawn and retire; the lambda
        # closes over it so the `done` guard always sees the current alive set.
        workers: list[WorkerState] = []
        orch_tools_server = build_orch_mcp_server(
            decisions,
            alive_worker_ids=lambda: [w.worker_id for w in workers if w.alive],
        )

        base_options = ClaudeAgentOptions(
            cwd=cwd, max_turns=100,
            model=config.worker_model_id or config.orchestrator_model_id,
        )

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

        verifier_managed: ManagedSDKClient | None = None
        director_managed: ManagedSDKClient | None = None

        try:
            # Initial worker
            log("worker", "Connecting Claude Code worker 1...")
            try:
                w1 = await create_worker(
                    1, 1, candidates, mcp_url, base_options, stderr_cb,
                    is_recon=True, user_prompt=config.prompt,
                )
                w1.autonomous_budget = config.recon_budget
                w1.max_autonomous_budget = config.recon_budget
                w1.is_recon = True
                workers.append(w1)
            except Exception as exc:
                log("worker", f"Failed to connect worker 1: {exc}")
                raise SystemExit(1) from exc
            log("worker",
                f"Recon worker connected (budget hard-capped at {config.recon_budget}).")

            # The recon worker's surface synthesis after iter 1; persists for
            # the rest of the run so workers spawned in later iterations also
            # get it prepended to their first assignment.
            recon_summary: str | None = None

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

            # Recon kick-off. The user assignment is already embedded in the
            # recon system prompt; this trigger just starts the run without
            # re-stating it. Recovery here would re-issue the kick-off, which
            # is harmless even if the original got partially through.
            _RECON_KICKOFF = "Begin recon. Map the surface; no testing or exploits."
            workers[0].last_instruction = _RECON_KICKOFF
            workers[0].assignment = config.prompt
            try:
                await submit_query(workers[0].client, _RECON_KICKOFF)
            except Exception as exc:
                log("worker", f"Initial prompt failed: {exc}. Recovery...")
                if not await attempt_worker_recovery(workers[0]):
                    raise SystemExit(1)

            # Triple-Ctrl-C graceful shutdown:
            #   press 1 → cancel workers, transition to final verification
            #   press 2 → abort current phase, dump pending candidates as
            #             UNVERIFIED, exit
            #   press 3 → force-exit (os._exit, no cleanup)
            shutdown_event = asyncio.Event()
            dump_unverified_event = asyncio.Event()
            shutdown_count = 0
            loop = asyncio.get_running_loop()

            def _on_sigint() -> None:
                nonlocal shutdown_count
                shutdown_count += 1
                if shutdown_count == 1:
                    log("ctrl-c",
                        "Stopping workers; transitioning to final verification. "
                        "Press Ctrl-C again to abort verification and dump unverified candidates.")
                    shutdown_event.set()
                elif shutdown_count == 2:
                    log("ctrl-c",
                        "Aborting current phase; will dump unverified candidates and exit. "
                        "Press Ctrl-C again to force-exit.")
                    dump_unverified_event.set()
                else:
                    log("ctrl-c", "Force-exit.")
                    # os._exit skips atexit/finally, so restore the terminal
                    # synchronously here or the scroll region and cbreak mode
                    # leak into the parent shell.
                    if stop_spacebar is not None:
                        stop_spacebar()
                    _status_bar.uninstall()
                    os._exit(130)

            loop.add_signal_handler(signal.SIGINT, _on_sigint)

            # Main loop
            for iteration in range(1, config.max_iterations + 1):
                _status_bar.set_iteration(iteration)
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
                    shutdown_event=shutdown_event,
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

                # 3b) Iter-1 only: harvest the recon worker's surface synthesis
                # and tear it down. After this point the recon worker no
                # longer exists; iter 2+ skips this block entirely.
                if iteration == 1 and workers and workers[0].worker_id == 1:
                    recon_summary, synth_cost = await synthesize_and_teardown_recon(
                        workers[0], candidates, iteration, config.verbose,
                    )
                    total_cost += synth_cost
                    log(f"iter {iteration}",
                        f"Recon synthesis captured ({len(recon_summary)} chars, "
                        f"cost=${synth_cost:.4f}).")

                if config.max_cost is not None and total_cost >= config.max_cost:
                    log(f"iter {iteration}", f"Cost ceiling reached (${total_cost:.2f}). Stopping.")
                    break

                # 4) Reset decisions for this iteration
                decisions.reset()

                # 5) Verification phase
                verifier_managed, v_cost, v_summary = await run_verification_phase(
                    verifier_managed, verifier_options, decisions, candidates,
                    finding_writer, iteration,
                    config.max_iterations, total_cost, config.max_cost, config.verbose,
                    abort_event=dump_unverified_event,
                )
                total_cost += v_cost

                if config.max_cost is not None and total_cost >= config.max_cost:
                    log(f"iter {iteration}", f"Cost ceiling reached (${total_cost:.2f}). Stopping.")
                    break

                # On shutdown: skip direction and exit. Dump pending candidates
                # to disk as UNVERIFIED if the user pressed Ctrl-C twice.
                if shutdown_event.is_set():
                    if dump_unverified_event.is_set():
                        _dump_unverified_candidates(candidates, finding_writer)
                    log(f"iter {iteration}",
                        "Shutdown requested; skipping direction phase and exiting.")
                    break

                # 6) Direction phase
                stall_warnings = _format_stall_warnings(workers)
                follow_up_hints = _format_follow_up_hints(
                    decisions.findings, decisions.merges, decisions.dismissals,
                )
                director_managed, d_cost = await run_direction_phase(
                    director_managed, director_options, decisions, workers, worker_runs,
                    candidates.pending(),
                    v_summary, finding_writer.summary_for_orchestrator(),
                    iteration, config.max_iterations, total_cost, config.max_cost,
                    finding_writer.count, stall_warnings, follow_up_hints, config.verbose,
                    config.max_workers,
                    config.prompt,
                    recon_summary=recon_summary,
                    abort_event=dump_unverified_event,
                )
                total_cost += d_cost

                if dump_unverified_event.is_set():
                    _dump_unverified_candidates(candidates, finding_writer)
                    log(f"iter {iteration}",
                        "Shutdown requested mid-direction; exiting.")
                    break

                # Single Ctrl-C pressed during direction: direction completed
                # normally, but the user has asked to wind down. Exit before
                # spawning more worker work. Without this check the loop would
                # waste a full iteration before noticing shutdown_event.
                if shutdown_event.is_set():
                    log(f"iter {iteration}",
                        "Shutdown requested during/after direction; exiting.")
                    break

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
                        decisions.plan, workers, candidates, mcp_url,
                        base_options, stderr_cb, config.max_workers,
                        recon_summary=recon_summary,
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
                        await submit_query(
                            w.client,
                            _build_worker_continue_prompt(
                                findings_summary=worker_findings_summary,
                            ),
                        )
                    except Exception:
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
        status_tick_task.cancel()
        try:
            await status_tick_task
        except (asyncio.CancelledError, Exception):
            pass
        if stop_spacebar is not None:
            stop_spacebar()
        _status_bar.uninstall()
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
