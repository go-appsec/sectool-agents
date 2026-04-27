"""SDK MCP tool definitions for worker and orchestrator agents.

Tools append records into in-process queues; the controller drains them each
turn. Handlers return short acknowledgements — real dispatch happens in the
controller loop.
"""

from __future__ import annotations

import contextvars
import re
import threading
from dataclasses import dataclass, field
from typing import Any

from claude_agent_sdk import create_sdk_mcp_server, tool


SEVERITIES = ("critical", "high", "medium", "low", "informational")
PROGRESS_TAGS = ("none", "incremental", "new")
DEFAULT_AUTONOMOUS_BUDGET = 8
MAX_AUTONOMOUS_BUDGET = 20

# Bounded tool-dispatch rounds inside the director's mandatory self-review substep.
DIRECTION_SELF_REVIEW_MAX_ROUNDS = 2

# Earliest iteration at which a director `done` with zero findings is accepted.
# Mirrors secagent's guardrail: models routinely confuse `done` with
# `direction_done` on early iterations.
MIN_ITERATIONS_FOR_DONE = 5

# Per-task active worker id. Each worker's concurrent drain runs in its own
# asyncio task; ContextVar isolates attribution across concurrent runs.
_ACTIVE_WORKER_ID: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "active_worker_id", default=None,
)


def set_active_worker(worker_id: int | None):
    """Set the active worker in the current asyncio task context.

    Returns the contextvars Token for use with `reset_active_worker`.
    """
    return _ACTIVE_WORKER_ID.set(worker_id)


def reset_active_worker(token) -> None:
    _ACTIVE_WORKER_ID.reset(token)


def current_worker_id() -> int | None:
    return _ACTIVE_WORKER_ID.get()


# ---------------------------------------------------------------------------
# Worker turn summary
# ---------------------------------------------------------------------------


@dataclass
class ToolCallRecord:
    """One tool call observed in a worker turn."""

    name: str
    input_summary: str
    result_summary: str = ""
    is_error: bool = False


@dataclass
class WorkerTurnSummary:
    """Structured summary of a single worker's turn."""

    worker_id: int
    iteration: int
    assistant_text: str = ""
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    flow_ids_touched: list[str] = field(default_factory=list)
    candidate_ids: list[str] = field(default_factory=list)
    cost_usd: float | None = None


# ---------------------------------------------------------------------------
# Finding candidates (worker-reported, unverified)
# ---------------------------------------------------------------------------


@dataclass
class FindingCandidate:
    candidate_id: str
    worker_id: int | None
    title: str
    severity: str
    endpoint: str
    flow_ids: list[str]
    summary: str
    evidence_notes: str
    reproduction_hint: str
    status: str = "pending"  # pending | verified | dismissed


class CandidatePool:
    """Thread-safe pool of worker-reported finding candidates.

    Worker attribution is read from the `_ACTIVE_WORKER_ID` ContextVar set by
    the controller around each worker's drain. This keeps attribution correct
    under concurrent worker runs.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, FindingCandidate] = {}
        self._order: list[str] = []
        self._counter = 0

    def add(
        self,
        *,
        title: str,
        severity: str,
        endpoint: str,
        flow_ids: list[str],
        summary: str,
        evidence_notes: str,
        reproduction_hint: str,
    ) -> str:
        worker_id = current_worker_id()
        with self._lock:
            self._counter += 1
            cid = f"c{self._counter:03d}"
            cand = FindingCandidate(
                candidate_id=cid,
                worker_id=worker_id,
                title=title,
                severity=severity,
                endpoint=endpoint,
                flow_ids=list(flow_ids),
                summary=summary,
                evidence_notes=evidence_notes,
                reproduction_hint=reproduction_hint,
            )
            self._by_id[cid] = cand
            self._order.append(cid)
            return cid

    def get(self, candidate_id: str) -> FindingCandidate | None:
        with self._lock:
            return self._by_id.get(candidate_id)

    def pending(self) -> list[FindingCandidate]:
        with self._lock:
            return [self._by_id[i] for i in self._order if self._by_id[i].status == "pending"]

    def mark(self, candidate_id: str, status: str) -> bool:
        """Transition a candidate to `verified` or `dismissed`.

        Returns True when the candidate moved, False when the call was a
        no-op (unknown id, terminal state already set, or invalid status).
        Only `pending → verified` and `pending → dismissed` are accepted;
        terminal states are sticky so a late `dismiss_candidate` can't
        silently downgrade an already-verified candidate.
        """
        if status not in ("verified", "dismissed"):
            return False
        with self._lock:
            c = self._by_id.get(candidate_id)
            if c is None:
                return False
            if c.status != "pending":
                return False
            c.status = status
            return True

    def ids_since(self, counter_before: int) -> list[str]:
        """IDs minted after `counter_before`."""
        with self._lock:
            return [f"c{i:03d}" for i in range(counter_before + 1, self._counter + 1)]

    def ids_since_for_worker(self, counter_before: int, worker_id: int) -> list[str]:
        """IDs minted after `counter_before` attributed to `worker_id`.

        Race-safe under concurrent worker runs when combined with the
        `_ACTIVE_WORKER_ID` ContextVar.
        """
        with self._lock:
            out: list[str] = []
            for i in range(counter_before + 1, self._counter + 1):
                cid = f"c{i:03d}"
                c = self._by_id.get(cid)
                if c is not None and c.worker_id == worker_id:
                    out.append(cid)
            return out

    @property
    def counter(self) -> int:
        with self._lock:
            return self._counter


# ---------------------------------------------------------------------------
# Orchestrator decisions
# ---------------------------------------------------------------------------


@dataclass
class WorkerDecision:
    """Per-worker orchestrator decision."""

    kind: str  # continue | expand | stop
    worker_id: int
    instruction: str = ""
    progress: str = "none"
    reason: str = ""
    autonomous_budget: int = DEFAULT_AUTONOMOUS_BUDGET


@dataclass
class PlanEntry:
    worker_id: int
    assignment: str


@dataclass
class FindingFiled:
    title: str
    severity: str
    endpoint: str
    description: str
    reproduction_steps: str
    evidence: str
    impact: str
    verification_notes: str
    supersedes_candidate_ids: list[str] = field(default_factory=list)
    follow_up_hint: str = ""


@dataclass
class CandidateDismissal:
    candidate_id: str
    reason: str
    follow_up_hint: str = ""


@dataclass
class FindingMerged:
    """Verifier-issued merge of a candidate into an already-filed finding."""

    finding_id: str
    rationale: str
    additional_endpoint: str = ""
    additional_evidence: str = ""
    additional_reproduction_steps: str = ""
    additional_verification_notes: str = ""
    additional_impact: str = ""
    supersedes_candidate_ids: list[str] = field(default_factory=list)
    follow_up_hint: str = ""


PHASE_IDLE = "idle"
PHASE_VERIFICATION = "verification"
PHASE_DIRECTION = "direction"


def _parse_plan_args(args: dict[str, Any]) -> tuple[
    list["PlanEntry"] | None, list[str], str | None,
]:
    """Validate a `plan_workers` args payload.

    Returns `(entries, rejections, error_text)`. When `error_text` is not
    None the whole payload should be rejected with that text. Otherwise
    `entries` holds the parsed entries and `rejections` is a (possibly
    empty) list of per-entry skip reasons to surface to the caller.
    """
    raw = args.get("plans", None)
    if raw is None or not isinstance(raw, list):
        got = type(raw).__name__ if raw is not None else "missing"
        return None, [], (
            f"Rejected: cannot parse arguments ('plans' {got}). "
            "Expected JSON shape "
            "{\"plans\":[{\"worker_id\":N,\"assignment\":\"...\"}]}."
        )
    if len(raw) == 0:
        return None, [], (
            "Rejected: 'plans' array is empty. Provide at least one "
            "{worker_id, assignment} object."
        )
    entries: list[PlanEntry] = []
    rejections: list[str] = []
    for i, p in enumerate(raw):
        if not isinstance(p, dict):
            rejections.append(f"plans[{i}]: entry must be an object")
            continue
        if "worker_id" not in p:
            rejections.append(f"plans[{i}]: worker_id is required")
            continue
        try:
            wid = int(p["worker_id"])
        except (TypeError, ValueError):
            rejections.append(
                f"plans[{i}]: worker_id must be an integer (got {p['worker_id']!r})"
            )
            continue
        if wid < 1:
            rejections.append(f"plans[{i}]: worker_id must be >= 1 (got {wid})")
            continue
        if "assignment" not in p:
            rejections.append(
                f"plans[{i}] (worker_id={wid}): assignment is required"
            )
            continue
        try:
            asg = str(p["assignment"]).strip()
        except (TypeError, ValueError):
            rejections.append(
                f"plans[{i}] (worker_id={wid}): assignment must be a string"
            )
            continue
        if not asg:
            rejections.append(
                f"plans[{i}] (worker_id={wid}): assignment is empty"
            )
            continue
        entries.append(PlanEntry(worker_id=wid, assignment=asg))
    if not entries:
        reason = "; ".join(rejections) if rejections else "no entries parseable"
        return None, rejections, f"Rejected: no valid plan entries. {reason}"
    return entries, rejections, None


def coalesce_decisions(
    worker_decisions: list["WorkerDecision"],
    plan: list["PlanEntry"] | None,
) -> list["WorkerDecision"]:
    """Collapse duplicate per-worker decisions before the controller applies them.

    The director often calls `continue_worker` / `expand_worker` / `stop_worker`
    for the same worker across substeps; each hit queues a duplicate instruction
    into the worker's SDK client. Semantics:

    - Pure last-writer-wins per `worker_id` — if the director's last decision
      for a worker is `stop`, the worker stops; if `continue`, the worker
      continues.
    - A `plan` entry covers the worker via the spawn/retarget path, so drop
      any `continue`/`expand` for `plan`'d workers. A `stop` for a `plan`'d
      worker is an explicit override and is preserved.

    The relative order of the first-seen decision per `worker_id` is kept
    so downstream iteration is deterministic.
    """
    plan_ids: set[int] = set()
    if plan is not None:
        plan_ids = {p.worker_id for p in plan}

    # Last-writer-wins per worker_id; record first-seen order for stable output.
    order: list[int] = []
    last: dict[int, "WorkerDecision"] = {}
    for d in worker_decisions:
        if d.worker_id not in last:
            order.append(d.worker_id)
        last[d.worker_id] = d

    out: list["WorkerDecision"] = []
    for wid in order:
        d = last[wid]
        if wid in plan_ids and d.kind != "stop":
            continue
        out.append(d)
    return out


class DecisionQueue:
    """Collects orchestrator tool calls across a two-phase orchestrator turn.

    Phases: idle → verification → direction → idle (next iteration).
    Within a phase, tool calls across substeps accumulate; `reset()` at
    iteration start clears everything.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.plan: list[PlanEntry] | None = None
        self.worker_decisions: list[WorkerDecision] = []
        self.findings: list[FindingFiled] = []
        self.dismissals: list[CandidateDismissal] = []
        self.merges: list[FindingMerged] = []
        self.done_summary: str | None = None
        self.phase: str = PHASE_IDLE
        self.verification_done_summary: str | None = None
        self.direction_done_summary: str | None = None

    def reset(self) -> None:
        with self._lock:
            self.plan = None
            self.worker_decisions = []
            self.findings = []
            self.dismissals = []
            self.merges = []
            self.done_summary = None
            self.phase = PHASE_IDLE
            self.verification_done_summary = None
            self.direction_done_summary = None

    def begin_phase(self, phase: str) -> None:
        """Transition into a phase. Clears only that phase's done flag."""
        with self._lock:
            self.phase = phase
            if phase == PHASE_VERIFICATION:
                self.verification_done_summary = None
            elif phase == PHASE_DIRECTION:
                self.direction_done_summary = None

    def set_plan(self, plan: list[PlanEntry]) -> None:
        """Merge plan entries into the current plan, accumulating across calls.

        Multiple `plan_workers` calls within one direction phase are additive:
        entries with new `worker_id` values are appended, entries with an
        existing `worker_id` overwrite that slot (last-wins per-id). This
        matches what models expect when they make several tool calls to
        build up a plan incrementally.
        """
        with self._lock:
            if self.plan is None:
                self.plan = []
            by_id: dict[int, PlanEntry] = {p.worker_id: p for p in self.plan}
            for entry in plan:
                by_id[entry.worker_id] = entry
            self.plan = sorted(by_id.values(), key=lambda p: p.worker_id)

    def add_decision(self, d: WorkerDecision) -> None:
        with self._lock:
            self.worker_decisions.append(d)

    def add_finding(self, f: FindingFiled) -> None:
        with self._lock:
            self.findings.append(f)

    def add_dismissal(self, candidate_id: str, reason: str, follow_up_hint: str = "") -> None:
        with self._lock:
            self.dismissals.append(CandidateDismissal(
                candidate_id=candidate_id, reason=reason, follow_up_hint=follow_up_hint,
            ))

    def add_merge(self, m: FindingMerged) -> None:
        with self._lock:
            self.merges.append(m)

    def decisions_by_worker(self) -> dict[int, str]:
        """worker_id → latest decision kind this phase (continue|expand|stop)."""
        with self._lock:
            return {d.worker_id: d.kind for d in self.worker_decisions}

    def set_done(self, summary: str) -> None:
        with self._lock:
            self.done_summary = summary

    def set_verification_done(self, summary: str) -> None:
        with self._lock:
            self.verification_done_summary = summary

    def set_direction_done(self, summary: str) -> None:
        with self._lock:
            self.direction_done_summary = summary

    @property
    def current_phase(self) -> str:
        with self._lock:
            return self.phase


# ---------------------------------------------------------------------------
# Flow ID extraction
# ---------------------------------------------------------------------------


# Flow IDs (sectool/service/ids/ids.go): base62, default length 6, entity IDs 4.
# Only match prefixed forms — a bare `flow` keyword mis-matches prose like
# "flow chart" → "chart". Structured sources are handled by the dict walker.
_FLOW_ID_RE = re.compile(
    r"""(?:flow[_ ]?id|flow_a|flow_b|source_flow_id)\b   # keyword
        \s*[:=]?\s*                                      # optional sep
        ["']?                                            # optional quote
        ([0-9A-Za-z]{4,16})                              # base62 token
    """,
    re.VERBOSE | re.IGNORECASE,
)


def extract_flow_ids(*sources: Any) -> list[str]:
    """Extract sectool flow IDs from a mix of strings, dicts, and lists.

    Order-preserving and deduplicated.
    """
    seen: dict[str, None] = {}

    def walk(val: Any) -> None:
        if val is None:
            return
        if isinstance(val, str):
            for m in _FLOW_ID_RE.finditer(val):
                fid = m.group(1)
                if fid not in seen:
                    seen[fid] = None
            return
        if isinstance(val, dict):
            for k, v in val.items():
                if isinstance(k, str) and k.lower() in (
                    "flow_id",
                    "flow_a",
                    "flow_b",
                    "source_flow_id",
                ) and isinstance(v, str) and v:
                    if v not in seen:
                        seen[v] = None
                walk(v)
            return
        if isinstance(val, (list, tuple)):
            for item in val:
                walk(item)

    for src in sources:
        walk(src)
    return list(seen.keys())


# ---------------------------------------------------------------------------
# Worker MCP server — report_finding_candidate
# ---------------------------------------------------------------------------


def build_worker_mcp_server(candidates: CandidatePool) -> Any:
    """SDK MCP server that exposes `report_finding_candidate` to workers."""

    @tool(
        "report_finding_candidate",
        (
            "Report a potential security finding for orchestrator verification. "
            "Include proof flow IDs from your testing (replay_send, request_send, "
            "or proxy_poll). Do NOT write a full finding document — the "
            "orchestrator will reproduce the issue and file the formal finding. "
            "Returns a candidate_id confirmation."
        ),
        {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Concise vulnerability name"},
                "severity": {"type": "string", "enum": list(SEVERITIES)},
                "endpoint": {"type": "string", "description": "Affected endpoint path + method"},
                "flow_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Proof flow IDs. At least one required.",
                },
                "summary": {"type": "string", "description": "1-3 sentence description"},
                "evidence_notes": {
                    "type": "string",
                    "description": "What makes this exploitable — response content, status codes, behavior.",
                },
                "reproduction_hint": {
                    "type": "string",
                    "description": "How the orchestrator should re-run to verify.",
                },
            },
            "required": [
                "title",
                "severity",
                "endpoint",
                "flow_ids",
                "summary",
                "evidence_notes",
                "reproduction_hint",
            ],
        },
    )
    async def report_finding_candidate(args: dict[str, Any]) -> dict[str, Any]:
        severity = str(args.get("severity", "")).lower()
        if severity not in SEVERITIES:
            return {
                "content": [{
                    "type": "text",
                    "text": f"Rejected: severity must be one of {SEVERITIES}.",
                }],
                "is_error": True,
            }
        flow_ids = args.get("flow_ids") or []
        if not isinstance(flow_ids, list) or not flow_ids:
            return {
                "content": [{
                    "type": "text",
                    "text": "Rejected: flow_ids must be a non-empty array.",
                }],
                "is_error": True,
            }
        cid = candidates.add(
            title=str(args.get("title", "")).strip() or "untitled",
            severity=severity,
            endpoint=str(args.get("endpoint", "")).strip(),
            flow_ids=[str(f) for f in flow_ids],
            summary=str(args.get("summary", "")).strip(),
            evidence_notes=str(args.get("evidence_notes", "")).strip(),
            reproduction_hint=str(args.get("reproduction_hint", "")).strip(),
        )
        return {
            "content": [{
                "type": "text",
                "text": (
                    f"Candidate {cid} recorded. The orchestrator will verify and, "
                    "if confirmed, file the formal finding. Continue your testing."
                ),
            }],
        }

    return create_sdk_mcp_server(
        name="worker_tools",
        version="1.0.0",
        tools=[report_finding_candidate],
    )


# ---------------------------------------------------------------------------
# Orchestrator MCP server — decision + finding tools
# ---------------------------------------------------------------------------


def _reject_wrong_phase(expected: str, current: str, tool_name: str) -> dict[str, Any]:
    hint = ""
    if current == PHASE_VERIFICATION and expected == PHASE_DIRECTION:
        hint = " Call `verification_done(summary)` first."
    elif current == PHASE_DIRECTION and expected == PHASE_VERIFICATION:
        hint = " Direction phase cannot file findings; verification already ended this iteration."
    return {
        "content": [{
            "type": "text",
            "text": (
                f"Rejected: `{tool_name}` is not allowed in phase '{current}'. "
                f"Expected phase '{expected}'.{hint}"
            ),
        }],
        "is_error": True,
    }


def build_orch_mcp_server(
    decisions: DecisionQueue,
    alive_worker_ids: Any | None = None,
) -> Any:
    """SDK MCP server with the orchestrator's decision + finding tools.

    Tools are phase-gated by `decisions.phase`; calling the wrong tool in the
    wrong phase returns an is_error=True response.

    `alive_worker_ids`, when provided, is a 0-arg callable returning the list
    of currently-alive worker IDs. It's consulted by the `done` handler to
    reject `done` while live workers lack an explicit `stop_worker` — this
    catches the common failure mode of the director queueing
    `continue_worker` + `done` in the same phase and silently abandoning
    in-progress investigations.
    """

    @tool(
        "plan_workers",
        (
            "Spawn or retarget workers for parallel testing. Provide a list of "
            "{worker_id, assignment} entries; worker IDs start at 1. Callable any "
            "turn. The controller diffs against the current worker set: new IDs "
            "are spawned, existing IDs are retargeted, and omitted alive workers "
            "are left running (use stop_worker to retire). Multiple calls within "
            "one direction phase accumulate: entries with new worker_ids are "
            "added; entries with an existing worker_id overwrite (last-wins). "
            "Prefer ONE call with all entries for clarity."
        ),
        {
            "type": "object",
            "properties": {
                "plans": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "worker_id": {"type": "integer", "minimum": 1},
                            "assignment": {"type": "string"},
                        },
                        "required": ["worker_id", "assignment"],
                    },
                },
            },
            "required": ["plans"],
        },
    )
    async def plan_workers(args: dict[str, Any]) -> dict[str, Any]:
        if decisions.current_phase != PHASE_DIRECTION:
            return _reject_wrong_phase(PHASE_DIRECTION, decisions.current_phase, "plan_workers")
        entries, rejections, err = _parse_plan_args(args)
        if err is not None:
            return {
                "content": [{"type": "text", "text": err}],
                "is_error": True,
            }
        decisions.set_plan(entries)
        # Post-merge count reflects accumulation across multiple calls in
        # this phase (set_plan merges by worker_id).
        total = len(decisions.plan) if decisions.plan is not None else 0
        ids_this_call = ", ".join(str(e.worker_id) for e in entries)
        text = (
            f"Plan recorded: this call added/updated worker_ids "
            f"[{ids_this_call}]; current plan covers {total} worker(s) "
            f"total this phase."
        )
        if rejections:
            text += " Skipped: " + "; ".join(rejections)
        return {"content": [{"type": "text", "text": text}]}

    def _record_worker_decision(kind: str, args: dict[str, Any]) -> dict[str, Any]:
        if decisions.current_phase != PHASE_DIRECTION:
            return _reject_wrong_phase(PHASE_DIRECTION, decisions.current_phase, f"{kind}_worker")
        try:
            wid = int(args["worker_id"])
        except (KeyError, TypeError, ValueError):
            return {
                "content": [{"type": "text", "text": "Rejected: worker_id required."}],
                "is_error": True,
            }
        instruction = str(args.get("instruction", "")).strip()
        progress = str(args.get("progress", "")).lower()
        if progress not in PROGRESS_TAGS:
            return {
                "content": [{"type": "text", "text": f"Rejected: progress must be one of {PROGRESS_TAGS}."}],
                "is_error": True,
            }
        if not instruction:
            return {
                "content": [{"type": "text", "text": "Rejected: instruction is required."}],
                "is_error": True,
            }
        budget = args.get("autonomous_budget", DEFAULT_AUTONOMOUS_BUDGET)
        try:
            budget = int(budget)
        except (TypeError, ValueError):
            budget = DEFAULT_AUTONOMOUS_BUDGET
        budget = max(1, min(MAX_AUTONOMOUS_BUDGET, budget))
        decisions.add_decision(WorkerDecision(
            kind=kind, worker_id=wid, instruction=instruction,
            progress=progress, autonomous_budget=budget,
        ))
        return {
            "content": [{
                "type": "text",
                "text": (
                    f"{kind} recorded for worker {wid} "
                    f"(progress={progress}, autonomous_budget={budget})."
                ),
            }],
        }

    _worker_directive_schema = {
        "type": "object",
        "properties": {
            "worker_id": {"type": "integer", "minimum": 1},
            "instruction": {"type": "string"},
            "progress": {"type": "string", "enum": list(PROGRESS_TAGS)},
            "autonomous_budget": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_AUTONOMOUS_BUDGET,
                "description": (
                    "Consecutive autonomous turns this worker may run before "
                    "escalating back for review. Use 5-10 for productive workers "
                    "on a clear path, 2-3 for exploratory or uncertain "
                    f"assignments. Default {DEFAULT_AUTONOMOUS_BUDGET}."
                ),
            },
        },
        "required": ["worker_id", "instruction", "progress"],
    }

    @tool(
        "continue_worker",
        (
            "Tell worker N to keep going with its current plan. Use when its "
            "work is productive and no pivot is needed. progress: 'none' if no "
            "new information gained, 'incremental' for steady progress, 'new' "
            "if a new attack surface opened."
        ),
        _worker_directive_schema,
    )
    async def continue_worker(args: dict[str, Any]) -> dict[str, Any]:
        return _record_worker_decision("continue", args)

    @tool(
        "expand_worker",
        (
            "Pivot worker N with an adjusted plan. Use when results warrant a "
            "new angle of attack or the current plan is exhausted. progress: "
            "same semantics as continue_worker."
        ),
        _worker_directive_schema,
    )
    async def expand_worker(args: dict[str, Any]) -> dict[str, Any]:
        return _record_worker_decision("expand", args)

    @tool(
        "stop_worker",
        (
            "Stop worker N. Use when its assignment is complete or the area is "
            "already covered by other workers."
        ),
        {
            "type": "object",
            "properties": {
                "worker_id": {"type": "integer", "minimum": 1},
                "reason": {"type": "string"},
            },
            "required": ["worker_id", "reason"],
        },
    )
    async def stop_worker(args: dict[str, Any]) -> dict[str, Any]:
        if decisions.current_phase != PHASE_DIRECTION:
            return _reject_wrong_phase(PHASE_DIRECTION, decisions.current_phase, "stop_worker")
        try:
            wid = int(args["worker_id"])
        except (KeyError, TypeError, ValueError):
            return {
                "content": [{"type": "text", "text": "Rejected: worker_id required."}],
                "is_error": True,
            }
        reason = str(args.get("reason", "")).strip()
        if not reason:
            return {
                "content": [{"type": "text", "text": "Rejected: reason is required."}],
                "is_error": True,
            }
        decisions.add_decision(WorkerDecision(
            kind="stop", worker_id=wid, reason=reason,
        ))
        return {"content": [{"type": "text", "text": f"stop recorded for worker {wid}."}]}

    @tool(
        "file_finding",
        (
            "File a verified security finding. Call ONLY after independently "
            "reproducing the issue with sectool tools (flow_get, replay_send, "
            "request_send, diff_flow, etc). All fields must be session-agnostic: "
            "describe endpoints, payloads, headers, and observed behavior — "
            "never cite flow IDs, OAST session IDs, or other ephemeral test state."
        ),
        {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": list(SEVERITIES)},
                "endpoint": {"type": "string"},
                "description": {"type": "string"},
                "reproduction_steps": {
                    "type": "string",
                    "description": "Step-by-step reproduction using endpoint, method, headers, and payload — no flow IDs or session references.",
                },
                "evidence": {
                    "type": "string",
                    "description": "Observable proof: response content, status codes, headers, behavior — no flow IDs or session references.",
                },
                "impact": {"type": "string"},
                "verification_notes": {
                    "type": "string",
                    "description": "How you reproduced the issue: tools used, mutations applied, what you observed — no flow IDs or session IDs.",
                },
                "supersedes_candidate_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                    "description": (
                        "Pending candidate IDs this finding resolves. Omit "
                        "only if the issue surfaced during verification and "
                        "does not correspond to any pending candidate — the "
                        "controller will auto-match by endpoint and similar "
                        "title as a safety net, but an explicit list is "
                        "preferred."
                    ),
                },
                "follow_up_hint": {
                    "type": "string",
                    "default": "",
                    "description": (
                        "Optional one-line hint for the director: a related "
                        "angle, variant, or adjacent endpoint worth probing "
                        "next. Advisory only; omit if nothing stands out."
                    ),
                },
            },
            "required": [
                "title",
                "severity",
                "endpoint",
                "description",
                "reproduction_steps",
                "evidence",
                "impact",
                "verification_notes",
            ],
        },
    )
    async def file_finding(args: dict[str, Any]) -> dict[str, Any]:
        if decisions.current_phase != PHASE_VERIFICATION:
            return _reject_wrong_phase(PHASE_VERIFICATION, decisions.current_phase, "file_finding")
        severity = str(args.get("severity", "")).lower()
        if severity not in SEVERITIES:
            return {
                "content": [{"type": "text", "text": f"Rejected: severity must be one of {SEVERITIES}."}],
                "is_error": True,
            }
        verification = str(args.get("verification_notes", "")).strip()
        if not verification:
            return {
                "content": [{
                    "type": "text",
                    "text": (
                        "Rejected: verification_notes must describe how you "
                        "reproduced the issue with sectool tools."
                    ),
                }],
                "is_error": True,
            }
        filed = FindingFiled(
            title=str(args.get("title", "")).strip() or "untitled",
            severity=severity,
            endpoint=str(args.get("endpoint", "")).strip(),
            description=str(args.get("description", "")).strip(),
            reproduction_steps=str(args.get("reproduction_steps", "")).strip(),
            evidence=str(args.get("evidence", "")).strip(),
            impact=str(args.get("impact", "")).strip(),
            verification_notes=verification,
            supersedes_candidate_ids=[
                str(c) for c in (args.get("supersedes_candidate_ids") or [])
            ],
            follow_up_hint=str(args.get("follow_up_hint", "")).strip(),
        )
        decisions.add_finding(filed)
        return {
            "content": [{"type": "text", "text": f"Finding '{filed.title}' recorded for persistence."}],
        }

    @tool(
        "merge_into_finding",
        (
            "Merge a candidate's evidence into an already-filed finding instead "
            "of filing a near-duplicate. Use when the candidate represents the "
            "same underlying vulnerability as an existing finding (e.g. another "
            "endpoint exhibiting the same flaw, or stronger evidence for an "
            "already-filed issue). Reference the target by its `finding_id` "
            "(e.g. 'F1', 'F2') from the findings list. Append-only: the merge "
            "addendum is added to the existing finding's markdown, not a new file."
        ),
        {
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "Target finding_id from the findings list (e.g. 'F1').",
                },
                "rationale": {
                    "type": "string",
                    "description": "One short sentence: why this is the same underlying issue.",
                },
                "additional_endpoint": {
                    "type": "string",
                    "default": "",
                    "description": "If the merge adds a new affected endpoint, name it here.",
                },
                "additional_evidence": {
                    "type": "string",
                    "default": "",
                    "description": "New observable proof — no flow IDs or session references.",
                },
                "additional_reproduction_steps": {
                    "type": "string",
                    "default": "",
                    "description": "New reproduction steps — no flow IDs or session references.",
                },
                "additional_verification_notes": {
                    "type": "string",
                    "default": "",
                    "description": "How you reproduced this variant — no flow IDs or session IDs.",
                },
                "additional_impact": {
                    "type": "string",
                    "default": "",
                    "description": "Any expanded impact this addendum demonstrates.",
                },
                "supersedes_candidate_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                    "description": (
                        "Pending candidate IDs this merge resolves. Same "
                        "semantics as `file_finding.supersedes_candidate_ids`."
                    ),
                },
                "follow_up_hint": {
                    "type": "string",
                    "default": "",
                    "description": (
                        "Optional one-line hint for the director: a related "
                        "angle worth probing next. Advisory only."
                    ),
                },
            },
            "required": ["finding_id", "rationale"],
        },
    )
    async def merge_into_finding(args: dict[str, Any]) -> dict[str, Any]:
        if decisions.current_phase != PHASE_VERIFICATION:
            return _reject_wrong_phase(
                PHASE_VERIFICATION, decisions.current_phase, "merge_into_finding",
            )
        finding_id = str(args.get("finding_id", "")).strip()
        rationale = str(args.get("rationale", "")).strip()
        if not finding_id or not rationale:
            return {
                "content": [{
                    "type": "text",
                    "text": "Rejected: finding_id and rationale are required.",
                }],
                "is_error": True,
            }
        decisions.add_merge(FindingMerged(
            finding_id=finding_id,
            rationale=rationale,
            additional_endpoint=str(args.get("additional_endpoint", "")).strip(),
            additional_evidence=str(args.get("additional_evidence", "")).strip(),
            additional_reproduction_steps=str(args.get("additional_reproduction_steps", "")).strip(),
            additional_verification_notes=str(args.get("additional_verification_notes", "")).strip(),
            additional_impact=str(args.get("additional_impact", "")).strip(),
            supersedes_candidate_ids=[
                str(c) for c in (args.get("supersedes_candidate_ids") or [])
            ],
            follow_up_hint=str(args.get("follow_up_hint", "")).strip(),
        ))
        return {
            "content": [{
                "type": "text",
                "text": f"Merge into {finding_id} recorded.",
            }],
        }

    @tool(
        "dismiss_candidate",
        (
            "Mark a worker-reported finding candidate as not a real issue — "
            "false positive, already covered by another finding, or out of "
            "scope. Provide a short reason. Dismissed candidates are no longer "
            "shown in subsequent turns."
        ),
        {
            "type": "object",
            "properties": {
                "candidate_id": {"type": "string"},
                "reason": {"type": "string"},
                "follow_up_hint": {
                    "type": "string",
                    "default": "",
                    "description": (
                        "Optional one-line hint for the director: a related "
                        "angle or real lead this dead-end points toward. "
                        "Advisory only; omit if nothing stands out."
                    ),
                },
            },
            "required": ["candidate_id", "reason"],
        },
    )
    async def dismiss_candidate(args: dict[str, Any]) -> dict[str, Any]:
        if decisions.current_phase != PHASE_VERIFICATION:
            return _reject_wrong_phase(PHASE_VERIFICATION, decisions.current_phase, "dismiss_candidate")
        cid = str(args.get("candidate_id", "")).strip()
        reason = str(args.get("reason", "")).strip()
        if not cid or not reason:
            return {
                "content": [{"type": "text", "text": "Rejected: candidate_id and reason required."}],
                "is_error": True,
            }
        decisions.add_dismissal(
            cid, reason, follow_up_hint=str(args.get("follow_up_hint", "")).strip(),
        )
        return {"content": [{"type": "text", "text": f"Candidate {cid} dismissal recorded."}]}

    @tool(
        "done",
        (
            "Signal that the exploration run should end. Provide a brief "
            "summary of what was covered. All unreported findings must already "
            "have been filed before calling this."
        ),
        {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
        },
    )
    async def done(args: dict[str, Any]) -> dict[str, Any]:
        if decisions.current_phase != PHASE_DIRECTION:
            return _reject_wrong_phase(PHASE_DIRECTION, decisions.current_phase, "done")
        summary = str(args.get("summary", "")).strip()
        if not summary:
            return {
                "content": [{"type": "text", "text": "Rejected: summary is required."}],
                "is_error": True,
            }
        if alive_worker_ids is not None:
            alive = list(alive_worker_ids())
            by_wid = decisions.decisions_by_worker()
            planned_ids = (
                {p.worker_id for p in decisions.plan}
                if decisions.plan is not None else set()
            )
            # `plan_workers` covers a worker via the spawn/retarget path —
            # for the purpose of the done guard, treat it the same as a
            # non-stop decision (work is still being scheduled).
            not_stopped = sorted(
                w for w in alive
                if (by_wid.get(w) and by_wid[w] != "stop") or w in planned_ids
            )
            no_decision = sorted(
                w for w in alive if w not in by_wid and w not in planned_ids
            )
            if not_stopped or no_decision:
                parts: list[str] = []
                if not_stopped:
                    parts.append(
                        f"workers {not_stopped} have decisions other than stop this iter"
                    )
                if no_decision:
                    parts.append(
                        f"workers {no_decision} have no decision recorded this iter"
                    )
                return {
                    "content": [{
                        "type": "text",
                        "text": (
                            "Rejected: `done` would abandon live work — "
                            + "; ".join(parts)
                            + ". Either stop them all via `stop_worker(worker_id, reason=...)` "
                            "in this iter and re-issue `done`, or call `direction_done(summary)` "
                            "to close this iter and let the workers continue next iter."
                        ),
                    }],
                    "is_error": True,
                }
        decisions.set_done(summary)
        return {"content": [{"type": "text", "text": "Run end signaled."}]}

    @tool(
        "verification_done",
        (
            "Signal that the verification phase is complete. Call this after "
            "every pending candidate has been resolved via `file_finding` or "
            "`dismiss_candidate`. Provide a 1-3 sentence summary of what you "
            "verified, dismissed, and any open questions to pass along to the "
            "direction phase."
        ),
        {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
        },
    )
    async def verification_done(args: dict[str, Any]) -> dict[str, Any]:
        if decisions.current_phase != PHASE_VERIFICATION:
            return _reject_wrong_phase(PHASE_VERIFICATION, decisions.current_phase, "verification_done")
        summary = str(args.get("summary", "")).strip()
        if not summary:
            return {
                "content": [{"type": "text", "text": "Rejected: summary is required."}],
                "is_error": True,
            }
        decisions.set_verification_done(summary)
        return {"content": [{"type": "text", "text": "Verification phase complete."}]}

    @tool(
        "direction_done",
        (
            "Signal that per-worker direction is complete for this iteration. "
            "Call only after every alive worker has a continue/expand/stop "
            "decision or is covered by a `plan_workers` entry. Provide a brief "
            "summary of what was assigned."
        ),
        {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
        },
    )
    async def direction_done(args: dict[str, Any]) -> dict[str, Any]:
        if decisions.current_phase != PHASE_DIRECTION:
            return _reject_wrong_phase(PHASE_DIRECTION, decisions.current_phase, "direction_done")
        summary = str(args.get("summary", "")).strip()
        if not summary:
            return {
                "content": [{"type": "text", "text": "Rejected: summary is required."}],
                "is_error": True,
            }
        decisions.set_direction_done(summary)
        return {"content": [{"type": "text", "text": "Direction phase complete."}]}

    return create_sdk_mcp_server(
        name="orch_tools",
        version="1.0.0",
        tools=[
            plan_workers,
            continue_worker,
            expand_worker,
            stop_worker,
            file_finding,
            merge_into_finding,
            dismiss_candidate,
            done,
            verification_done,
            direction_done,
        ],
    )


# Public allowed-tool names (use with ClaudeAgentOptions.allowed_tools).
WORKER_TOOL_ALLOWED = "mcp__worker_tools__report_finding_candidate"

# Tools available during the verification phase.
VERIFIER_TOOL_NAMES = (
    "file_finding",
    "merge_into_finding",
    "dismiss_candidate",
    "verification_done",
)

# Tools available during the direction phase.
DIRECTOR_TOOL_NAMES = (
    "plan_workers",
    "continue_worker",
    "expand_worker",
    "stop_worker",
    "direction_done",
    "done",
)

ORCH_TOOL_NAMES = VERIFIER_TOOL_NAMES + DIRECTOR_TOOL_NAMES
ORCH_TOOL_ALLOWED = [f"mcp__orch_tools__{n}" for n in ORCH_TOOL_NAMES]
VERIFIER_TOOL_ALLOWED = [f"mcp__orch_tools__{n}" for n in VERIFIER_TOOL_NAMES]
DIRECTOR_TOOL_ALLOWED = [f"mcp__orch_tools__{n}" for n in DIRECTOR_TOOL_NAMES]
