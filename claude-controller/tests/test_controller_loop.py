"""Smoke tests for controller loop internals.

Covers the autonomous-worker turn classification and loop, stall updates,
apply_decision dispatch, and verifier/director prompt contents — using a
scripted fake ClaudeSDKClient (no network, no real SDK).
"""

import asyncio
import tempfile
import unittest
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

import controller
from findings import FindingWriter
from tools import (
    CandidatePool,
    DecisionQueue,
    FindingFiled,
    ToolCallRecord,
    WorkerDecision,
    WorkerTurnSummary,
    set_active_worker,
    reset_active_worker,
)


def _result(cost: float = 0.01) -> ResultMessage:
    return ResultMessage(
        subtype="result",
        duration_ms=0,
        duration_api_ms=0,
        is_error=False,
        num_turns=1,
        session_id="test",
        total_cost_usd=cost,
    )


class FakeSDKClient:
    """Minimal async fake of ClaudeSDKClient.

    Scripts can be supplied as a list (popped left-to-right per
    receive_response call) or a dict keyed by query index (0-based).
    """

    def __init__(self, scripts):
        if isinstance(scripts, dict):
            self._scripts: Any = dict(scripts)
        else:
            self._scripts = list(scripts)
        self.queries: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def query(self, content: str) -> None:
        self.queries.append(content)

    def receive_response(self):
        if isinstance(self._scripts, dict):
            idx = max(0, len(self.queries) - 1)
            messages = self._scripts[idx]
        else:
            if not self._scripts:
                raise AssertionError("No more scripted turns")
            messages = self._scripts.pop(0)

        async def gen():
            for m in messages:
                yield m

        return gen()

    async def interrupt(self) -> None:
        pass


class _StubClient:
    def __init__(self):
        self.queries: list[str] = []

    async def query(self, msg: str) -> None:
        self.queries.append(msg)


def _run(coro):
    return asyncio.run(coro)


class _FakeManaged:
    """ManagedSDKClient duck-type for tests.

    Phase functions (run_verification_phase, run_direction_phase) take a
    ManagedSDKClient-shaped object and access `.client` on it for queries.
    `aclose` is the only other method they might call (on recovery).
    """

    def __init__(self, client):
        self.client = client

    async def aclose(self):
        self.client = None


# ---------------------------------------------------------------------------
# Turn collection
# ---------------------------------------------------------------------------


class TestCollectWorkerTurn(unittest.TestCase):
    def test_captures_text_and_tools(self):
        pool = CandidatePool()
        client = FakeSDKClient([
            [
                AssistantMessage(
                    content=[
                        TextBlock(text="Tested /search. Found reflection."),
                        ToolUseBlock(
                            id="u1",
                            name="mcp__sectool__replay_send",
                            input={"flow_id": "abc123", "mutations": {}},
                        ),
                    ],
                    model="test",
                ),
                UserMessage(content=[
                    ToolResultBlock(
                        tool_use_id="u1",
                        content=[{"type": "text", "text": "Replayed. new flow_id: xyz789"}],
                    ),
                ]),
                _result(0.02),
            ],
        ])
        s = _run(controller.collect_worker_turn(client, worker_id=1, iteration=1, candidates=pool))
        self.assertEqual(s.worker_id, 1)
        self.assertIn("Tested /search", s.assistant_text)
        self.assertEqual(len(s.tool_calls), 1)
        self.assertEqual(s.tool_calls[0].name, "mcp__sectool__replay_send")
        self.assertIn("Replayed", s.tool_calls[0].result_summary)
        self.assertIn("abc123", s.flow_ids_touched)
        self.assertIn("xyz789", s.flow_ids_touched)
        self.assertEqual(s.cost_usd, 0.02)

    def test_attributes_candidates_to_active_worker(self):
        pool = CandidatePool()
        # Pre-seed a prior candidate (other worker) to verify filtering.
        token = set_active_worker(99)
        try:
            pool.add(title="other", severity="low", endpoint="/a",
                     flow_ids=["aaaa11"], summary="", evidence_notes="", reproduction_hint="")
        finally:
            reset_active_worker(token)

        class PoolSideEffectClient(FakeSDKClient):
            def receive_response(self_inner):
                async def gen():
                    for m in self_inner._scripts.pop(0):
                        yield m
                        if isinstance(m, AssistantMessage) and any(
                            isinstance(b, ToolUseBlock)
                            and b.name == "mcp__worker_tools__report_finding_candidate"
                            for b in m.content
                        ):
                            # Simulate tool handler side effect — CandidatePool.add
                            # reads from the contextvar set by collect_worker_turn.
                            pool.add(title="new", severity="high", endpoint="/b",
                                     flow_ids=["bbbb22"], summary="",
                                     evidence_notes="", reproduction_hint="")
                return gen()

        client = PoolSideEffectClient([
            [
                AssistantMessage(
                    content=[
                        TextBlock(text="Reporting."),
                        ToolUseBlock(
                            id="u1",
                            name="mcp__worker_tools__report_finding_candidate",
                            input={"title": "new"},
                        ),
                    ],
                    model="test",
                ),
                UserMessage(content=[
                    ToolResultBlock(tool_use_id="u1",
                                    content=[{"type": "text", "text": "Candidate c002 recorded."}]),
                ]),
                _result(),
            ],
        ])
        s = _run(controller.collect_worker_turn(client, worker_id=2, iteration=3, candidates=pool))
        self.assertEqual(s.candidate_ids, ["c002"])
        self.assertEqual(pool.get("c002").worker_id, 2)


# ---------------------------------------------------------------------------
# Autonomous worker run
# ---------------------------------------------------------------------------


def _productive_turn(flow_id: str = "prod01") -> list:
    return [
        AssistantMessage(
            content=[
                TextBlock(text="Probing."),
                ToolUseBlock(id="u", name="mcp__sectool__replay_send",
                             input={"flow_id": flow_id, "mutations": {}}),
            ],
            model="test",
        ),
        UserMessage(content=[
            ToolResultBlock(tool_use_id="u",
                            content=[{"type": "text", "text": f"Replayed {flow_id}"}]),
        ]),
        _result(0.01),
    ]


def _silent_turn() -> list:
    return [
        AssistantMessage(content=[], model="test"),
        _result(0.0),
    ]


def _candidate_turn(pool: CandidatePool, wid: int) -> list:
    # The FakeSDKClient doesn't trigger tool handlers; simulate side effect by
    # letting the test script mutate pool via a custom subclass. For tests
    # below we instead use a specialised client that adds to the pool.
    return [
        AssistantMessage(
            content=[
                TextBlock(text="Found something."),
                ToolUseBlock(id="u", name="mcp__worker_tools__report_finding_candidate",
                             input={"title": "x"}),
            ],
            model="test",
        ),
        UserMessage(content=[
            ToolResultBlock(tool_use_id="u",
                            content=[{"type": "text", "text": "Candidate recorded."}]),
        ]),
        _result(0.01),
    ]


class _CandidateInjectingClient(FakeSDKClient):
    """FakeSDKClient that triggers pool.add() when it sees a candidate tool."""

    def __init__(self, scripts, pool: CandidatePool, add_on_turn_indexes: list[int]):
        super().__init__(scripts)
        self._pool = pool
        self._add_on = set(add_on_turn_indexes)
        self._turn_idx = -1

    def receive_response(self):
        self._turn_idx += 1
        if isinstance(self._scripts, dict):
            idx = max(0, len(self.queries) - 1)
            messages = self._scripts[idx]
        else:
            if not self._scripts:
                raise AssertionError("No more scripted turns")
            messages = self._scripts.pop(0)
        add_this_turn = self._turn_idx in self._add_on

        async def gen():
            for m in messages:
                yield m
                if add_this_turn and isinstance(m, AssistantMessage):
                    for b in m.content:
                        if isinstance(b, ToolUseBlock) and b.name == "mcp__worker_tools__report_finding_candidate":
                            self._pool.add(
                                title="injected", severity="high", endpoint="/x",
                                flow_ids=["ijct01"], summary="", evidence_notes="",
                                reproduction_hint="",
                            )
        return gen()


class TestRunWorkerAutonomousTurn(unittest.TestCase):
    def _make_worker(self, client):
        w = controller.WorkerState(worker_id=5, options=None)
        w.client = client
        return w

    def test_classifies_turn_by_reason(self):
        """Each turn type produces the matching escalation reason (None/silent/candidate)."""
        for case in ("productive", "silent", "candidate"):
            with self.subTest(case=case):
                pool = CandidatePool()
                if case == "productive":
                    client = FakeSDKClient([_productive_turn()])
                elif case == "silent":
                    client = FakeSDKClient([_silent_turn()])
                else:
                    client = _CandidateInjectingClient(
                        [_candidate_turn(pool, 5)], pool, add_on_turn_indexes=[0],
                    )
                w = self._make_worker(client)
                s, reason = _run(controller.run_worker_autonomous_turn(w, 1, pool, verbose=False))
                if case == "productive":
                    self.assertIsNotNone(s)
                    self.assertIsNone(reason)
                elif case == "silent":
                    self.assertEqual(reason, "silent")
                    self.assertEqual(s.tool_calls, [])
                else:
                    self.assertEqual(reason, "candidate")
                    self.assertEqual(len(s.candidate_ids), 1)


class TestRunWorkerUntilEscalation(unittest.TestCase):
    def _make_worker(self, client, budget: int = 3):
        w = controller.WorkerState(worker_id=9, options=None)
        w.client = client
        w.autonomous_budget = budget
        return w

    def test_budget_exhausted_sets_budget(self):
        pool = CandidatePool()
        # All three turns productive → budget reached
        scripts = [_productive_turn("pp01a"), _productive_turn("pp01b"), _productive_turn("pp01c")]
        client = FakeSDKClient(scripts)
        w = self._make_worker(client, budget=3)
        runs = _run(controller.run_worker_until_escalation(w, 1, pool, verbose=False))
        self.assertEqual(len(runs), 3)
        self.assertEqual(w.escalation_reason, "budget")
        # First turn does not send a Continue query; subsequent ones do.
        # Intra-iteration requeries use the bare continue directive (no
        # findings roster — tokens precious between autonomous turns).
        self.assertEqual(client.queries, [
            controller._BARE_WORKER_CONTINUE,
            controller._BARE_WORKER_CONTINUE,
        ])

    def test_non_productive_turn_escalates_early(self):
        """Silent or candidate turn mid-run ends the loop at turn 2."""
        for expected_reason in ("silent", "candidate"):
            with self.subTest(reason=expected_reason):
                pool = CandidatePool()
                if expected_reason == "silent":
                    scripts = [_productive_turn("aa01"), _silent_turn(), _productive_turn("aa02")]
                    client = FakeSDKClient(scripts)
                else:
                    scripts = [_productive_turn("xyz01"), _candidate_turn(pool, 9), _productive_turn("no01")]
                    client = _CandidateInjectingClient(scripts, pool, add_on_turn_indexes=[1])
                w = self._make_worker(client, budget=3)
                runs = _run(controller.run_worker_until_escalation(w, 1, pool, verbose=False))
                self.assertEqual(len(runs), 2)
                self.assertEqual(w.escalation_reason, expected_reason)

    def test_tracks_autonomous_turns_on_worker(self):
        pool = CandidatePool()
        scripts = [_productive_turn("tt01"), _silent_turn()]
        client = FakeSDKClient(scripts)
        w = self._make_worker(client, budget=4)
        _run(controller.run_worker_until_escalation(w, 1, pool, verbose=False))
        self.assertEqual(len(w.autonomous_turns), 2)


# ---------------------------------------------------------------------------
# Stall streak updates
# ---------------------------------------------------------------------------


class TestUpdateWorkerStreaks(unittest.TestCase):
    def _make(self):
        w = controller.WorkerState(worker_id=1, options=None)
        w.alive = True
        return w

    def test_silent_increments_streak(self):
        w = self._make()
        w.progress_none_streak = 2
        w.escalation_reason = "silent"
        w.autonomous_turns = [WorkerTurnSummary(worker_id=1, iteration=1)]
        controller.update_worker_streaks([w])
        self.assertEqual(w.progress_none_streak, 3)

    def test_candidate_resets_streak(self):
        w = self._make()
        w.progress_none_streak = 3
        w.stall_warned = True
        w.escalation_reason = "candidate"
        w.autonomous_turns = [WorkerTurnSummary(worker_id=1, iteration=1)]
        controller.update_worker_streaks([w])
        self.assertEqual(w.progress_none_streak, 0)
        self.assertFalse(w.stall_warned)

    def test_productive_flows_reset_streak(self):
        w = self._make()
        w.progress_none_streak = 2
        w.stall_warned = True
        w.escalation_reason = "budget"
        s = WorkerTurnSummary(worker_id=1, iteration=1)
        s.flow_ids_touched = ["aaaa11"]
        w.autonomous_turns = [s]
        controller.update_worker_streaks([w])
        self.assertEqual(w.progress_none_streak, 0)
        self.assertFalse(w.stall_warned)

    def test_budget_without_flows_unchanged(self):
        """Budget escalation with no flow activity leaves streak intact."""
        w = self._make()
        w.progress_none_streak = 1
        w.escalation_reason = "budget"
        w.autonomous_turns = [WorkerTurnSummary(worker_id=1, iteration=1)]
        controller.update_worker_streaks([w])
        self.assertEqual(w.progress_none_streak, 1)


# ---------------------------------------------------------------------------
# apply_decision (simplified — no more streak mutation)
# ---------------------------------------------------------------------------


class TestApplyDecision(unittest.TestCase):
    def _make_worker(self):
        w = controller.WorkerState(worker_id=7, options=None)
        w.client = _StubClient()
        return w

    def test_continue_applies_budget_and_query(self):
        w = self._make_worker()
        d = WorkerDecision(kind="continue", worker_id=7, instruction="go",
                           progress="new", autonomous_budget=7)
        _run(controller.apply_decision(d, w, iteration=5))
        self.assertEqual(w.last_instruction, "go")
        self.assertEqual(w.client.queries, ["go"])
        self.assertEqual(w.autonomous_budget, 7)

    def test_continue_does_not_touch_streak(self):
        w = self._make_worker()
        w.progress_none_streak = 4
        w.stall_warned = True
        d = WorkerDecision(kind="continue", worker_id=7, instruction="go",
                           progress="new", autonomous_budget=5)
        _run(controller.apply_decision(d, w, iteration=5))
        self.assertEqual(w.progress_none_streak, 4)  # unchanged
        self.assertTrue(w.stall_warned)

    def test_stop_tears_down(self):
        w = self._make_worker()
        d = WorkerDecision(kind="stop", worker_id=7, reason="coverage complete")
        _run(controller.apply_decision(d, w, iteration=5))
        self.assertFalse(w.alive)

    def test_budget_clamped(self):
        w = self._make_worker()
        d = WorkerDecision(kind="continue", worker_id=7, instruction="go",
                           progress="new", autonomous_budget=999)
        _run(controller.apply_decision(d, w, iteration=5))
        self.assertLessEqual(w.autonomous_budget, 20)


# ---------------------------------------------------------------------------
# Prompt formatting
# ---------------------------------------------------------------------------


def _turn(worker_id: int, iteration: int, tools: list[str], flows: list[str], cands: list[str]) -> WorkerTurnSummary:
    s = WorkerTurnSummary(worker_id=worker_id, iteration=iteration, assistant_text="ran tests")
    s.tool_calls = [ToolCallRecord(name=n, input_summary="{}", result_summary="ok") for n in tools]
    s.flow_ids_touched = list(flows)
    s.candidate_ids = list(cands)
    return s


class TestPromptFormatting(unittest.TestCase):
    def test_pending_candidates_empty(self):
        pool = CandidatePool()
        self.assertEqual(controller._format_pending_candidates(pool), "No pending finding candidates.")

    def test_pending_candidates_populated(self):
        pool = CandidatePool()
        pool.add(title="XSS in search", severity="high", endpoint="GET /search",
                 flow_ids=["abcdef"], summary="reflection in q",
                 evidence_notes="script tag echoed", reproduction_hint="replay abcdef")
        out = controller._format_pending_candidates(pool)
        self.assertIn("c001", out)
        self.assertIn("XSS in search", out)
        self.assertIn("abcdef", out)

    def test_format_autonomous_run(self):
        turns = [
            _turn(1, 3, ["mcp__sectool__proxy_poll"], ["fl0w01"], []),
            _turn(1, 3, ["mcp__sectool__replay_send"], ["fl0w02"], ["c001"]),
        ]
        out = controller._format_autonomous_run(1, turns, "candidate")
        self.assertIn("Worker 1", out)
        self.assertIn("escalated: candidate", out)
        self.assertIn("Turn 1", out)
        self.assertIn("Turn 2", out)
        self.assertIn("fl0w02", out)
        self.assertIn("c001", out)

    def test_build_verifier_prompt(self):
        pool = CandidatePool()
        pool.add(title="T", severity="low", endpoint="/x",
                 flow_ids=["zz1122"], summary="s",
                 evidence_notes="e", reproduction_hint="r")
        w = controller.WorkerState(worker_id=1, options=None)
        w.escalation_reason = "candidate"
        turns = [_turn(1, 2, ["mcp__sectool__proxy_poll"], ["zz1122"], ["c001"])]

        msg = controller._build_verifier_prompt(
            workers=[w],
            worker_runs={1: turns},
            pending=pool.pending(),
            findings_summary="No findings filed yet.",
            iteration=2, max_iter=10,
            total_cost=0.5, max_cost=5.0,
            findings_count=0,
        )
        self.assertIn("iteration 2/10", msg)
        self.assertIn("cost $0.50/$5.00", msg)
        self.assertIn("Pending finding candidates", msg)
        self.assertIn("mcp__sectool__proxy_poll", msg)
        self.assertIn("verification_done", msg)

    def test_build_director_prompt(self):
        w = controller.WorkerState(worker_id=2, options=None)
        w.escalation_reason = "budget"
        turns = [_turn(2, 5, ["mcp__sectool__replay_send"], ["fl0w01"], [])]

        msg = controller._build_director_prompt(
            workers=[w],
            worker_runs={2: turns},
            verification_summary="Filed 1, dismissed 0.",
            findings_summary="1 finding so far.",
            iteration=5, max_iter=10,
            total_cost=1.25, max_cost=None,
            findings_count=1,
            stall_warnings="",
            follow_up_hints="",
            max_workers=4,
            user_prompt="Explore example.com for auth bugs.",
        )
        self.assertIn("iteration 5/10", msg)
        self.assertIn("Filed 1, dismissed 0.", msg)
        self.assertIn("**Alive:** [2]", msg)
        self.assertIn("Parallelism:** 1/4", msg)
        # The user's prompt must always be surfaced to the director.
        self.assertIn("**Assignment (user prompt):**", msg)
        self.assertIn("Explore example.com for auth bugs.", msg)
        # Iteration 1 fan-out directive must NOT appear in mid-run iterations.
        self.assertNotIn("Iteration 1 fan-out is mandatory", msg)

    def test_build_director_prompt_iter1_dispatch_nudge(self):
        w = controller.WorkerState(worker_id=1, options=None)
        w.escalation_reason = "silent"
        turns = [_turn(1, 3, ["mcp__sectool__proxy_poll"], ["fl0w01"], [])]

        msg = controller._build_director_prompt(
            workers=[w],
            worker_runs={1: turns},
            verification_summary="No pending candidates this iteration.",
            findings_summary="No findings filed yet.",
            iteration=1, max_iter=10,
            total_cost=0.2, max_cost=None,
            findings_count=0,
            stall_warnings="",
            follow_up_hints="",
            max_workers=4,
            user_prompt="Broad exploration of target.example.com",
        )
        self.assertIn("Iteration 1 fan-out is mandatory", msg)
        self.assertIn("plan_workers", msg)
        # Directive should explicitly call out silent/timed-out worker 1.
        self.assertIn("NOT a reason to stay at one worker", msg)
        self.assertIn("Broad exploration of target.example.com", msg)

    def test_build_director_prompt_iter1_no_nudge_when_parallelism_full(self):
        """If iter 1 is already at parallelism budget, the nudge is suppressed."""
        workers = []
        for wid in range(1, 5):
            w = controller.WorkerState(worker_id=wid, options=None)
            w.escalation_reason = "candidate"
            workers.append(w)

        msg = controller._build_director_prompt(
            workers=workers,
            worker_runs={w.worker_id: [] for w in workers},
            verification_summary="ok",
            findings_summary="x",
            iteration=1, max_iter=10,
            total_cost=0.0, max_cost=None,
            findings_count=0,
            stall_warnings="",
            follow_up_hints="",
            max_workers=4,
            user_prompt="anything",
        )
        self.assertNotIn("Iteration 1 fan-out is mandatory", msg)

    def test_verifier_system_prompt_covers_core_contract(self):
        """The verifier prompt must state the full sectool surface is available,
        enumerate its phase control tools, and reject the director's tools.

        Mirrors controller/secagent/prompts/verifier.go: the tight prompt no
        longer enumerates every sectool tool (the MCP surface already exposes
        them); it only names the shared-state caveats and decision tools.
        """
        from prompts import orchestrator_verifier

        prompt = orchestrator_verifier.build_system_prompt(max_workers=2)
        required_phrases = [
            "full sectool surface",
            "file_finding",
            "dismiss_candidate",
            "verification_done",
            "proxy_poll",  # the shared-state caveat still names this
            "Never file a finding you did not personally reproduce",
        ]
        for phrase in required_phrases:
            self.assertIn(phrase, prompt, f"verifier prompt missing `{phrase}`")
        # The director-only tools must be listed as rejected.
        for rejected in ("plan_workers", "continue_worker", "direction_done", "done"):
            self.assertIn(rejected, prompt,
                          f"verifier prompt should mention rejected `{rejected}`")

    def test_verifier_allowed_tools_uses_sectool_glob(self):
        """The verifier's allowed_tools must include the full sectool glob."""
        self.assertEqual(controller.ORCH_SECTOOL_TOOLS_GLOB, "mcp__sectool__*")

    def test_build_director_continue_prompt(self):
        msg = controller._build_director_continue_prompt(
            pending_wids={1, 3}, substep=2, max_substeps=4,
        )
        self.assertIn("substep 2/4", msg)
        self.assertIn("[1, 3]", msg)

    def test_build_director_self_review_prompt(self):
        msg = controller._build_director_self_review_prompt()
        self.assertIn("Self-review", msg)
        self.assertIn("direction_done", msg)


# ---------------------------------------------------------------------------
# Phase drivers (integration over FakeSDKClient)
# ---------------------------------------------------------------------------


def _orch_result(cost: float = 0.01) -> ResultMessage:
    return _result(cost)


def _orch_tool_turn(tool_name: str, tool_input: dict, cost: float = 0.01) -> list:
    """Produce an orchestrator turn that calls one orch tool."""
    return [
        AssistantMessage(
            content=[
                TextBlock(text=f"Calling {tool_name}."),
                ToolUseBlock(id="t1", name=f"mcp__orch_tools__{tool_name}", input=tool_input),
            ],
            model="test",
        ),
        UserMessage(content=[
            ToolResultBlock(tool_use_id="t1",
                            content=[{"type": "text", "text": "ok"}]),
        ]),
        _orch_result(cost),
    ]


class _OrchSideEffectClient(FakeSDKClient):
    """FakeSDKClient that invokes `decisions.<method>` before yielding messages.

    The driver breaks out on ResultMessage so side effects attached AFTER the
    final yield never fire — we run them up-front instead. Simulates the MCP
    tool handler having already populated `decisions` by the time the turn
    completes.
    """

    def __init__(self, scripts, decisions: DecisionQueue, actions_per_turn: list):
        super().__init__(scripts)
        self._decisions = decisions
        self._actions = list(actions_per_turn)

    def receive_response(self):
        if isinstance(self._scripts, dict):
            idx = max(0, len(self.queries) - 1)
            messages = self._scripts[idx]
        else:
            if not self._scripts:
                raise AssertionError("No more scripted turns")
            messages = self._scripts.pop(0)
        action = self._actions.pop(0) if self._actions else None
        if action is not None:
            action(self._decisions)

        async def gen():
            for m in messages:
                yield m
        return gen()


class TestVerificationPhase(unittest.TestCase):
    def _seed_pool(self, pool: CandidatePool) -> str:
        return pool.add(title="XSS", severity="high", endpoint="/s",
                        flow_ids=["fl0w01"], summary="", evidence_notes="",
                        reproduction_hint="")

    def test_ends_on_verification_done(self):
        pool = CandidatePool()
        cid = self._seed_pool(pool)
        decisions = DecisionQueue()

        def action(d: DecisionQueue):
            d.add_finding(FindingFiled(
                title="XSS", severity="high", endpoint="/s",
                description="d", reproduction_steps="r", evidence="e", impact="i",
                verification_notes="replayed fl0w01",
                supersedes_candidate_ids=[cid],
            ))
            d.set_verification_done("one filed")

        client = _OrchSideEffectClient([_orch_tool_turn("verification_done", {"summary": "x"})],
                                       decisions, [action])
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            new_managed, cost, summary = _run(controller.run_verification_phase(
                _FakeManaged(client), None, decisions, pool, fw,
                worker_runs={}, workers=[],
                iteration=1, max_iter=10, total_cost=0.0, max_cost=None, verbose=False,
            ))
        self.assertEqual(summary, "one filed")
        self.assertEqual(fw.count, 1)
        self.assertEqual(pool.get(cid).status, "verified")

    def test_ends_when_no_pending_left(self):
        pool = CandidatePool()
        cid = self._seed_pool(pool)
        decisions = DecisionQueue()

        def action(d: DecisionQueue):
            d.add_dismissal(cid, "false positive")

        client = _OrchSideEffectClient([_orch_tool_turn("dismiss_candidate", {"candidate_id": cid, "reason": "fp"})],
                                       decisions, [action])
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            _, _, summary = _run(controller.run_verification_phase(
                _FakeManaged(client), None, decisions, pool, fw,
                worker_runs={}, workers=[],
                iteration=1, max_iter=10, total_cost=0.0, max_cost=None, verbose=False,
            ))
        self.assertIn("dismissed", summary)
        self.assertEqual(pool.get(cid).status, "dismissed")

    def test_file_finding_without_supersedes_auto_resolves_matching_candidate(self):
        pool = CandidatePool()
        cid = pool.add(title="Reflected XSS in search", severity="high",
                       endpoint="GET /search", flow_ids=["fl0w01"],
                       summary="", evidence_notes="", reproduction_hint="")
        decisions = DecisionQueue()

        def action(d: DecisionQueue):
            d.add_finding(FindingFiled(
                title="Reflected XSS in search results", severity="high",
                endpoint="get /search/",
                description="d", reproduction_steps="r", evidence="e", impact="i",
                verification_notes="replayed fl0w01",
                supersedes_candidate_ids=[],  # forgotten — should auto-resolve
            ))
            d.set_verification_done("one filed")

        client = _OrchSideEffectClient(
            [_orch_tool_turn("verification_done", {"summary": "x"})],
            decisions, [action],
        )
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            _run(controller.run_verification_phase(
                _FakeManaged(client), None, decisions, pool, fw,
                worker_runs={}, workers=[],
                iteration=1, max_iter=10, total_cost=0.0, max_cost=None, verbose=False,
            ))
        self.assertEqual(fw.count, 1)
        self.assertEqual(pool.get(cid).status, "verified")

    def test_file_finding_without_supersedes_leaves_unrelated_candidate_pending(self):
        pool = CandidatePool()
        c_match = pool.add(title="Reflected XSS in search", severity="high",
                           endpoint="GET /search", flow_ids=["fl0w01"],
                           summary="", evidence_notes="", reproduction_hint="")
        c_other = pool.add(title="SQL injection in login", severity="high",
                           endpoint="POST /login", flow_ids=["fl0w02"],
                           summary="", evidence_notes="", reproduction_hint="")
        decisions = DecisionQueue()

        def action(d: DecisionQueue):
            d.add_finding(FindingFiled(
                title="Reflected XSS in search", severity="high",
                endpoint="GET /search",
                description="d", reproduction_steps="r", evidence="e", impact="i",
                verification_notes="replayed fl0w01",
                supersedes_candidate_ids=[],
            ))
            d.add_dismissal(c_other, "insufficient evidence")
            d.set_verification_done("one filed, one dismissed")

        client = _OrchSideEffectClient(
            [_orch_tool_turn("verification_done", {"summary": "x"})],
            decisions, [action],
        )
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            _run(controller.run_verification_phase(
                _FakeManaged(client), None, decisions, pool, fw,
                worker_runs={}, workers=[],
                iteration=1, max_iter=10, total_cost=0.0, max_cost=None, verbose=False,
            ))
        self.assertEqual(pool.get(c_match).status, "verified")
        self.assertEqual(pool.get(c_other).status, "dismissed")

    def test_explicit_supersedes_beats_auto_match(self):
        """If verifier lists supersedes, only those are resolved — no heuristic."""
        pool = CandidatePool()
        c_explicit = pool.add(title="Some other title", severity="high",
                              endpoint="POST /login", flow_ids=["fl0w01"],
                              summary="", evidence_notes="", reproduction_hint="")
        c_similar = pool.add(title="Reflected XSS", severity="high",
                             endpoint="GET /search", flow_ids=["fl0w02"],
                             summary="", evidence_notes="", reproduction_hint="")
        decisions = DecisionQueue()

        def action(d: DecisionQueue):
            d.add_finding(FindingFiled(
                title="Reflected XSS", severity="high", endpoint="GET /search",
                description="d", reproduction_steps="r", evidence="e", impact="i",
                verification_notes="v",
                supersedes_candidate_ids=[c_explicit],
            ))
            d.add_dismissal(c_similar, "cleanup")
            d.set_verification_done("ok")

        client = _OrchSideEffectClient(
            [_orch_tool_turn("verification_done", {"summary": "x"})],
            decisions, [action],
        )
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            _run(controller.run_verification_phase(
                _FakeManaged(client), None, decisions, pool, fw,
                worker_runs={}, workers=[],
                iteration=1, max_iter=10, total_cost=0.0, max_cost=None, verbose=False,
            ))
        # Explicit one is verified; similar-but-not-listed one was dismissed (not auto-verified)
        self.assertEqual(pool.get(c_explicit).status, "verified")
        self.assertEqual(pool.get(c_similar).status, "dismissed")

    def test_skips_phase_when_no_pending(self):
        pool = CandidatePool()
        decisions = DecisionQueue()
        client = FakeSDKClient([])  # must never be queried
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            _, cost, summary = _run(controller.run_verification_phase(
                _FakeManaged(client), None, decisions, pool, fw,
                worker_runs={}, workers=[],
                iteration=1, max_iter=10, total_cost=0.0, max_cost=None, verbose=False,
            ))
        self.assertEqual(cost, 0.0)
        self.assertEqual(client.queries, [])
        self.assertIn("No pending candidates", summary)


class TestDirectionPhase(unittest.TestCase):
    def _make_worker(self, wid: int):
        w = controller.WorkerState(worker_id=wid, options=None)
        w.alive = True
        return w

    def test_ends_when_all_workers_covered(self):
        decisions = DecisionQueue()
        w1 = self._make_worker(1)
        w2 = self._make_worker(2)

        def action(d: DecisionQueue):
            d.add_decision(WorkerDecision(kind="continue", worker_id=1,
                                          instruction="keep", progress="new"))
            d.add_decision(WorkerDecision(kind="continue", worker_id=2,
                                          instruction="keep", progress="new"))
            # Note: NO direction_done called — driver should still exit because all covered.

        # Two scripted turns: the coverage turn + the mandatory self-review turn.
        self_review_turn = [
            AssistantMessage(content=[TextBlock(text="no changes")], model="test"),
            _orch_result(0.001),
        ]
        client = _OrchSideEffectClient(
            [
                _orch_tool_turn("continue_worker",
                                {"worker_id": 1, "instruction": "k", "progress": "new"}),
                self_review_turn,
            ],
            decisions, [action, None],
        )
        new_managed, cost = _run(controller.run_direction_phase(
            _FakeManaged(client), None, decisions, [w1, w2], worker_runs={},
            verification_summary="ok", findings_summary="x",
            iteration=1, max_iter=10, total_cost=0.0, max_cost=None,
            findings_count=0, stall_warnings="", follow_up_hints="", verbose=False,
            max_workers=4, user_prompt="test",
        ))
        self.assertEqual(len(decisions.worker_decisions), 2)
        # self-review substep should have fired after main loop exit.
        self.assertEqual(len(client.queries), 2)
        self.assertIn("Self-review", client.queries[-1])

    def test_ends_on_direction_done(self):
        decisions = DecisionQueue()
        w1 = self._make_worker(1)

        def action(d: DecisionQueue):
            d.set_direction_done("done")

        # After direction_done, self-review still fires (the guard only skips
        # self-review when `done(summary)` ended the full run).
        self_review_turn = [
            AssistantMessage(content=[TextBlock(text="no changes")], model="test"),
            _orch_result(0.001),
        ]
        client = _OrchSideEffectClient(
            [
                _orch_tool_turn("direction_done", {"summary": "d"}),
                self_review_turn,
            ],
            decisions, [action, None],
        )
        new_managed, cost = _run(controller.run_direction_phase(
            _FakeManaged(client), None, decisions, [w1], worker_runs={},
            verification_summary="ok", findings_summary="x",
            iteration=1, max_iter=10, total_cost=0.0, max_cost=None,
            findings_count=0, stall_warnings="", follow_up_hints="", verbose=False,
            max_workers=4, user_prompt="test",
        ))
        self.assertEqual(decisions.direction_done_summary, "done")

    def test_self_review_skipped_when_done_called(self):
        """If the director calls `done(summary)`, skip the self-review substep."""
        decisions = DecisionQueue()
        w1 = self._make_worker(1)

        def action(d: DecisionQueue):
            d.set_done("finished")

        client = _OrchSideEffectClient(
            [_orch_tool_turn("done", {"summary": "finished"})],
            decisions, [action],
        )
        _run(controller.run_direction_phase(
            _FakeManaged(client), None, decisions, [w1], worker_runs={},
            verification_summary="ok", findings_summary="x",
            iteration=1, max_iter=10, total_cost=0.0, max_cost=None,
            findings_count=0, stall_warnings="", follow_up_hints="", verbose=False,
            max_workers=4, user_prompt="test",
        ))
        self.assertEqual(decisions.done_summary, "finished")
        # No self-review query should have fired.
        self.assertEqual(len(client.queries), 1)

    def test_reaches_substep_cap(self):
        """When the director keeps making fresh progress each substep but
        never covers the alive worker, the main loop runs to the cap and
        self-review fires afterward (because decisions were produced)."""
        decisions = DecisionQueue()
        # Alive worker is id=1; the test queues stop decisions for other ids
        # so the coverage check never fires and the main loop runs to the cap.
        w1 = self._make_worker(1)

        def make_action(i: int):
            def act(d: DecisionQueue):
                d.add_decision(WorkerDecision(
                    kind="stop", worker_id=100 + i, reason="cleanup",
                ))
            return act

        script = [
            _orch_tool_turn("stop_worker",
                            {"worker_id": 100 + i, "reason": "x"})
            for i in range(1, controller.DIRECTION_MAX_SUBSTEPS + 1)
        ]
        script.append([
            AssistantMessage(content=[TextBlock(text="self-review done")], model="test"),
            _orch_result(0.001),
        ])
        actions = [make_action(i) for i in range(1, controller.DIRECTION_MAX_SUBSTEPS + 1)]
        actions.append(None)

        client = _OrchSideEffectClient(script, decisions, actions)
        _, cost = _run(controller.run_direction_phase(
            _FakeManaged(client), None, decisions, [w1], worker_runs={},
            verification_summary="ok", findings_summary="x",
            iteration=1, max_iter=10, total_cost=0.0, max_cost=None,
            findings_count=0, stall_warnings="", follow_up_hints="", verbose=False,
            max_workers=4, user_prompt="test",
        ))
        self.assertEqual(
            len(client.queries), controller.DIRECTION_MAX_SUBSTEPS + 1,
            "main loop should hit cap then run one self-review substep",
        )
        self.assertIn("Self-review", client.queries[-1])


class TestClearLeakedCancellations(unittest.TestCase):
    """The helper drains `task.cancelling()` via `task.uncancel()`.

    SDK anyio cancel scopes propagate onto our asyncio task when
    `asyncio.wait_for` times out mid-stream. Without draining, subsequent
    awaits in the same task raise CancelledError.
    """

    def test_no_pending_cancellation_returns_zero(self):
        async def body():
            return controller._clear_leaked_cancellations("test")
        self.assertEqual(_run(body()), 0)

    def test_drains_pending_cancellations(self):
        """Cancel a sub-task and verify the helper drains its counter.

        Run inside a sub-task so the outer `asyncio.run` doesn't observe
        the cancellation: on 3.11/3.12, `uncancel()` decrements the counter
        but doesn't clear the `_must_cancel` flag set by `task.cancel()`,
        so the task finalizes as cancelled even though the counter is 0.
        That doesn't affect the helper's real-world contract (anyio
        cancel-scope leaks don't set `_must_cancel`), but it would otherwise
        break this test on 3.11/3.12.
        """
        captured: dict = {}

        async def inner():
            task = asyncio.current_task()
            if not hasattr(task, "uncancel"):
                captured["skip"] = True
                return
            task.cancel()
            captured["before"] = task.cancelling()
            captured["cleared"] = controller._clear_leaked_cancellations()
            captured["after"] = task.cancelling()

        async def body():
            inner_task = asyncio.create_task(inner())
            try:
                await inner_task
            except asyncio.CancelledError:
                pass

        _run(body())

        if captured.get("skip"):
            self.skipTest("Python < 3.11: Task.uncancel/cancelling unavailable")
        self.assertGreater(captured["before"], 0)
        self.assertEqual(captured["after"], 0)
        self.assertGreaterEqual(captured["cleared"], 1)

    def test_survives_no_current_task(self):
        """Helper returns 0 when called outside an async task context."""
        # Called synchronously (no running event loop / current task).
        self.assertEqual(controller._clear_leaked_cancellations(), 0)


class TestManagedTeardown(unittest.TestCase):
    """Teardown delegates to `ManagedSDKClient.aclose()` — the managed client
    owns the real lifecycle (entering/exiting the SDK client on its own
    runner task). teardown_worker only needs to trigger the aclose and
    clear the references."""

    def test_teardown_calls_aclose_and_clears_refs(self):
        class _Managed:
            def __init__(self):
                self.aclosed = False

            async def aclose(self):
                self.aclosed = True

        w = controller.WorkerState(worker_id=1, options=object())
        managed = _Managed()
        w.client = object()
        w.managed = managed

        _run(controller.teardown_worker(w))

        self.assertTrue(managed.aclosed)
        self.assertIsNone(w.client)
        self.assertIsNone(w.managed)
        self.assertFalse(w.alive)

    def test_teardown_noop_when_no_managed(self):
        w = controller.WorkerState(worker_id=1, options=object())
        w.client = None
        w.managed = None
        # Should not raise
        _run(controller.teardown_worker(w))
        self.assertFalse(w.alive)


class TestCancelledErrorIsolation(unittest.TestCase):
    """A CancelledError in one per-worker task must not crash the whole run."""

    def test_cancelled_worker_marked_error_others_survive(self):
        class _Managed:
            def __init__(self):
                self.aclosed = False

            async def aclose(self):
                self.aclosed = True

        w1 = controller.WorkerState(worker_id=1, options=object())
        w1.client = object()  # non-None so it's treated as alive-with-client
        w1.managed = _Managed()
        w2 = controller.WorkerState(worker_id=2, options=object())
        w2.client = object()
        w2.managed = _Managed()

        call_count = {"w1": 0, "w2": 0}

        async def fake_run(worker, iteration, candidates, verbose):
            if worker.worker_id == 1:
                call_count["w1"] += 1
                raise asyncio.CancelledError()
            call_count["w2"] += 1
            worker.escalation_reason = "silent"
            return []

        orig = controller.run_worker_until_escalation
        controller.run_worker_until_escalation = fake_run
        try:
            results = _run(controller.run_all_workers_until_escalation(
                [w1, w2], iteration=1, candidates=CandidatePool(), verbose=False,
            ))
        finally:
            controller.run_worker_until_escalation = orig

        # Both workers were entered.
        self.assertEqual(call_count["w1"], 1)
        self.assertEqual(call_count["w2"], 1)
        # The cancelled worker was marked error and its managed client was
        # aclosed + cleared, so the main-loop recovery branch will rebuild it
        # next iteration.
        self.assertEqual(w1.escalation_reason, "error")
        self.assertIsNone(w1.client)
        self.assertIsNone(w1.managed)
        self.assertTrue(w1.alive, "cancelled worker should stay alive for recovery")
        # The surviving worker's result is preserved.
        self.assertIn(2, results)


class TestManagedSDKClientScopeIsolation(unittest.TestCase):
    """The whole point of ManagedSDKClient: a cancellation that fires inside
    the runner task's anyio scope must NOT poison the caller task. Without
    the ManagedSDKClient wrapper, entering the SDK's internal task group on
    the main task leaks a cancelled ancestor scope into main's stack."""

    def test_runner_cancellation_does_not_propagate_to_caller(self):
        """A CancelledError raised inside the runner task must not leak onto
        the main task after aclose. This is the core invariant that makes
        ManagedSDKClient useful."""
        orig = controller.ClaudeSDKClient

        class _CancelDuringExitClient:
            def __init__(self, options):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                # Simulate an anyio task-group __aexit__ that terminates with
                # CancelledError (exactly what happens when the SDK's internal
                # scope was cancelled mid-operation).
                raise asyncio.CancelledError()

            async def query(self, content: str) -> None:
                pass

        controller.ClaudeSDKClient = _CancelDuringExitClient
        try:
            async def body():
                m = controller.ManagedSDKClient(options=object())
                await m.connect()
                # aclose triggers __aexit__ → CancelledError inside runner.
                await m.aclose()
                # Main must still be usable.
                await asyncio.sleep(0)
                return True

            self.assertTrue(_run(body()))
        finally:
            controller.ClaudeSDKClient = orig

    def test_connect_aclose_roundtrip(self):
        """Verify ManagedSDKClient.connect + aclose works end-to-end without
        a real SDK by stubbing `ClaudeSDKClient` on the controller module."""
        orig = controller.ClaudeSDKClient

        class _FakeClient:
            def __init__(self, options):
                self.options = options

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def query(self, content: str) -> None:
                pass

        controller.ClaudeSDKClient = _FakeClient
        try:
            async def body():
                m = controller.ManagedSDKClient(options=object())
                client = await m.connect()
                assert isinstance(client, _FakeClient)
                await m.aclose()
                return m.client is None

            self.assertTrue(_run(body()))
        finally:
            controller.ClaudeSDKClient = orig

    def test_connect_surfaces_enter_exception(self):
        """If __aenter__ raises, connect() must propagate the error."""
        orig = controller.ClaudeSDKClient

        class _FailClient:
            def __init__(self, options):
                pass

            async def __aenter__(self):
                raise RuntimeError("boom")

            async def __aexit__(self, *exc):
                return False

        controller.ClaudeSDKClient = _FailClient
        try:
            async def body():
                m = controller.ManagedSDKClient(options=object())
                try:
                    await m.connect()
                    return None
                except RuntimeError as e:
                    return str(e)

            self.assertEqual(_run(body()), "boom")
        finally:
            controller.ClaudeSDKClient = orig


class TestPrematureDoneGuard(unittest.TestCase):
    def test_premature_when_early_and_no_findings(self):
        from tools import MIN_ITERATIONS_FOR_DONE
        for it in range(1, MIN_ITERATIONS_FOR_DONE):
            self.assertTrue(controller._is_premature_done(it, 0),
                            f"iter {it} with 0 findings should be premature")

    def test_not_premature_with_findings(self):
        self.assertFalse(controller._is_premature_done(1, 1))
        self.assertFalse(controller._is_premature_done(2, 3))

    def test_not_premature_past_min_iteration(self):
        from tools import MIN_ITERATIONS_FOR_DONE
        self.assertFalse(
            controller._is_premature_done(MIN_ITERATIONS_FOR_DONE, 0),
        )
        self.assertFalse(
            controller._is_premature_done(MIN_ITERATIONS_FOR_DONE + 1, 0),
        )


# ---------------------------------------------------------------------------
# Finding lifecycle (retained)
# ---------------------------------------------------------------------------


class TestFindingLifecycle(unittest.TestCase):
    def test_finding_and_dismissal_drains(self):
        pool = CandidatePool()
        decisions = DecisionQueue()
        c1 = pool.add(title="XSS", severity="high", endpoint="GET /s",
                      flow_ids=["aaaa11"], summary="", evidence_notes="",
                      reproduction_hint="")
        c2 = pool.add(title="SQLi", severity="critical", endpoint="POST /l",
                      flow_ids=["bbbb22"], summary="", evidence_notes="",
                      reproduction_hint="")

        decisions.add_finding(FindingFiled(
            title="Reflected XSS", severity="high", endpoint="GET /s",
            description="d", reproduction_steps="r", evidence="e", impact="i",
            verification_notes="replayed aaaa11 with payload — got reflection",
            supersedes_candidate_ids=[c1],
        ))
        decisions.add_dismissal(c2, "already covered")
        decisions.set_done("coverage complete")

        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            for f in decisions.findings:
                fw.write(f)
                for cid in f.supersedes_candidate_ids:
                    pool.mark(cid, "verified")
            for dm in decisions.dismissals:
                pool.mark(dm.candidate_id, "dismissed")

        self.assertEqual(fw.count, 1)
        self.assertEqual(pool.get(c1).status, "verified")
        self.assertEqual(pool.get(c2).status, "dismissed")
        self.assertEqual(pool.pending(), [])
        self.assertEqual(decisions.done_summary, "coverage complete")

    def test_merge_resolves_candidates_without_extra_finding(self):
        """A second candidate for the same underlying issue is merged in,
        not filed as a near-duplicate. Both candidates resolve verified."""
        from tools import FindingMerged

        pool = CandidatePool()
        c1 = pool.add(title="XSS", severity="high", endpoint="GET /s",
                      flow_ids=["aaaa11"], summary="", evidence_notes="",
                      reproduction_hint="")
        c2 = pool.add(title="XSS variant", severity="high", endpoint="GET /s2",
                      flow_ids=["bbbb22"], summary="", evidence_notes="",
                      reproduction_hint="")

        decisions = DecisionQueue()
        decisions.add_finding(FindingFiled(
            title="Reflected XSS", severity="high", endpoint="GET /s",
            description="d", reproduction_steps="r", evidence="e", impact="i",
            verification_notes="v1", supersedes_candidate_ids=[c1],
        ))
        decisions.add_merge(FindingMerged(
            finding_id="F1",
            rationale="same vuln, additional endpoint",
            additional_endpoint="GET /s2",
            additional_evidence="param `q` reflected on /s2 too",
            supersedes_candidate_ids=[c2],
        ))

        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            for f in decisions.findings:
                fw.write(f)
                for cid in f.supersedes_candidate_ids:
                    pool.mark(cid, "verified")
            for mg in decisions.merges:
                self.assertIsNotNone(fw.merge(
                    mg.finding_id,
                    rationale=mg.rationale,
                    additional_endpoint=mg.additional_endpoint,
                    additional_evidence=mg.additional_evidence,
                ))
                for cid in mg.supersedes_candidate_ids:
                    pool.mark(cid, "verified")

        self.assertEqual(fw.count, 1)
        self.assertEqual(pool.get(c1).status, "verified")
        self.assertEqual(pool.get(c2).status, "verified")
        self.assertEqual(pool.pending(), [])


class TestVerifyDedup(unittest.TestCase):
    """A1, A3: per-substep dedup of dismissals and findings."""

    def test_dismiss_dedup_logs_once_per_id(self):
        """Repeated `dismiss_candidate` calls for one id must only log once."""
        pool = CandidatePool()
        cid = pool.add(title="A", severity="low", endpoint="/x",
                       flow_ids=["aaaa11"], summary="", evidence_notes="",
                       reproduction_hint="")
        decisions = DecisionQueue()

        # Verifier dismisses the same id twice in one burst, then finishes.
        def action(d: DecisionQueue):
            d.add_dismissal(cid, "dup 1")
            d.add_dismissal(cid, "dup 2")
            d.set_verification_done("ok")

        client = _OrchSideEffectClient(
            [_orch_tool_turn("verification_done", {"summary": "x"})],
            decisions, [action],
        )

        logs: list[tuple[str, str]] = []
        original_log = controller.log
        controller.log = lambda tag, msg: logs.append((tag, msg))
        try:
            with tempfile.TemporaryDirectory() as td:
                fw = FindingWriter(td)
                _run(controller.run_verification_phase(
                    _FakeManaged(client), None, decisions, pool, fw,
                    worker_runs={}, workers=[],
                    iteration=1, max_iter=10, total_cost=0.0, max_cost=None, verbose=False,
                ))
        finally:
            controller.log = original_log

        dismiss_lines = [m for t, m in logs if "dismissed" in m and cid in m]
        self.assertEqual(
            len(dismiss_lines), 1,
            f"expected one dismissal log, got: {dismiss_lines}",
        )
        self.assertEqual(pool.get(cid).status, "dismissed")

    def test_dismiss_cannot_override_verified(self):
        """A1 + A4: once verified, a late dismissal must not downgrade."""
        pool = CandidatePool()
        cid = pool.add(title="A", severity="high", endpoint="GET /x",
                       flow_ids=["aaaa11"], summary="", evidence_notes="",
                       reproduction_hint="")
        decisions = DecisionQueue()

        def action(d: DecisionQueue):
            d.add_finding(FindingFiled(
                title="A", severity="high", endpoint="GET /x",
                description="d", reproduction_steps="r", evidence="e",
                impact="i", verification_notes="v",
                supersedes_candidate_ids=[cid],
            ))
            d.add_dismissal(cid, "races with file_finding")
            d.set_verification_done("done")

        client = _OrchSideEffectClient(
            [_orch_tool_turn("verification_done", {"summary": "x"})],
            decisions, [action],
        )
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            _run(controller.run_verification_phase(
                _FakeManaged(client), None, decisions, pool, fw,
                worker_runs={}, workers=[],
                iteration=1, max_iter=10, total_cost=0.0, max_cost=None, verbose=False,
            ))
        self.assertEqual(pool.get(cid).status, "verified")

    def test_finding_duplicate_logged_once_per_substep(self):
        """A3: same title filed multiple times in one substep → one disk write."""
        pool = CandidatePool()
        cid = pool.add(title="A", severity="high", endpoint="GET /x",
                       flow_ids=["aaaa11"], summary="", evidence_notes="",
                       reproduction_hint="")
        decisions = DecisionQueue()

        def action(d: DecisionQueue):
            for _ in range(3):
                d.add_finding(FindingFiled(
                    title="Reflected XSS", severity="high", endpoint="GET /x",
                    description="d", reproduction_steps="r", evidence="e",
                    impact="i", verification_notes="v",
                    supersedes_candidate_ids=[cid],
                ))
            d.set_verification_done("ok")

        client = _OrchSideEffectClient(
            [_orch_tool_turn("verification_done", {"summary": "x"})],
            decisions, [action],
        )
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            _run(controller.run_verification_phase(
                _FakeManaged(client), None, decisions, pool, fw,
                worker_runs={}, workers=[],
                iteration=1, max_iter=10, total_cost=0.0, max_cost=None, verbose=False,
            ))
            self.assertEqual(fw.count, 1)


class TestVerifyFallback(unittest.TestCase):
    """Orphan-log emission in verify phase when auto-match misses."""

    def test_orphan_logged_when_no_match(self):
        """No strict match → candidate stays pending and orphan log fires."""
        pool = CandidatePool()
        cid = pool.add(title="Reflected XSS in search", severity="high",
                       endpoint="GET /search", flow_ids=["aaaa11"],
                       summary="", evidence_notes="", reproduction_hint="")
        decisions = DecisionQueue()

        def action(d: DecisionQueue):
            d.add_finding(FindingFiled(
                title="Totally unrelated auth issue", severity="high",
                endpoint="POST /totally-different-path",
                description="d", reproduction_steps="r", evidence="e",
                impact="i", verification_notes="v",
                supersedes_candidate_ids=[],
            ))
            # Keep the candidate pending by NOT calling verification_done —
            # but we need to exit the loop somehow. Use dismiss_candidate
            # on a bogus id to keep pending unchanged, then done.
            d.set_verification_done("orphan run")

        client = _OrchSideEffectClient(
            [_orch_tool_turn("verification_done", {"summary": "x"})],
            decisions, [action],
        )
        logs: list[tuple[str, str]] = []
        original = controller.log
        controller.log = lambda tag, msg: logs.append((tag, msg))
        try:
            with tempfile.TemporaryDirectory() as td:
                fw = FindingWriter(td)
                _run(controller.run_verification_phase(
                    _FakeManaged(client), None, decisions, pool, fw,
                    worker_runs={}, workers=[],
                    iteration=1, max_iter=10, total_cost=0.0, max_cost=None, verbose=False,
                ))
        finally:
            controller.log = original

        self.assertEqual(pool.get(cid).status, "pending")
        orphan_lines = [m for _, m in logs if "finding orphan" in m]
        self.assertEqual(len(orphan_lines), 1)
        self.assertIn(cid, orphan_lines[0])


class TestDirectionEfficiency(unittest.TestCase):
    """C2, C3: no-progress early-exit and self-review gating."""

    def _make_worker(self, wid: int):
        w = controller.WorkerState(worker_id=wid, options=None)
        w.alive = True
        return w

    def test_early_exit_on_no_progress(self):
        """Director produces one decision on substep 1, nothing on 2 & 3
        → loop exits before substep 4 and self-review still runs."""
        decisions = DecisionQueue()
        w1 = self._make_worker(1)
        w2 = self._make_worker(2)

        # Substep 1 adds one decision for a non-alive id (so coverage never
        # completes). Substeps 2 and 3 add nothing. After two no-progress
        # substeps, the main loop breaks. Self-review fires because
        # decisions were produced on substep 1.
        def action1(d: DecisionQueue):
            d.add_decision(WorkerDecision(
                kind="stop", worker_id=999, reason="non-alive cleanup"))

        empty_turn = [
            AssistantMessage(content=[TextBlock(text="nothing to add")], model="test"),
            _orch_result(0.001),
        ]
        self_review_turn = [
            AssistantMessage(content=[TextBlock(text="self review")], model="test"),
            _orch_result(0.001),
        ]
        client = _OrchSideEffectClient(
            [
                _orch_tool_turn("stop_worker", {"worker_id": 999, "reason": "x"}),
                list(empty_turn),
                list(empty_turn),
                list(empty_turn),                  # defensive — should not reach
                self_review_turn,
            ],
            decisions,
            [action1, None, None, None, None],
        )
        _run(controller.run_direction_phase(
            _FakeManaged(client), None, decisions, [w1, w2], worker_runs={},
            verification_summary="ok", findings_summary="x",
            iteration=1, max_iter=10, total_cost=0.0, max_cost=None,
            findings_count=0, stall_warnings="", follow_up_hints="", verbose=False,
            max_workers=4, user_prompt="test",
        ))
        # 3 substeps in main loop (1 decision + 2 no-progress) + 1 self-review.
        self.assertLess(
            len(client.queries), controller.DIRECTION_MAX_SUBSTEPS + 1,
            "should have broken out of main loop early",
        )
        self.assertIn("Self-review", client.queries[-1])

class TestPromptBuilders(unittest.TestCase):
    """B1, B2, B3 prompt-shape checks."""

    def test_director_prompt_includes_stopped_roster(self):
        alive = controller.WorkerState(worker_id=1, options=None)
        alive.alive = True
        stopped = controller.WorkerState(worker_id=2, options=None)
        stopped.alive = False
        msg = controller._build_director_prompt(
            workers=[alive, stopped],
            worker_runs={1: []},
            verification_summary="ok",
            findings_summary="x",
            iteration=3, max_iter=10,
            total_cost=0.0, max_cost=None,
            findings_count=0, stall_warnings="", follow_up_hints="",
            max_workers=4, user_prompt="test",
        )
        self.assertIn("Stopped this run: [2]", msg)
        self.assertIn("do not re-plan around these", msg)

    def test_director_prompt_omits_stopped_line_when_none(self):
        alive = controller.WorkerState(worker_id=1, options=None)
        alive.alive = True
        msg = controller._build_director_prompt(
            workers=[alive],
            worker_runs={1: []},
            verification_summary="ok",
            findings_summary="x",
            iteration=3, max_iter=10,
            total_cost=0.0, max_cost=None,
            findings_count=0, stall_warnings="", follow_up_hints="",
            max_workers=4, user_prompt="test",
        )
        self.assertNotIn("Stopped this run", msg)

    def test_worker_continue_with_findings_summary(self):
        prompt = controller._build_worker_continue_prompt(
            findings_summary="Findings filed so far — do not re-file:\n- XSS — /s",
        )
        self.assertIn("Findings filed so far — do not re-file:", prompt)
        self.assertIn("XSS — /s", prompt)
        self.assertIn(controller._BARE_WORKER_CONTINUE, prompt)

    def test_worker_continue_without_findings_returns_bare(self):
        prompt = controller._build_worker_continue_prompt(findings_summary="")
        self.assertEqual(prompt, controller._BARE_WORKER_CONTINUE)

    def test_verifier_continue_lists_phase_progress(self):
        pool = CandidatePool()
        pool.add(title="T", severity="low", endpoint="/x",
                 flow_ids=["aaaa11"], summary="", evidence_notes="",
                 reproduction_hint="")
        filed = [FindingFiled(
            title="Admin PUT JSON Injection", severity="high", endpoint="PUT /admin",
            description="d", reproduction_steps="r", evidence="e", impact="i",
            verification_notes="v",
        )]
        dismissed = [controller.CandidateDismissal(candidate_id="c004", reason="fp")]
        msg = controller._build_verifier_continue_prompt(
            pending=pool.pending(),
            filed_this_phase=filed,
            merged_this_phase=[],
            dismissed_this_phase=dismissed,
            substep=2, max_substeps=6,
        )
        self.assertIn("substep 2/6", msg)
        self.assertIn("Already filed this phase", msg)
        self.assertIn("Admin PUT JSON Injection", msg)
        self.assertIn("Already dismissed this phase", msg)
        self.assertIn("c004", msg)

    def test_verifier_continue_omits_sections_when_empty(self):
        pool = CandidatePool()
        msg = controller._build_verifier_continue_prompt(
            pending=pool.pending(),
            filed_this_phase=[],
            merged_this_phase=[],
            dismissed_this_phase=[],
            substep=2, max_substeps=6,
        )
        self.assertNotIn("Already filed this phase", msg)
        self.assertNotIn("Already merged this phase", msg)
        self.assertNotIn("Already dismissed this phase", msg)

    def test_verifier_continue_lists_merges(self):
        from tools import FindingMerged

        pool = CandidatePool()
        merges = [FindingMerged(finding_id="F2", rationale="same vuln, new endpoint")]
        msg = controller._build_verifier_continue_prompt(
            pending=pool.pending(),
            filed_this_phase=[],
            merged_this_phase=merges,
            dismissed_this_phase=[],
            substep=3, max_substeps=6,
        )
        self.assertIn("Already merged this phase", msg)
        self.assertIn("F2", msg)
        self.assertIn("same vuln, new endpoint", msg)


class TestCoalesceInApplyLoop(unittest.TestCase):
    """A2 hookup: when two decisions for the same worker land, apply once."""

    def test_last_writer_wins_single_apply(self):
        from tools import coalesce_decisions as _coalesce
        d1 = WorkerDecision(kind="continue", worker_id=5,
                            instruction="first", progress="new")
        d2 = WorkerDecision(kind="continue", worker_id=5,
                            instruction="second", progress="new")
        out = _coalesce([d1, d2], None)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].instruction, "second")


if __name__ == "__main__":
    unittest.main()
