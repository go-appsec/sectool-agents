"""Unit tests for tools.py — queue recording, phase gating, and flow IDs."""

import unittest

from tools import (
    CandidatePool,
    DEFAULT_AUTONOMOUS_BUDGET,
    DecisionQueue,
    FindingFiled,
    PHASE_DIRECTION,
    PHASE_IDLE,
    PHASE_VERIFICATION,
    PlanEntry,
    WorkerDecision,
    _parse_plan_args,
    _reject_wrong_phase,
    coalesce_decisions,
    extract_flow_ids,
)


class TestCandidatePool(unittest.TestCase):
    def test_worker_id_attribution(self):
        p = CandidatePool()
        cid = p.add(worker_id=3, title="T", severity="medium", endpoint="/z",
                    flow_ids=["qq11rr"], summary="s", evidence_notes="e",
                    reproduction_hint="r")
        self.assertEqual(p.get(cid).worker_id, 3)

    def test_pending_excludes_verified_and_dismissed(self):
        p = CandidatePool()
        c1 = p.add(worker_id=1, title="A", severity="high", endpoint="/x",
                   flow_ids=["a1b2c3"], summary="", evidence_notes="",
                   reproduction_hint="")
        c2 = p.add(worker_id=1, title="B", severity="low", endpoint="/y",
                   flow_ids=["d4e5f6"], summary="", evidence_notes="",
                   reproduction_hint="")
        c3 = p.add(worker_id=1, title="C", severity="low", endpoint="/z",
                   flow_ids=["g7h8i9"], summary="", evidence_notes="",
                   reproduction_hint="")
        p.mark(c1, "verified")
        p.mark(c3, "dismissed")
        self.assertEqual([c.candidate_id for c in p.pending()], [c2])

    def test_ids_since(self):
        p = CandidatePool()
        p.add(worker_id=1, title="a", severity="low", endpoint="/",
              flow_ids=["aaaa11"], summary="", evidence_notes="",
              reproduction_hint="")
        before = p.counter
        p.add(worker_id=1, title="b", severity="low", endpoint="/",
              flow_ids=["bbbb22"], summary="", evidence_notes="",
              reproduction_hint="")
        p.add(worker_id=1, title="c", severity="low", endpoint="/",
              flow_ids=["cccc33"], summary="", evidence_notes="",
              reproduction_hint="")
        self.assertEqual(p.ids_since(before), ["c002", "c003"])

    def test_ids_since_for_worker_filters(self):
        p = CandidatePool()
        p.add(worker_id=1, title="w1", severity="low", endpoint="/",
              flow_ids=["aaaa11"], summary="", evidence_notes="",
              reproduction_hint="")
        before = p.counter
        p.add(worker_id=2, title="w2a", severity="low", endpoint="/",
              flow_ids=["bbbb22"], summary="", evidence_notes="",
              reproduction_hint="")
        p.add(worker_id=2, title="w2b", severity="low", endpoint="/",
              flow_ids=["cccc33"], summary="", evidence_notes="",
              reproduction_hint="")
        p.add(worker_id=1, title="w1b", severity="low", endpoint="/",
              flow_ids=["dddd44"], summary="", evidence_notes="",
              reproduction_hint="")

        self.assertEqual(p.ids_since_for_worker(before, 2), ["c002", "c003"])
        self.assertEqual(p.ids_since_for_worker(before, 1), ["c004"])
        self.assertEqual(p.ids_since_for_worker(before, 99), [])


class TestPlanAccumulation(unittest.TestCase):
    """Multiple plan_workers calls in one phase must accumulate.

    Claude routinely issues plan_workers across several tool calls
    (e.g. one call per new worker). If set_plan replaced rather than
    merged, only the last call's entries would survive, which manifests
    as "director wanted 3 workers but only 1 spawned".
    """

    def test_two_calls_different_ids_accumulate(self):
        q = DecisionQueue()
        q.begin_phase(PHASE_DIRECTION)
        q.set_plan([PlanEntry(2, "scan /api")])
        q.set_plan([PlanEntry(3, "scan /admin")])
        self.assertIsNotNone(q.plan)
        ids = [p.worker_id for p in q.plan]
        self.assertEqual(sorted(ids), [2, 3])

    def test_same_id_overrides_last_wins(self):
        q = DecisionQueue()
        q.begin_phase(PHASE_DIRECTION)
        q.set_plan([PlanEntry(2, "first")])
        q.set_plan([PlanEntry(2, "second")])
        self.assertEqual(len(q.plan), 1)
        self.assertEqual(q.plan[0].assignment, "second")

    def test_mixed_new_and_override(self):
        q = DecisionQueue()
        q.begin_phase(PHASE_DIRECTION)
        q.set_plan([PlanEntry(2, "a"), PlanEntry(3, "b")])
        q.set_plan([PlanEntry(3, "b2"), PlanEntry(4, "c")])
        by_id = {p.worker_id: p.assignment for p in q.plan}
        self.assertEqual(by_id, {2: "a", 3: "b2", 4: "c"})

    def test_reset_clears_accumulated_plan(self):
        q = DecisionQueue()
        q.begin_phase(PHASE_DIRECTION)
        q.set_plan([PlanEntry(2, "a"), PlanEntry(3, "b")])
        q.reset()
        self.assertIsNone(q.plan)

    def test_phase_boundary_does_not_carry_plan_across_iters(self):
        """After controller reset() between iterations, plans don't leak."""
        q = DecisionQueue()
        q.begin_phase(PHASE_DIRECTION)
        q.set_plan([PlanEntry(2, "iter-1")])
        q.reset()
        q.begin_phase(PHASE_DIRECTION)
        q.set_plan([PlanEntry(3, "iter-2")])
        self.assertEqual([p.worker_id for p in q.plan], [3])


class TestDecisionQueuePhases(unittest.TestCase):
    def test_reset_clears_all(self):
        q = DecisionQueue()
        q.begin_phase(PHASE_DIRECTION)
        q.set_plan([PlanEntry(1, "x")])
        q.add_decision(WorkerDecision(kind="continue", worker_id=1, instruction="i", progress="new"))
        q.begin_phase(PHASE_VERIFICATION)
        q.add_finding(FindingFiled(title="T", severity="high", endpoint="/", description="",
                                    reproduction_steps="", evidence="", impact="",
                                    verification_notes="v"))
        q.add_dismissal("c001", "false positive")
        q.set_verification_done("verified")
        q.begin_phase(PHASE_DIRECTION)
        q.set_direction_done("directed")
        q.set_done("wrap")

        q.reset()
        self.assertIsNone(q.plan)
        self.assertEqual(q.worker_decisions, [])
        self.assertEqual(q.findings, [])
        self.assertEqual(q.dismissals, [])
        self.assertIsNone(q.done_summary)
        self.assertIsNone(q.verification_done_summary)
        self.assertIsNone(q.direction_done_summary)
        self.assertEqual(q.phase, PHASE_IDLE)

    def test_begin_phase_transitions(self):
        q = DecisionQueue()
        self.assertEqual(q.current_phase, PHASE_IDLE)
        q.begin_phase(PHASE_VERIFICATION)
        self.assertEqual(q.current_phase, PHASE_VERIFICATION)
        q.set_verification_done("ok")
        self.assertEqual(q.verification_done_summary, "ok")
        # Re-entering a phase clears only its own done flag
        q.begin_phase(PHASE_VERIFICATION)
        self.assertIsNone(q.verification_done_summary)

    def test_begin_phase_does_not_clear_other_accumulators(self):
        q = DecisionQueue()
        q.begin_phase(PHASE_VERIFICATION)
        q.add_finding(FindingFiled(title="T", severity="high", endpoint="/", description="",
                                    reproduction_steps="", evidence="", impact="",
                                    verification_notes="v"))
        q.begin_phase(PHASE_DIRECTION)
        self.assertEqual(len(q.findings), 1)  # findings accumulate across phase switches within an iter

    def test_decisions_by_worker_returns_latest_kind(self):
        q = DecisionQueue()
        q.begin_phase(PHASE_DIRECTION)
        q.add_decision(WorkerDecision(kind="continue", worker_id=1, instruction="x", progress="new"))
        q.add_decision(WorkerDecision(kind="continue", worker_id=2, instruction="y", progress="new"))
        # Same worker re-issued — latest wins.
        q.add_decision(WorkerDecision(kind="stop", worker_id=2, reason="done"))
        by_wid = q.decisions_by_worker()
        self.assertEqual(by_wid, {1: "continue", 2: "stop"})

    def test_reset_clears_merges_too(self):
        from tools import FindingMerged
        q = DecisionQueue()
        q.begin_phase(PHASE_VERIFICATION)
        q.add_merge(FindingMerged(finding_id="F1", rationale="dup"))
        self.assertEqual(len(q.merges), 1)
        q.reset()
        self.assertEqual(q.merges, [])


class TestRejectWrongPhase(unittest.TestCase):
    def test_error_shape_and_content(self):
        cases = [
            (PHASE_DIRECTION, PHASE_VERIFICATION, "plan_workers",
             ["plan_workers", "verification", "verification_done"]),
            (PHASE_VERIFICATION, PHASE_DIRECTION, "file_finding", ["file_finding"]),
        ]
        for current, expected, tool, must_include in cases:
            with self.subTest(tool=tool):
                out = _reject_wrong_phase(current, expected, tool)
                self.assertTrue(out["is_error"])
                for needle in must_include:
                    self.assertIn(needle, out["content"][0]["text"])


class TestWorkerDecisionDefaults(unittest.TestCase):
    def test_autonomous_budget_default(self):
        d = WorkerDecision(kind="continue", worker_id=1, instruction="go", progress="new")
        self.assertEqual(d.autonomous_budget, DEFAULT_AUTONOMOUS_BUDGET)


class TestExtractFlowIds(unittest.TestCase):
    def test_text_keyword_patterns(self):
        text = (
            "I opened flow_id=abcdef and also source_flow_id: DEF456. "
            'Nested: flow_a="xy12zz", flow_b=11qq2.'
        )
        ids = extract_flow_ids(text)
        for expected in ("abcdef", "DEF456", "xy12zz", "11qq2"):
            self.assertIn(expected, ids)

    def test_dict_flow_id_field(self):
        d = {"flow_id": "id0001", "inner": {"source_flow_id": "id0002"}}
        ids = extract_flow_ids(d)
        self.assertIn("id0001", ids)
        self.assertIn("id0002", ids)

    def test_list_of_dicts(self):
        lst = [{"flow_id": "aaaa11"}, {"flow_id": "bbbb22"}]
        ids = extract_flow_ids(lst)
        self.assertEqual(ids, ["aaaa11", "bbbb22"])

    def test_dedup_and_order_preserved(self):
        ids = extract_flow_ids(
            "flow_id AAAA11",
            {"flow_id": "BBBB22"},
            "flow_id AAAA11 seen again",
            {"flow_id": "CCCC33"},
        )
        self.assertEqual(ids, ["AAAA11", "BBBB22", "CCCC33"])

    def test_no_match_without_keyword(self):
        ids = extract_flow_ids("I saw ABCDEF and QWERTY as tokens.")
        self.assertEqual(ids, [])

    def test_ignores_none_values(self):
        ids = extract_flow_ids(None, "flow_id zz11aa")
        self.assertEqual(ids, ["zz11aa"])

    def test_bare_flow_in_prose_does_not_match(self):
        self.assertEqual(extract_flow_ids("data flow analysis found an issue"), [])
        self.assertEqual(extract_flow_ids("the flow chart shows"), [])
        self.assertEqual(extract_flow_ids("request flow through the system"), [])


class TestCandidatePoolMark(unittest.TestCase):
    """A4: mark must enforce legal transitions and be sticky on terminal states."""

    def _pool_with(self, *titles: str) -> tuple[CandidatePool, list[str]]:
        p = CandidatePool()
        ids = [
            p.add(worker_id=1, title=t, severity="low", endpoint="/x",
                  flow_ids=["aaaa11"], summary="", evidence_notes="",
                  reproduction_hint="")
            for t in titles
        ]
        return p, ids

    def test_pending_to_verified_transitions(self):
        p, [c1] = self._pool_with("a")
        self.assertTrue(p.mark(c1, "verified"))
        self.assertEqual(p.get(c1).status, "verified")

    def test_pending_to_dismissed_transitions(self):
        p, [c1] = self._pool_with("a")
        self.assertTrue(p.mark(c1, "dismissed"))
        self.assertEqual(p.get(c1).status, "dismissed")

    def test_verified_cannot_become_dismissed(self):
        p, [c1] = self._pool_with("a")
        p.mark(c1, "verified")
        self.assertFalse(p.mark(c1, "dismissed"))
        self.assertEqual(p.get(c1).status, "verified")

    def test_dismissed_cannot_become_verified(self):
        p, [c1] = self._pool_with("a")
        p.mark(c1, "dismissed")
        self.assertFalse(p.mark(c1, "verified"))
        self.assertEqual(p.get(c1).status, "dismissed")

    def test_unknown_status_rejected(self):
        p, [c1] = self._pool_with("a")
        self.assertFalse(p.mark(c1, "bogus"))
        self.assertEqual(p.get(c1).status, "pending")

    def test_unknown_id_is_noop(self):
        p, _ = self._pool_with("a")
        self.assertFalse(p.mark("c999", "verified"))

    def test_repeated_mark_same_terminal_is_noop(self):
        p, [c1] = self._pool_with("a")
        self.assertTrue(p.mark(c1, "verified"))
        # A second verified call finds the candidate non-pending → no-op.
        self.assertFalse(p.mark(c1, "verified"))


class TestCoalesceDecisions(unittest.TestCase):
    """A2: collapse duplicate director decisions into one per worker."""

    def _dec(self, kind: str, wid: int, instruction: str = "go") -> WorkerDecision:
        return WorkerDecision(
            kind=kind, worker_id=wid, instruction=instruction, progress="new",
            reason="" if kind != "stop" else "r",
        )

    def test_empty(self):
        self.assertEqual(coalesce_decisions([], None), [])

    def test_single_passes_through(self):
        d = self._dec("continue", 1)
        self.assertEqual(coalesce_decisions([d], None), [d])

    def test_two_continues_for_one_worker_keeps_last(self):
        d1 = self._dec("continue", 1, "first")
        d2 = self._dec("continue", 1, "second")
        out = coalesce_decisions([d1, d2], None)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].instruction, "second")

    def test_stop_then_continue_last_wins(self):
        stop = self._dec("stop", 1)
        cont = self._dec("continue", 1, "after-stop")
        out = coalesce_decisions([stop, cont], None)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].kind, "continue")

    def test_continue_then_stop_last_wins(self):
        cont = self._dec("continue", 1, "first")
        stop = self._dec("stop", 1)
        out = coalesce_decisions([cont, stop], None)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].kind, "stop")

    def test_mixed_workers_preserved(self):
        d1 = self._dec("continue", 1, "a")
        d2 = self._dec("expand", 2, "b")
        d3 = self._dec("stop", 3)
        out = coalesce_decisions([d1, d2, d3], None)
        self.assertEqual([d.worker_id for d in out], [1, 2, 3])

    def test_plan_entry_drops_continue_and_expand(self):
        cont = self._dec("continue", 2, "keep going")
        expand = self._dec("expand", 3, "pivot")
        out = coalesce_decisions(
            [cont, expand],
            [PlanEntry(2, "new assignment"), PlanEntry(3, "other")],
        )
        # Both dropped — plan covers them via the spawn/retarget path.
        self.assertEqual(out, [])

    def test_plan_entry_does_not_drop_stop(self):
        stop = self._dec("stop", 2)
        out = coalesce_decisions([stop], [PlanEntry(2, "retarget")])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].kind, "stop")

    def test_ordering_stable_by_first_seen(self):
        d2 = self._dec("continue", 2, "x")
        d1 = self._dec("continue", 1, "y")
        d1b = self._dec("continue", 1, "z")  # updates last for worker 1
        out = coalesce_decisions([d2, d1, d1b], None)
        # Order follows first-seen: worker 2 first, then worker 1.
        self.assertEqual([d.worker_id for d in out], [2, 1])


class TestPlanWorkersHandler(unittest.TestCase):
    """C1: plan_workers must return per-field detail on rejection.

    Tests exercise `_parse_plan_args` directly; the async handler just
    wraps it with phase-gating and response formatting.
    """

    def test_missing_plans_key_returns_detail(self):
        entries, rej, err = _parse_plan_args({})
        self.assertIsNone(entries)
        self.assertIn("cannot parse arguments", err)
        self.assertIn("plans", err)

    def test_non_list_plans_returns_detail(self):
        entries, rej, err = _parse_plan_args({"plans": "nope"})
        self.assertIsNone(entries)
        self.assertIn("cannot parse arguments", err)

    def test_empty_plans_returns_detail(self):
        entries, rej, err = _parse_plan_args({"plans": []})
        self.assertIsNone(entries)
        self.assertIn("'plans' array is empty", err)

    def test_all_invalid_returns_per_entry_reasons(self):
        entries, rej, err = _parse_plan_args({"plans": [
            {"worker_id": 0, "assignment": "x"},          # wid < 1
            {"worker_id": 2, "assignment": ""},           # empty assignment
            {"worker_id": "abc", "assignment": "y"},      # bad wid type
            {"assignment": "z"},                          # missing wid
            {"worker_id": 5},                             # missing assignment
        ]})
        self.assertIsNone(entries)
        self.assertIn("no valid plan entries", err)
        self.assertIn("worker_id must be >= 1", err)
        self.assertIn("assignment is empty", err)
        self.assertIn("worker_id must be an integer", err)
        self.assertIn("worker_id is required", err)
        self.assertIn("assignment is required", err)

    def test_partial_success_surfaces_skipped(self):
        entries, rej, err = _parse_plan_args({"plans": [
            {"worker_id": 2, "assignment": "scan /api"},   # valid
            {"worker_id": 0, "assignment": "bad"},         # skipped
        ]})
        self.assertIsNone(err)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].worker_id, 2)
        self.assertEqual(entries[0].assignment, "scan /api")
        self.assertEqual(len(rej), 1)
        self.assertIn("worker_id must be >= 1", rej[0])

    def test_all_valid_no_rejections(self):
        entries, rej, err = _parse_plan_args({"plans": [
            {"worker_id": 1, "assignment": "a"},
            {"worker_id": 2, "assignment": "b"},
        ]})
        self.assertIsNone(err)
        self.assertEqual([e.worker_id for e in entries], [1, 2])
        self.assertEqual(rej, [])


class TestValidateRepoHint(unittest.TestCase):
    """_validate_repro_hint guards against sparse hints reaching the verifier."""

    def test_too_short_rejected(self):
        from tools import _validate_repro_hint
        err = _validate_repro_hint("see flows", ["aaaa11"])
        self.assertIsNotNone(err)
        self.assertIn("too short", err)

    def test_paraphrase_without_actionable_content_rejected(self):
        """Long but vague — no flow_id, no method, no replay/curl/request keyword."""
        from tools import _validate_repro_hint
        hint = "The endpoint is broken and exposes data when you try a different id."
        err = _validate_repro_hint(hint, ["aaaa11"])
        self.assertIsNotNone(err)
        self.assertIn("flow_id", err)

    def test_flow_id_reference_accepted(self):
        from tools import _validate_repro_hint
        err = _validate_repro_hint("Replay flow aaaa11 with id=124; expect 403.", ["aaaa11"])
        self.assertIsNone(err)

    def test_http_method_accepted(self):
        from tools import _validate_repro_hint
        err = _validate_repro_hint("Send a POST to /api/x with body {…}; observe reflected payload.", [])
        self.assertIsNone(err)

    def test_curl_keyword_accepted(self):
        from tools import _validate_repro_hint
        err = _validate_repro_hint("curl https://target/x?q=<script> and check the body for echo.", [])
        self.assertIsNone(err)


if __name__ == "__main__":
    unittest.main()
