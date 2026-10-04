"""Unit tests for tools.py — queue recording, phase gating, and flow IDs."""

import unittest

from tools import (
    MIN_ITERATIONS_FOR_DONE,
    CandidatePool,
    DecisionQueue,
    FindingFiled,
    FindingMerged,
    PHASE_DIRECTION,
    PHASE_IDLE,
    PHASE_VERIFICATION,
    PlanEntry,
    WorkerDecision,
    _done_guard_rejection,
    _is_premature_done,
    _parse_plan_args,
    _reject_wrong_phase,
    _unresolved_pending_ids,
    _verification_done_rejection,
    coalesce_decisions,
    extract_flow_ids,
)


class TestCandidatePool(unittest.TestCase):
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
        q.add_decision(WorkerDecision(kind="continue", worker_id=1, instruction="i"))
        q.begin_phase(PHASE_VERIFICATION)
        q.add_finding(FindingFiled(title="T", severity="high", endpoint="/", description="",
                                    reproduction_steps="", evidence="", impact="",
                                    verification_notes="v"))
        q.add_dismissal("c001", "false positive")
        q.set_verification_done("verified")
        q.begin_phase(PHASE_DIRECTION)
        q.set_direction_done("directed")
        q.set_done("wrap")

        q.add_merge(FindingMerged(finding_id="F1", rationale="same bug"))

        # Simulate the controller applying every queue record.
        q.applied_findings.extend(q.findings)
        q.applied_dismissals.extend(q.dismissals)
        q.applied_merges.extend(q.merges)

        q.reset()
        self.assertIsNone(q.plan)
        self.assertEqual(q.worker_decisions, [])
        self.assertEqual(q.findings, [])
        self.assertEqual(q.dismissals, [])
        self.assertEqual(q.applied_findings, [])
        self.assertEqual(q.applied_dismissals, [])
        self.assertEqual(q.applied_merges, [])
        self.assertIsNone(q.done_summary)
        self.assertIsNone(q.verification_done_summary)
        self.assertIsNone(q.direction_done_summary)
        self.assertEqual(q.phase, PHASE_IDLE)

    def test_worker_decision_has_no_progress_field(self):
        """Issue 24: the progress tag fed no logic — removed from the contract."""
        self.assertNotIn("progress", WorkerDecision.__dataclass_fields__)

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
        q.add_decision(WorkerDecision(kind="continue", worker_id=1, instruction="x"))
        q.add_decision(WorkerDecision(kind="continue", worker_id=2, instruction="y"))
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


class TestExtractFlowIds(unittest.TestCase):
    def test_text_keyword_patterns(self):
        text = (
            "I opened flow_id=abcdef and also source_flow_id: DEF456. "
            'Nested: flow_a="xy12zz", flow_b=11qq22.'
        )
        ids = extract_flow_ids(text)
        for expected in ("abcdef", "DEF456", "xy12zz", "11qq22"):
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
            "flow_id=AAAA11",
            {"flow_id": "BBBB22"},
            "flow_id: AAAA11 seen again",
            {"flow_id": "CCCC33"},
        )
        self.assertEqual(ids, ["AAAA11", "BBBB22", "CCCC33"])

    def test_no_match_without_keyword(self):
        ids = extract_flow_ids("I saw ABCDEF and QWERTY as tokens.")
        self.assertEqual(ids, [])

    def test_ignores_none_values(self):
        ids = extract_flow_ids(None, "flow_id: zz11aa")
        self.assertEqual(ids, ["zz11aa"])

    def test_bare_flow_in_prose_does_not_match(self):
        self.assertEqual(extract_flow_ids("data flow analysis found an issue"), [])
        self.assertEqual(extract_flow_ids("the flow chart shows"), [])
        self.assertEqual(extract_flow_ids("request flow through the system"), [])

    def test_suffix_embedded_key_does_not_match(self):
        self.assertEqual(extract_flow_ids("workflow_id=abc123 and dataflow_id=def456"), [])

    def test_prose_without_separator_does_not_match(self):
        self.assertEqual(extract_flow_ids("flow_a returned nothing"), [])
        self.assertEqual(extract_flow_ids("flow a was dismissed"), [])
        self.assertEqual(extract_flow_ids("flow_id abc123"), [])

    def test_dict_value_shape_validation(self):
        self.assertEqual(extract_flow_ids({"flow_id": "ab1", "flow_a": "abc-123!"}), [])
        self.assertEqual(extract_flow_ids({"flow_id": 123456, "flow_b": True}), ["123456"])

    def test_plural_keys_text_and_dicts(self):
        ids = extract_flow_ids(
            '"flow_ids": ["ab12cd", "ef34gh"], flow_ids=aa11bb',
            {"source_flow_ids": ["cc22dd"]},
            {"flow_id": ["ww33xx"]},
        )
        self.assertEqual(ids, ["ab12cd", "ef34gh", "aa11bb", "cc22dd", "ww33xx"])

    def test_oversized_tokens_rejected_entirely(self):
        # No truncation: over-long tokens fail the whole match.
        self.assertEqual(extract_flow_ids("flow_id: abc123def456"), [])
        self.assertEqual(extract_flow_ids({"flow_id": "abc123def456"}), [])
        self.assertEqual(
            extract_flow_ids('"flow_ids": ["abc123def", "ab12cd"]'),
            ["ab12cd"],
        )


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

    def _dec(self, kind: str, wid: int, instruction: str = "go",
             budget: int | None = None) -> WorkerDecision:
        kwargs: dict = {
            "kind": kind, "worker_id": wid, "instruction": instruction,
            "reason": "" if kind != "stop" else "r",
        }
        if budget is not None:
            kwargs["autonomous_budget"] = budget
        return WorkerDecision(**kwargs)

    def test_empty(self):
        out = coalesce_decisions([], None)
        self.assertEqual(out.decisions, [])
        self.assertIsNone(out.plan)
        self.assertEqual(out.notes, [])

    def test_single_passes_through(self):
        d = self._dec("continue", 1)
        self.assertEqual(coalesce_decisions([d], None).decisions, [d])

    def test_two_continues_for_one_worker_keeps_last(self):
        d1 = self._dec("continue", 1, "first")
        d2 = self._dec("continue", 1, "second")
        out = coalesce_decisions([d1, d2], None)
        self.assertEqual(len(out.decisions), 1)
        self.assertEqual(out.decisions[0].instruction, "second")

    def test_stop_then_continue_last_wins(self):
        stop = self._dec("stop", 1)
        cont = self._dec("continue", 1, "after-stop")
        out = coalesce_decisions([stop, cont], None)
        self.assertEqual(len(out.decisions), 1)
        self.assertEqual(out.decisions[0].kind, "continue")

    def test_continue_then_stop_last_wins(self):
        cont = self._dec("continue", 1, "first")
        stop = self._dec("stop", 1)
        out = coalesce_decisions([cont, stop], None)
        self.assertEqual(len(out.decisions), 1)
        self.assertEqual(out.decisions[0].kind, "stop")

    def test_mixed_workers_preserved(self):
        d1 = self._dec("continue", 1, "a")
        d2 = self._dec("expand", 2, "b")
        d3 = self._dec("stop", 3)
        out = coalesce_decisions([d1, d2, d3], None)
        self.assertEqual([d.worker_id for d in out.decisions], [1, 2, 3])

    def test_paired_decision_folds_into_plan_entry(self):
        cont = self._dec("continue", 2, "keep going", budget=12)
        expand = self._dec("expand", 3, "pivot", budget=5)
        out = coalesce_decisions(
            [cont, expand],
            [PlanEntry(2, "new assignment"), PlanEntry(3, "other")],
        )
        # Folded into the plan — no separate dispatch, one kickoff each.
        self.assertEqual(out.decisions, [])
        self.assertEqual(len(out.plan), 2)
        self.assertEqual(out.plan[0].instruction, "keep going")
        self.assertEqual(out.plan[0].autonomous_budget, 12)
        self.assertEqual(out.plan[1].instruction, "pivot")
        self.assertEqual(out.plan[1].autonomous_budget, 5)

    def test_last_paired_decision_wins(self):
        d1 = self._dec("continue", 2, "first", budget=3)
        d2 = self._dec("expand", 2, "second", budget=9)
        out = coalesce_decisions([d1, d2], [PlanEntry(2, "reassignment")])
        self.assertEqual(out.decisions, [])
        self.assertEqual(out.plan[0].instruction, "second")
        self.assertEqual(out.plan[0].autonomous_budget, 9)

    def test_unpaired_plan_entry_untouched(self):
        entry = PlanEntry(4, "fresh spawn")
        cont = self._dec("continue", 2, "go", budget=6)
        out = coalesce_decisions([cont], [entry])
        self.assertEqual(len(out.decisions), 1)
        self.assertIs(out.plan[0], entry)
        self.assertIsNone(out.plan[0].autonomous_budget)

    def test_fold_does_not_mutate_input_entry(self):
        cont = self._dec("continue", 2, "go", budget=6)
        entry = PlanEntry(2, "reassignment")
        out = coalesce_decisions([cont], [entry])
        # The fold lands on a copy; the queue's original stays pristine.
        self.assertIsNot(out.plan[0], entry)
        self.assertEqual(entry.instruction, "")
        self.assertIsNone(entry.autonomous_budget)

    def test_plan_entry_voided_by_stop(self):
        stop = self._dec("stop", 2)
        out = coalesce_decisions([stop], [PlanEntry(2, "retarget")])
        # Stop survives and wins — the plan must not connect a client.
        self.assertEqual(len(out.decisions), 1)
        self.assertEqual(out.decisions[0].kind, "stop")
        self.assertEqual(out.plan, [])

    def test_stop_without_plan_untouched(self):
        stop = self._dec("stop", 2)
        out = coalesce_decisions([stop], None)
        self.assertEqual(len(out.decisions), 1)
        self.assertIsNone(out.plan)

    def test_notes_describe_fold_and_void(self):
        cont = self._dec("continue", 2, "go", budget=12)
        stop = self._dec("stop", 3)
        out = coalesce_decisions(
            [cont, stop],
            [PlanEntry(2, "a"), PlanEntry(3, "b")],
        )
        self.assertEqual(len(out.notes), 2)
        self.assertIn("worker 2", out.notes[0])
        self.assertIn("folded", out.notes[0])
        self.assertIn("12", out.notes[0])
        self.assertIn("worker 3", out.notes[1])
        self.assertIn("stop decision takes precedence", out.notes[1])

    def test_ordering_stable_by_first_seen(self):
        d2 = self._dec("continue", 2, "x")
        d1 = self._dec("continue", 1, "y")
        d1b = self._dec("continue", 1, "z")  # updates last for worker 1
        out = coalesce_decisions([d2, d1, d1b], None)
        # Order follows first-seen: worker 2 first, then worker 1.
        self.assertEqual([d.worker_id for d in out.decisions], [2, 1])


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


class TestPrematureDonePredicate(unittest.TestCase):
    def test_truth_table(self):
        cases = [
            # (iter, findings, expected_premature)
            (1, 0, True),
            (MIN_ITERATIONS_FOR_DONE - 1, 0, True),
            (1, 1, False),                  # any finding clears the guard
            (2, 3, False),
            (MIN_ITERATIONS_FOR_DONE, 0, False),  # at threshold, no longer premature
            (MIN_ITERATIONS_FOR_DONE + 1, 0, False),
        ]
        for it, n, expected in cases:
            with self.subTest(iteration=it, findings=n):
                self.assertEqual(_is_premature_done(it, n), expected)


class TestDoneGuardRejection(unittest.TestCase):
    """07: done guards fire at the tool call so the director sees why."""

    def _queue(self) -> DecisionQueue:
        q = DecisionQueue()
        q.begin_phase(PHASE_DIRECTION)
        return q

    @staticmethod
    def _progress(iteration: int, findings: int):
        return lambda: (iteration, findings)

    def test_premature_rejected_with_explanation(self):
        msg = _done_guard_rejection(
            self._queue(), None, self._progress(2, 0))
        self.assertIsNotNone(msg)
        self.assertIn("premature", msg)
        self.assertIn(str(MIN_ITERATIONS_FOR_DONE), msg)
        self.assertIn("direction_done", msg)

    def test_findings_or_threshold_accepted(self):
        for it, n in ((1, 2), (MIN_ITERATIONS_FOR_DONE, 0)):
            with self.subTest(iteration=it, findings=n):
                msg = _done_guard_rejection(
                    self._queue(), None, self._progress(it, n))
                self.assertIsNone(msg)

    def test_no_progress_provider_skips_premature(self):
        self.assertIsNone(_done_guard_rejection(self._queue(), None, None))

    def test_alive_worker_without_stop_rejected(self):
        q = self._queue()
        q.add_decision(WorkerDecision(
            kind="continue", worker_id=4, instruction="go"))
        msg = _done_guard_rejection(
            q, lambda: [4], self._progress(MIN_ITERATIONS_FOR_DONE + 1, 0))
        self.assertIsNotNone(msg)
        self.assertIn("abandon live work", msg)

    def test_alive_worker_without_decision_rejected(self):
        msg = _done_guard_rejection(
            self._queue(), lambda: [4], self._progress(MIN_ITERATIONS_FOR_DONE + 1, 0))
        self.assertIsNotNone(msg)
        self.assertIn("no decision recorded", msg)

    def test_all_stopped_alive_workers_accepted(self):
        q = self._queue()
        q.add_decision(WorkerDecision(kind="stop", worker_id=4, reason="exhausted"))
        msg = _done_guard_rejection(
            q, lambda: [4], self._progress(MIN_ITERATIONS_FOR_DONE + 1, 0))
        self.assertIsNone(msg)

    def test_empty_alive_without_plan_rejected(self):
        """The iteration-1 recon teardown leaves no alive workers; done must
        not pass the live-work guard vacuously."""
        msg = _done_guard_rejection(
            self._queue(), lambda: [], self._progress(MIN_ITERATIONS_FOR_DONE + 1, 0))
        self.assertIsNotNone(msg)
        self.assertIn("no workers alive", msg)

    def test_empty_alive_with_plan_accepted(self):
        q = self._queue()
        q.set_plan([PlanEntry(2, "scan /api")])
        msg = _done_guard_rejection(
            q, lambda: [], self._progress(MIN_ITERATIONS_FOR_DONE + 1, 0))
        self.assertIsNone(msg)

    def test_no_alive_provider_skips_live_work(self):
        self.assertIsNone(_done_guard_rejection(self._queue(), None, None))


class TestBumpVerifyAttempts(unittest.TestCase):
    """Issue 28: failed verification attempts accumulate per pending candidate."""

    def _pool_with(self, *titles: str) -> tuple[CandidatePool, list[str]]:
        p = CandidatePool()
        ids = [
            p.add(worker_id=1, title=t, severity="low", endpoint="/x",
                  flow_ids=["aaaa11"], summary="", evidence_notes="",
                  reproduction_hint="")
            for t in titles
        ]
        return p, ids

    def test_counts_only_pending(self):
        p, [c1, c2] = self._pool_with("a", "b")
        p.mark(c2, "verified")
        out = p.bump_verify_attempts()
        self.assertEqual(out, {c1: 1})
        self.assertEqual(p.get(c1).verify_attempts, 1)
        self.assertEqual(p.get(c2).verify_attempts, 0)

    def test_attempts_accumulate(self):
        p, [c1] = self._pool_with("a")
        p.bump_verify_attempts()
        out = p.bump_verify_attempts()
        self.assertEqual(out, {c1: 2})

    def test_no_pending_returns_empty(self):
        p, _ = self._pool_with()
        self.assertEqual(p.bump_verify_attempts(), {})

    def test_terminal_candidates_never_resume_counting(self):
        """Terminal candidates are never bumped again."""
        p, [c1] = self._pool_with("a")
        p.bump_verify_attempts()
        p.mark(c1, "dismissed")
        self.assertEqual(p.bump_verify_attempts(), {})


class TestUnresolvedPendingIds(unittest.TestCase):
    """Issue 28: verification_done must see through queue records that the
    post-substep drain will apply — same-burst file/dismiss + done is honest."""

    def _queue(self) -> DecisionQueue:
        q = DecisionQueue()
        q.begin_phase(PHASE_VERIFICATION)
        return q

    def _pending_provider(self, *cids: str):
        return lambda: list(cids)

    def test_no_provider_means_nothing_unresolved(self):
        self.assertEqual(_unresolved_pending_ids(self._queue(), None), [])

    def test_pending_without_resolution_listed(self):
        ids = _unresolved_pending_ids(
            self._queue(), self._pending_provider("c001", "c002"))
        self.assertEqual(ids, ["c001", "c002"])

    def test_queued_dismissal_resolves(self):
        q = self._queue()
        q.add_dismissal("c001", "false positive")
        ids = _unresolved_pending_ids(q, self._pending_provider("c001", "c002"))
        self.assertEqual(ids, ["c002"])

    def test_queued_finding_supersedes_resolves(self):
        q = self._queue()
        q.add_finding(FindingFiled(
            title="T", severity="high", endpoint="/x", description="d",
            reproduction_steps="r", evidence="e", impact="i",
            verification_notes="v", supersedes_candidate_ids=["c001"]))
        ids = _unresolved_pending_ids(q, self._pending_provider("c001", "c002"))
        self.assertEqual(ids, ["c002"])

    def test_queued_merge_supersedes_resolves(self):
        q = self._queue()
        q.add_merge(FindingMerged(
            finding_id="F1", rationale="same bug",
            supersedes_candidate_ids=["c001"]))
        ids = _unresolved_pending_ids(q, self._pending_provider("c001"))
        self.assertEqual(ids, [])

    def test_supersedes_only_resolves_listed_candidates(self):
        """A finding linked to one candidate leaves others unresolved."""
        q = self._queue()
        q.add_finding(FindingFiled(
            title="T", severity="high", endpoint="/x", description="d",
            reproduction_steps="r", evidence="e", impact="i",
            verification_notes="v", supersedes_candidate_ids=["c001"]))
        ids = _unresolved_pending_ids(q, self._pending_provider("c002"))
        self.assertEqual(ids, ["c002"])


class TestVerificationDoneRejection(unittest.TestCase):
    """Issue 28: completing verification with unresolved candidates requires
    an explicit confirm_open acknowledgment."""

    def _queue(self) -> DecisionQueue:
        q = DecisionQueue()
        q.begin_phase(PHASE_VERIFICATION)
        return q

    def test_unresolved_without_confirm_rejected(self):
        msg = _verification_done_rejection(
            self._queue(), lambda: ["c001", "c002"], False)
        self.assertIsNotNone(msg)
        self.assertIn("c001, c002", msg)
        self.assertIn("confirm_open=true", msg)

    def test_confirm_open_acknowledges(self):
        msg = _verification_done_rejection(
            self._queue(), lambda: ["c001"], True)
        self.assertIsNone(msg)

    def test_no_candidates_accepted(self):
        msg = _verification_done_rejection(
            self._queue(), lambda: [], False)
        self.assertIsNone(msg)

    def test_queued_resolution_accepted_without_confirm(self):
        q = self._queue()
        q.add_dismissal("c001", "fp")
        msg = _verification_done_rejection(q, lambda: ["c001"], False)
        self.assertIsNone(msg)

    def test_no_provider_accepted(self):
        msg = _verification_done_rejection(
            self._queue(), None, False)
        self.assertIsNone(msg)


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

    def test_keyword_inside_word_rejected(self):
        """Issue 27: 'budget' must not satisfy the embedded 'get' keyword."""
        from tools import _validate_repro_hint
        hint = "Stay within budget while probing this endpoint for data leaks."
        err = _validate_repro_hint(hint, ["aaaa11"])
        self.assertIsNotNone(err)
        self.assertIn("must reference", err)

    def test_flow_id_inside_larger_token_rejected(self):
        """Issue 27: an id-shaped fragment must not satisfy the flow check."""
        from tools import _validate_repro_hint
        hint = "The aaaa1100 response token repeats on every retry attempt now."
        err = _validate_repro_hint(hint, ["aaaa11"])
        self.assertIsNotNone(err)
        self.assertIn("must reference", err)

    def test_flow_id_with_punctuation_accepted(self):
        from tools import _validate_repro_hint
        err = _validate_repro_hint(
            "Resend flow (aaaa11) twice and expect 403 on the second call.", ["aaaa11"])
        self.assertIsNone(err)


if __name__ == "__main__":
    unittest.main()
