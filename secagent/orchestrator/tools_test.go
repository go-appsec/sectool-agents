package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/orchestrator/prompts"
)

func findTool(defs []agent.ToolDef, name string) *agent.ToolDef {
	for i, d := range defs {
		if d.Name == name {
			return &defs[i]
		}
	}
	return nil
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()

	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestWorkerToolDefs(t *testing.T) {
	t.Parallel()

	baseArgs := func() map[string]any {
		return map[string]any{
			"title":             "XSS",
			"severity":          "high",
			"endpoint":          "GET /",
			"flow_ids":          []string{"abc123"},
			"summary":           "s",
			"evidence_notes":    "e",
			"reproduction_hint": "r",
		}
	}

	t.Run("report_candidate", func(t *testing.T) {
		pool := NewCandidatePool()
		defs := WorkerToolDefs(pool, nil, 7, nil, nil)
		require.Len(t, defs, 1)
		rc := findTool(defs, "report_finding_candidate")
		require.NotNil(t, rc)

		res := rc.Handler(t.Context(), mustMarshal(t, baseArgs()))
		assert.False(t, res.IsError, res.Text)
		assert.Contains(t, res.Text, "Candidate c001 recorded")
		pending := pool.Pending()
		require.Len(t, pending, 1)
		assert.Equal(t, 7, pending[0].WorkerID)
	})

	t.Run("rejects_bad_severity", func(t *testing.T) {
		pool := NewCandidatePool()
		rc := findTool(WorkerToolDefs(pool, nil, 1, nil, nil), "report_finding_candidate")
		require.NotNil(t, rc)
		args := baseArgs()
		args["severity"] = "nope"
		res := rc.Handler(t.Context(), mustMarshal(t, args))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "severity")
	})

	t.Run("rejects_empty_flow_ids", func(t *testing.T) {
		pool := NewCandidatePool()
		rc := findTool(WorkerToolDefs(pool, nil, 1, nil, nil), "report_finding_candidate")
		require.NotNil(t, rc)
		args := baseArgs()
		args["flow_ids"] = []string{}
		res := rc.Handler(t.Context(), mustMarshal(t, args))
		assert.True(t, res.IsError)
	})

	t.Run("rejects_filed_duplicate_exact_slug", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := NewFindingWriter(t.TempDir())
		_, err := writer.Write(FindingFiled{
			Title:    "XSS",
			Severity: "high",
			Endpoint: "GET /",
		})
		require.NoError(t, err)
		rc := findTool(WorkerToolDefs(pool, writer, 1, nil, nil), "report_finding_candidate")
		require.NotNil(t, rc)

		res := rc.Handler(t.Context(), mustMarshal(t, baseArgs()))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "already-filed")
		assert.Contains(t, res.Text, "XSS")
		assert.Empty(t, pool.Pending())
	})

	t.Run("admits_similar_title_when_no_reviewer", func(t *testing.T) {
		// Without a CandidateDedupReviewer the deterministic MatchesFiled
		// fallback only short-circuits exact slug+endpoint matches.
		// Similar titles route to the verifier-side dedup pipeline instead.
		pool := NewCandidatePool()
		writer := NewFindingWriter(t.TempDir())
		_, err := writer.Write(FindingFiled{
			Title:    "Reflected XSS in search",
			Severity: "high",
			Endpoint: "GET /search",
		})
		require.NoError(t, err)
		rc := findTool(WorkerToolDefs(pool, writer, 1, nil, nil), "report_finding_candidate")
		require.NotNil(t, rc)

		args := baseArgs()
		args["title"] = "Reflected XSS in search endpoint"
		args["endpoint"] = "GET /search"
		res := rc.Handler(t.Context(), mustMarshal(t, args))
		assert.False(t, res.IsError, res.Text)
		assert.Len(t, pool.Pending(), 1)
	})

	t.Run("admits_distinct_title_and_endpoint", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := NewFindingWriter(t.TempDir())
		_, err := writer.Write(FindingFiled{
			Title:    "XSS",
			Severity: "high",
			Endpoint: "GET /",
		})
		require.NoError(t, err)
		rc := findTool(WorkerToolDefs(pool, writer, 1, nil, nil), "report_finding_candidate")
		require.NotNil(t, rc)

		args := baseArgs()
		args["title"] = "SQL Injection in login"
		args["endpoint"] = "POST /login"
		res := rc.Handler(t.Context(), mustMarshal(t, args))
		assert.False(t, res.IsError, res.Text)
		assert.Len(t, pool.Pending(), 1)
	})

	dedupArgs := func() map[string]any {
		return map[string]any{
			"title":             "Reflected XSS in search",
			"severity":          "high",
			"endpoint":          "GET /search",
			"flow_ids":          []string{"abc123"},
			"summary":           "user input reflected",
			"evidence_notes":    "saw <script> echoed",
			"reproduction_hint": "send q=<script>alert(1)</script>",
		}
	}
	primeWriter := func(t *testing.T) *FindingWriter {
		t.Helper()

		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(FindingFiled{
			Title: "Open redirect on /go", Severity: "medium", Endpoint: "GET /go",
			Description: "Existing description.",
		})
		require.NoError(t, err)
		return w
	}

	t.Run("unique_admits_to_pool", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := primeWriter(t)
		dedup := &fakeCandidateDedup{verdict: CandidateDedupVerdict{Action: "unique"}}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, &fakeMerger{}), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, dedupArgs()))
		assert.False(t, res.IsError, res.Text)
		assert.Equal(t, 1, dedup.calls)
		assert.Len(t, pool.Pending(), 1)
	})

	t.Run("duplicate_rejects_with_cite", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := primeWriter(t)
		// matched filename will be the only finding's filename
		var matchedName string
		for _, d := range writer.Digests() {
			matchedName = d.Filename
		}
		require.NotEmpty(t, matchedName)
		dedup := &fakeCandidateDedup{verdict: CandidateDedupVerdict{
			Action: "duplicate", MatchedFilename: matchedName,
		}}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, &fakeMerger{}), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, dedupArgs()))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, matchedName)
		assert.Empty(t, pool.Pending())
	})

	t.Run("merge_acks_and_submits_async", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := primeWriter(t)
		var matchedName string
		for _, d := range writer.Digests() {
			matchedName = d.Filename
		}
		merger := &fakeMerger{}
		dedup := &fakeCandidateDedup{verdict: CandidateDedupVerdict{
			Action: "merge", MatchedFilename: matchedName,
		}}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, merger), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, dedupArgs()))
		assert.False(t, res.IsError, res.Text)
		assert.Contains(t, res.Text, matchedName)
		assert.Contains(t, res.Text, "merged")
		assert.Empty(t, pool.Pending())
		merger.mu.Lock()
		require.Len(t, merger.submissions, 1)
		assert.Equal(t, matchedName, merger.submissions[0].matched)
		merger.mu.Unlock()
	})

	t.Run("merge_without_merger_rejects", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := primeWriter(t)
		var matchedName string
		for _, d := range writer.Digests() {
			matchedName = d.Filename
		}
		dedup := &fakeCandidateDedup{verdict: CandidateDedupVerdict{
			Action: "merge", MatchedFilename: matchedName,
		}}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, nil), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, dedupArgs()))
		assert.True(t, res.IsError)
		assert.Empty(t, pool.Pending())
	})

	t.Run("classifier_error_fails_open", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := primeWriter(t)
		dedup := &fakeCandidateDedup{err: errors.New("boom")}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, &fakeMerger{}), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, dedupArgs()))
		assert.False(t, res.IsError, res.Text)
		assert.Len(t, pool.Pending(), 1)
	})

	t.Run("empty_index_skips_dedup", func(t *testing.T) {
		pool := NewCandidatePool()
		writer := NewFindingWriter(t.TempDir())
		dedup := &fakeCandidateDedup{}
		rc := findTool(WorkerToolDefs(pool, writer, 1, dedup, &fakeMerger{}), "report_finding_candidate")

		res := rc.Handler(t.Context(), mustMarshal(t, dedupArgs()))
		assert.False(t, res.IsError, res.Text)
		assert.Equal(t, 0, dedup.calls)
		assert.Len(t, pool.Pending(), 1)
	})
}

// fakeCandidateDedup is a scripted CandidateDedupReviewer for tool tests.
type fakeCandidateDedup struct {
	verdict CandidateDedupVerdict
	err     error
	calls   int
}

func (f *fakeCandidateDedup) ClassifyCandidate(_ context.Context, _ AddInput, _ []FindingDigest) (CandidateDedupVerdict, error) {
	f.calls++
	return f.verdict, f.err
}

// fakeMerger collects async merge submissions for assertion.
type fakeMerger struct {
	mu          sync.Mutex
	submissions []fakeMergerSubmission
}

type fakeMergerSubmission struct {
	matched  string
	incoming AddInput
}

func (f *fakeMerger) Submit(matched string, in AddInput) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.submissions = append(f.submissions, fakeMergerSubmission{matched, in})
}

func TestVerifierToolDefs(t *testing.T) {
	t.Parallel()

	fileFindingArgs := map[string]any{
		"title": "t", "severity": "high", "endpoint": "GET /",
		"description": "d", "reproduction_steps": "r",
		"evidence": "e", "impact": "i", "verification_notes": "v",
	}

	t.Run("rejects_before_phase_begin", func(t *testing.T) {
		dq := NewDecisionQueue()
		ff := findTool(VerifierToolDefs(dq), "file_finding")
		require.NotNil(t, ff)
		res := ff.Handler(t.Context(), mustMarshal(t, fileFindingArgs))
		assert.True(t, res.IsError)
		assert.Contains(t, strings.ToLower(res.Text), "phase")
	})

	t.Run("accepts_in_verification_phase", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseVerification)
		ff := findTool(VerifierToolDefs(dq), "file_finding")
		require.NotNil(t, ff)
		res := ff.Handler(t.Context(), mustMarshal(t, fileFindingArgs))
		assert.False(t, res.IsError, res.Text)
		assert.Len(t, dq.Findings, 1)
	})

	t.Run("dismiss_candidate", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseVerification)
		dc := findTool(VerifierToolDefs(dq), "dismiss_candidate")
		require.NotNil(t, dc)
		res := dc.Handler(t.Context(), mustMarshal(t, map[string]any{"candidate_id": "c1", "reason": "noise"}))
		assert.False(t, res.IsError)
		require.Len(t, dq.Dismissals, 1)
	})

	t.Run("dismiss_rejects_empty_id", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseVerification)
		dc := findTool(VerifierToolDefs(dq), "dismiss_candidate")
		require.NotNil(t, dc)
		res := dc.Handler(t.Context(), mustMarshal(t, map[string]any{"candidate_id": "", "reason": "x"}))
		assert.True(t, res.IsError)
	})

	t.Run("verification_done", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseVerification)
		vd := findTool(VerifierToolDefs(dq), "verification_done")
		require.NotNil(t, vd)
		res := vd.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "done verifying"}))
		assert.False(t, res.IsError)
		assert.True(t, dq.HasVerificationDone)
	})
}

func TestDecisionToolDefs(t *testing.T) {
	t.Parallel()

	noTaken := func() map[int]bool { return nil }

	t.Run("continue_clamps_budget", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dq.BeginPerWorkerDecision(2)
		dw := findTool(DecisionToolDefs(dq, noTaken, nil), "decide_worker")
		require.NotNil(t, dw)
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 2, "action": "continue", "instruction": "keep going",
			"autonomous_budget": 999,
		}))
		require.False(t, res.IsError, res.Text)
		require.Len(t, dq.WorkerDecisions, 1)
		assert.Equal(t, "continue", dq.WorkerDecisions[0].Kind)
		assert.Equal(t, 20, dq.WorkerDecisions[0].AutonomousBudget)
	})

	t.Run("rejects_id_mismatch", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dq.BeginPerWorkerDecision(5)
		log, path := newTestLogger(t)
		dw := findTool(DecisionToolDefs(dq, noTaken, log), "decide_worker")
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 7, "action": "continue", "instruction": "x",
		}))
		require.True(t, res.IsError)
		assert.Contains(t, res.Text, "Rejected: this prompt asked about worker 5")
		assert.Contains(t, res.Text, "worker_id=7")
		assert.Contains(t, res.Text, "Re-issue with worker_id=5")
		assert.Empty(t, dq.WorkerDecisions)
		require.NoError(t, log.Close())
		content := mustReadFile(t, path)
		assert.Contains(t, content, `"tag":"decision"`)
		assert.Contains(t, content, `"msg":"worker-id-mismatch"`)
		assert.Contains(t, content, `"asked":5`)
		assert.Contains(t, content, `"received":7`)
	})

	t.Run("expand_requires_instruction", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dw := findTool(DecisionToolDefs(dq, noTaken, nil), "decide_worker")
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 1, "action": "expand", "instruction": "  ",
		}))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "instruction is required")
	})

	t.Run("continue_defaults_when_instruction_missing", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dw := findTool(DecisionToolDefs(dq, noTaken, nil), "decide_worker")
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 1, "action": "continue",
		}))
		require.False(t, res.IsError, res.Text)
		require.Len(t, dq.WorkerDecisions, 1)
		assert.Equal(t, "continue", dq.WorkerDecisions[0].Kind)
		assert.Equal(t, prompts.DefaultContinueDirective, dq.WorkerDecisions[0].Instruction)
	})

	t.Run("continue_preserves_supplied_instruction", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dw := findTool(DecisionToolDefs(dq, noTaken, nil), "decide_worker")
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 1, "action": "continue", "instruction": "press the SSRF angle on the federation endpoint",
		}))
		require.False(t, res.IsError, res.Text)
		require.Len(t, dq.WorkerDecisions, 1)
		assert.Equal(t, "press the SSRF angle on the federation endpoint", dq.WorkerDecisions[0].Instruction)
	})

	t.Run("stop_requires_reason", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dw := findTool(DecisionToolDefs(dq, noTaken, nil), "decide_worker")
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 1, "action": "stop",
		}))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "reason is required")
	})

	t.Run("fork_rejects_taken_id", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		taken := func() map[int]bool { return map[int]bool{1: true, 2: true, 9: true} }
		dw := findTool(DecisionToolDefs(dq, taken, nil), "decide_worker")
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 1, "action": "expand", "instruction": "pivot",
			"fork": map[string]any{"new_worker_id": 9, "instruction": "child"},
		}))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "collides with an existing or retired worker")
	})

	t.Run("fork_records_fresh_id", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		taken := func() map[int]bool { return map[int]bool{1: true} }
		dw := findTool(DecisionToolDefs(dq, taken, nil), "decide_worker")
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 1, "action": "expand", "instruction": "pivot",
			"fork": map[string]any{"new_worker_id": 5, "instruction": "child probes /admin"},
		}))
		require.False(t, res.IsError, res.Text)
		require.Len(t, dq.WorkerDecisions, 1)
		require.NotNil(t, dq.WorkerDecisions[0].Fork)
		assert.Equal(t, 5, dq.WorkerDecisions[0].Fork.NewWorkerID)
	})

	t.Run("fork_rejects_parent_id", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dw := findTool(DecisionToolDefs(dq, noTaken, nil), "decide_worker")
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 3, "action": "expand", "instruction": "pivot",
			"fork": map[string]any{"new_worker_id": 3, "instruction": "child"},
		}))
		assert.True(t, res.IsError)
	})

	t.Run("phase_mismatch_rejects", func(t *testing.T) {
		dq := NewDecisionQueue()
		dw := findTool(DecisionToolDefs(dq, noTaken, nil), "decide_worker")
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 1, "action": "continue", "instruction": "x",
		}))
		assert.True(t, res.IsError)
	})

	t.Run("unknown_action_rejected", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dw := findTool(DecisionToolDefs(dq, noTaken, nil), "decide_worker")
		res := dw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"worker_id": 1, "action": "destroy",
		}))
		assert.True(t, res.IsError)
	})
}

func TestSynthesisToolDefs(t *testing.T) {
	t.Parallel()

	// guardAccept is a guardState closure that always permits end_run. Used by
	// director-tool tests that aren't exercising the premature-end_run path.
	guardAccept := func() (int, int) { return minIterationsForDone, 0 }

	// guardPremature is a guardState closure that always produces a rejection
	// from the end_run handler (iter below threshold, zero findings this run).
	guardPremature := func() (int, int) { return 1, 0 }

	noTaken := func() map[int]bool { return nil }
	noCompleted := func() map[int]bool { return nil }

	t.Run("plan_records_valid", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(SynthesisToolDefs(dq, guardAccept, noTaken, noCompleted, nil), "plan_workers")
		require.NotNil(t, pw)
		res := pw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"plans": []map[string]any{
				{"worker_id": 1, "assignment": "scan auth"},
				{"worker_id": 0, "assignment": "invalid"},
				{"worker_id": 2, "assignment": "   "},
				{"worker_id": 3, "assignment": "scan admin"},
			},
		}))
		assert.False(t, res.IsError)
		require.Len(t, dq.Plan, 2)
		assert.Equal(t, 1, dq.Plan[0].WorkerID)
		assert.Equal(t, 3, dq.Plan[1].WorkerID)
		assert.Contains(t, res.Text, "plans[1]")
		assert.Contains(t, res.Text, "plans[2]")
	})

	t.Run("plan_rejects_completed_id", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		taken := func() map[int]bool { return map[int]bool{4: true} }
		done := func() map[int]bool { return map[int]bool{4: true} }
		pw := findTool(SynthesisToolDefs(dq, guardAccept, taken, done, nil), "plan_workers")
		res := pw.Handler(t.Context(), mustMarshal(t, map[string]any{
			"plans": []map[string]any{{"worker_id": 4, "assignment": "x"}},
		}))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "retired worker")
	})

	t.Run("plan_recovers_string_array", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		pw := findTool(SynthesisToolDefs(dq, guardAccept, noTaken, noCompleted, nil), "plan_workers")
		res := pw.Handler(t.Context(), json.RawMessage(
			`{"plans": "[{\"worker_id\":1,\"assignment\":\"scan auth\"}]"}`,
		))
		assert.False(t, res.IsError)
		require.Len(t, dq.Plan, 1)
		assert.Equal(t, "scan auth", dq.Plan[0].Assignment)
	})

	t.Run("direction_done_records", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dd := findTool(SynthesisToolDefs(dq, guardAccept, noTaken, noCompleted, nil), "direction_done")
		res := dd.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "ok"}))
		assert.False(t, res.IsError)
		assert.True(t, dq.HasDirectionDone)
	})

	t.Run("end_run_premature_rejected", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		er := findTool(SynthesisToolDefs(dq, guardPremature, noTaken, noCompleted, nil), "end_run")
		res := er.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "s"}))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "premature")
	})

	t.Run("end_run_accepted", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		er := findTool(SynthesisToolDefs(dq, guardAccept, noTaken, noCompleted, nil), "end_run")
		res := er.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "s"}))
		assert.False(t, res.IsError)
		assert.True(t, dq.HasEndRun)
	})

	t.Run("phase_mismatch_rejects", func(t *testing.T) {
		dq := NewDecisionQueue()
		defs := SynthesisToolDefs(dq, guardAccept, noTaken, noCompleted, nil)
		for _, name := range []string{"plan_workers", "direction_done", "end_run"} {
			d := findTool(defs, name)
			require.NotNil(t, d, name)
			res := d.Handler(t.Context(), []byte(`{}`))
			assert.True(t, res.IsError, name)
		}
	})

	t.Run("end_run_rejects_when_alive_workers_have_non_stop_decisions", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dq.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 4})
		dq.AddDecision(WorkerDecision{Kind: "stop", WorkerID: 5, Reason: "exhausted"})
		alive := func() []int { return []int{4, 5} }
		er := findTool(SynthesisToolDefs(dq, guardAccept, noTaken, noCompleted, alive), "end_run")
		res := er.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "s"}))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "[4]")
		assert.NotContains(t, res.Text, "[5]")
		assert.False(t, dq.HasEndRun)
	})

	t.Run("end_run_rejects_when_alive_worker_has_no_decision", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dq.AddDecision(WorkerDecision{Kind: "stop", WorkerID: 4, Reason: "x"})
		alive := func() []int { return []int{4, 5} }
		er := findTool(SynthesisToolDefs(dq, guardAccept, noTaken, noCompleted, alive), "end_run")
		res := er.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "s"}))
		assert.True(t, res.IsError)
		assert.Contains(t, res.Text, "[5]")
		assert.False(t, dq.HasEndRun)
	})

	t.Run("end_run_accepted_when_all_alive_stopped", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		dq.AddDecision(WorkerDecision{Kind: "stop", WorkerID: 4, Reason: "x"})
		dq.AddDecision(WorkerDecision{Kind: "stop", WorkerID: 5, Reason: "y"})
		alive := func() []int { return []int{4, 5} }
		er := findTool(SynthesisToolDefs(dq, guardAccept, noTaken, noCompleted, alive), "end_run")
		res := er.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "s"}))
		assert.False(t, res.IsError)
		assert.True(t, dq.HasEndRun)
	})

	t.Run("end_run_accepted_when_no_alive_workers", func(t *testing.T) {
		dq := NewDecisionQueue()
		dq.BeginPhase(agent.PhaseDirection)
		alive := func() []int { return nil }
		er := findTool(SynthesisToolDefs(dq, guardAccept, noTaken, noCompleted, alive), "end_run")
		res := er.Handler(t.Context(), mustMarshal(t, map[string]any{"summary": "s"}))
		assert.False(t, res.IsError)
		assert.True(t, dq.HasEndRun)
	})
}
