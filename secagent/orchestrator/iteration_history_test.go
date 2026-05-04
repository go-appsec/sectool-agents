package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

// seedCandidate adds a candidate for workerID and returns its id.
func seedCandidate(pool *CandidatePool, workerID int, title, endpoint string) string {
	return pool.Add(AddInput{
		WorkerID: workerID,
		Title:    title,
		Endpoint: endpoint,
		FlowIDs:  []string{"f1"},
	})
}

func TestDeriveIterationOutcome(t *testing.T) {
	t.Parallel()

	type setup struct {
		worker       *WorkerState
		populate     func(pool *CandidatePool, dq *DecisionQueue) []string
		expectedKind IterationOutcome
	}

	tests := []struct {
		name string
		setup
	}{
		{
			name: "stopped_worker_dead",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: false, EscalationReason: "silent"},
				populate: func(_ *CandidatePool, _ *DecisionQueue) []string {
					return nil
				},
				expectedKind: OutcomeStopped,
			},
		},
		{
			name: "finding_via_supersedes",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true},
				populate: func(pool *CandidatePool, dq *DecisionQueue) []string {
					cid := seedCandidate(pool, 1, "XSS", "GET /x")
					dq.AddFinding(FindingFiled{
						Title:                  "XSS",
						Endpoint:               "GET /x",
						SupersedesCandidateIDs: []string{cid},
					})
					return []string{cid}
				},
				expectedKind: OutcomeFinding,
			},
		},
		{
			name: "possible_finding_via_tiered_match",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true},
				populate: func(pool *CandidatePool, dq *DecisionQueue) []string {
					cid := seedCandidate(pool, 1, "Reflected XSS in search", "GET /search")
					dq.AddFinding(FindingFiled{
						Title:    "Reflected XSS in search",
						Endpoint: "GET /search",
					})
					return []string{cid}
				},
				expectedKind: OutcomePossibleFinding,
			},
		},
		{
			name: "explicit_finding_beats_tier_match",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true},
				populate: func(pool *CandidatePool, dq *DecisionQueue) []string {
					explicit := seedCandidate(pool, 1, "Auth bypass on /admin", "GET /admin")
					tierOnly := seedCandidate(pool, 1, "Reflected XSS in search", "GET /search")
					dq.AddFinding(FindingFiled{
						Title:                  "Auth bypass on /admin",
						Endpoint:               "GET /admin",
						SupersedesCandidateIDs: []string{explicit},
					})
					dq.AddFinding(FindingFiled{
						Title:    "Reflected XSS in search",
						Endpoint: "GET /search",
					})
					return []string{explicit, tierOnly}
				},
				expectedKind: OutcomeFinding,
			},
		},
		{
			name: "candidate_dismissed",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true},
				populate: func(pool *CandidatePool, dq *DecisionQueue) []string {
					cid := seedCandidate(pool, 1, "x", "GET /x")
					dq.AddDismissal(CandidateDismissal{CandidateID: cid, Reason: "noise"})
					return []string{cid}
				},
				expectedKind: OutcomeDismissed,
			},
		},
		{
			name: "candidate_still_pending",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true},
				populate: func(pool *CandidatePool, _ *DecisionQueue) []string {
					cid := seedCandidate(pool, 1, "x", "GET /x")
					c := pool.ByID(cid)
					require.NotNil(t, c)
					require.Equal(t, "pending", c.Status)
					return []string{cid}
				},
				expectedKind: OutcomeCandidate,
			},
		},
		{
			name: "silent_escalation",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true, EscalationReason: "silent"},
				populate: func(_ *CandidatePool, _ *DecisionQueue) []string {
					return nil
				},
				expectedKind: OutcomeSilent,
			},
		},
		{
			name: "error_escalation",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true, EscalationReason: "error"},
				populate: func(_ *CandidatePool, _ *DecisionQueue) []string {
					return nil
				},
				expectedKind: OutcomeError,
			},
		},
		{
			name: "budget_escalation",
			setup: setup{
				worker: &WorkerState{ID: 1, Alive: true, EscalationReason: "budget"},
				populate: func(_ *CandidatePool, _ *DecisionQueue) []string {
					return nil
				},
				expectedKind: OutcomeBudget,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pool := NewCandidatePool()
			dq := NewDecisionQueue()
			cids := tc.populate(pool, dq)
			out := DeriveIterationOutcome(tc.worker, dq, pool, cids)
			assert.Equal(t, tc.expectedKind, out)
		})
	}
}

func TestAppendIterationHistory(t *testing.T) {
	t.Parallel()

	t.Run("skips_workers_not_alive_at_start", func(t *testing.T) {
		w1 := &WorkerState{ID: 1, Alive: true}
		w2 := &WorkerState{ID: 2, Alive: true}
		w3 := &WorkerState{ID: 3, Alive: true}
		alive := map[int]bool{1: true, 3: true}
		runs := map[int][]agent.TurnSummary{
			1: {{ToolCalls: []agent.ToolCallRecord{{Name: "a"}}}},
			2: {{ToolCalls: []agent.ToolCallRecord{{Name: "b"}}}},
			3: {{ToolCalls: []agent.ToolCallRecord{{Name: "c"}}}},
		}

		appendIterationHistory(
			[]*WorkerState{w1, w2, w3}, alive, nil, runs,
			NewDecisionQueue(), NewCandidatePool(), 0, 7,
		)

		assert.Equal(t, 1, w1.HistoryLen)
		assert.Equal(t, 0, w2.HistoryLen, "worker 2 was not in aliveAtStart")
		assert.Equal(t, 1, w3.HistoryLen)
		assert.Equal(t, 7, w1.RecentHistory()[0].Iteration)
	})

	t.Run("tool_call_and_flow_counts_summed", func(t *testing.T) {
		w := &WorkerState{ID: 1, Alive: true, EscalationReason: "silent"}
		runs := map[int][]agent.TurnSummary{
			1: {
				{
					ToolCalls: []agent.ToolCallRecord{{Name: "a"}, {Name: "b"}},
					FlowIDs:   []string{"f1", "f2"},
				},
				{
					ToolCalls: []agent.ToolCallRecord{{Name: "c"}},
					FlowIDs:   []string{"f3"},
				},
			},
		}

		appendIterationHistory(
			[]*WorkerState{w}, map[int]bool{1: true}, nil, runs,
			NewDecisionQueue(), NewCandidatePool(), 0, 1,
		)

		require.Equal(t, 1, w.HistoryLen)
		entry := w.RecentHistory()[0]
		assert.Equal(t, 3, entry.ToolCalls)
		assert.Equal(t, 3, entry.FlowsTouched)
	})
}
