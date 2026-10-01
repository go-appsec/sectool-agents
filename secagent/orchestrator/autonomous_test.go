package orchestrator

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/sectool-agents/secagent/agent"
)

func TestRunWorkerUntilEscalation(t *testing.T) {
	t.Parallel()

	t.Run("budget_exhausted_escalation", func(t *testing.T) {
		fake := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
			},
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 3}
		pool := NewCandidatePool()
		log, _ := newTestLogger(t)
		rs := newWorkerRunResult(w)
		runs, err := RunWorkerUntilEscalation(t.Context(), w, &rs, pool, log)
		require.NoError(t, err)
		w.ApplyRunResult(rs)
		assert.Len(t, runs, 3)
		assert.Equal(t, "budget", w.EscalationReason)
	})

	t.Run("silent_turn_escalation", func(t *testing.T) {
		fake := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
				{AssistantText: "nothing more"},
			},
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 5}
		log, _ := newTestLogger(t)
		rs := newWorkerRunResult(w)
		runs, err := RunWorkerUntilEscalation(t.Context(), w, &rs, NewCandidatePool(), log)
		require.NoError(t, err)
		w.ApplyRunResult(rs)
		assert.Len(t, runs, 2)
		assert.Equal(t, "silent", w.EscalationReason)
	})

	t.Run("candidate_reported_escalation", func(t *testing.T) {
		pool := NewCandidatePool()
		fake := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
				{ToolCalls: []agent.ToolCallRecord{{Name: "report_finding_candidate"}}},
			},
		}
		// turnIdx 0 fires after the first Drain; pool must hold candidate
		// before the 2nd turn's report_finding_candidate is classified
		fake.OnDrain = func(turnIdx int) {
			if turnIdx == 0 {
				pool.Add(AddInput{WorkerID: 1, Title: "x", Severity: "low", FlowIDs: []string{"abc123"}})
			}
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 5}
		log, _ := newTestLogger(t)
		rs := newWorkerRunResult(w)
		runs, err := RunWorkerUntilEscalation(t.Context(), w, &rs, pool, log)
		require.NoError(t, err)
		w.ApplyRunResult(rs)
		assert.Len(t, runs, 2)
		assert.Equal(t, "candidate", w.EscalationReason)
	})
}

func TestUpdateToolErrorSignatures(t *testing.T) {
	t.Parallel()

	t.Run("error_tool_calls_recorded", func(t *testing.T) {
		rs := &workerRunResult{}
		updateToolErrorSignatures(rs, agent.TurnSummary{
			ToolCalls: []agent.ToolCallRecord{
				{Name: "x", IsError: true, ResultSummary: "e1"},
				{Name: "y", IsError: true, ResultSummary: "e2"},
			},
		})
		assert.Equal(t, []string{"e1", "e2"}, rs.RecentToolErrors)
	})

	t.Run("success_clears_coached_sig", func(t *testing.T) {
		rs := &workerRunResult{CoachedErrorSig: "prev"}
		updateToolErrorSignatures(rs, agent.TurnSummary{
			ToolCalls: []agent.ToolCallRecord{
				{Name: "ok", IsError: false, ResultSummary: "done"},
			},
		})
		assert.Empty(t, rs.CoachedErrorSig)
	})

	t.Run("window_capped_to_max", func(t *testing.T) {
		rs := &workerRunResult{}
		// Populate 7 errors; only the last 5 should survive
		calls := make([]agent.ToolCallRecord, 7)
		for i := range calls {
			calls[i] = agent.ToolCallRecord{IsError: true, ResultSummary: string(rune('A' + i))}
		}
		updateToolErrorSignatures(rs, agent.TurnSummary{ToolCalls: calls})
		assert.Len(t, rs.RecentToolErrors, MaxRecentToolErrors)
		assert.Equal(t, []string{"C", "D", "E", "F", "G"}, rs.RecentToolErrors)
	})

	t.Run("signature_truncated_to_prefix", func(t *testing.T) {
		long := strings.Repeat("x", ErrorSignatureMaxLen*2)
		rs := &workerRunResult{}
		updateToolErrorSignatures(rs, agent.TurnSummary{
			ToolCalls: []agent.ToolCallRecord{{IsError: true, ResultSummary: long}},
		})
		require.Len(t, rs.RecentToolErrors, 1)
		assert.Len(t, rs.RecentToolErrors[0], ErrorSignatureMaxLen)
	})
}
