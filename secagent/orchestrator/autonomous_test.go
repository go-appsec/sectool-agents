package orchestrator

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
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
		runs, err := RunWorkerUntilEscalation(t.Context(), w, pool, log)
		require.NoError(t, err)
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
		runs, err := RunWorkerUntilEscalation(t.Context(), w, NewCandidatePool(), log)
		require.NoError(t, err)
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
		runs, err := RunWorkerUntilEscalation(t.Context(), w, pool, log)
		require.NoError(t, err)
		assert.Len(t, runs, 2)
		assert.Equal(t, "candidate", w.EscalationReason)
	})
}

func TestUpdateToolErrorSignatures(t *testing.T) {
	t.Parallel()

	t.Run("error_tool_calls_recorded", func(t *testing.T) {
		w := &WorkerState{}
		updateToolErrorSignatures(w, agent.TurnSummary{
			ToolCalls: []agent.ToolCallRecord{
				{Name: "x", IsError: true, ResultSummary: "e1"},
				{Name: "y", IsError: true, ResultSummary: "e2"},
			},
		})
		assert.Equal(t, []string{"e1", "e2"}, w.RecentToolErrors)
	})

	t.Run("success_clears_coached_sig", func(t *testing.T) {
		w := &WorkerState{CoachedErrorSig: "prev"}
		updateToolErrorSignatures(w, agent.TurnSummary{
			ToolCalls: []agent.ToolCallRecord{
				{Name: "ok", IsError: false, ResultSummary: "done"},
			},
		})
		assert.Empty(t, w.CoachedErrorSig)
	})

	t.Run("window_capped_to_max", func(t *testing.T) {
		w := &WorkerState{}
		// Populate 7 errors; only the last 5 should survive
		calls := make([]agent.ToolCallRecord, 7)
		for i := range calls {
			calls[i] = agent.ToolCallRecord{IsError: true, ResultSummary: string(rune('A' + i))}
		}
		updateToolErrorSignatures(w, agent.TurnSummary{ToolCalls: calls})
		assert.Len(t, w.RecentToolErrors, MaxRecentToolErrors)
		assert.Equal(t, []string{"C", "D", "E", "F", "G"}, w.RecentToolErrors)
	})

	t.Run("signature_truncated_to_prefix", func(t *testing.T) {
		long := strings.Repeat("x", ErrorSignatureMaxLen*2)
		w := &WorkerState{}
		updateToolErrorSignatures(w, agent.TurnSummary{
			ToolCalls: []agent.ToolCallRecord{{IsError: true, ResultSummary: long}},
		})
		require.Len(t, w.RecentToolErrors, 1)
		assert.Len(t, w.RecentToolErrors[0], ErrorSignatureMaxLen)
	})
}
