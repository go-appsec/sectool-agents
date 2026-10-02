package orchestrator

import (
	"errors"
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

	t.Run("interrupted_run_no_error_escalation", func(t *testing.T) {
		fake := &agent.FakeAgent{
			Turns:  []agent.TurnSummary{{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}}},
			Errors: []error{agent.ErrDrainInterrupted},
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 5}
		log, _ := newTestLogger(t)
		rs := newWorkerRunResult(w)
		_, err := RunWorkerUntilEscalation(t.Context(), w, &rs, NewCandidatePool(), log)
		require.ErrorIs(t, err, agent.ErrDrainInterrupted)
		assert.Empty(t, rs.EscalationReason)
	})

	t.Run("context_exhausted_survives_candidate", func(t *testing.T) {
		pool := NewCandidatePool()
		fake := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{
					EscalationReason: "context_exhausted",
					ToolCalls:        []agent.ToolCallRecord{{Name: "report_finding_candidate"}},
				},
			},
		}
		fake.OnDrain = func(int) {
			pool.Add(AddInput{WorkerID: 1, Title: "x", Severity: "low", FlowIDs: []string{"abc123"}})
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 5}
		log, _ := newTestLogger(t)
		rs := newWorkerRunResult(w)
		_, err := RunWorkerUntilEscalation(t.Context(), w, &rs, pool, log)
		require.NoError(t, err)
		w.ApplyRunResult(rs)
		assert.Equal(t, "context_exhausted", w.EscalationReason)
	})
}

func TestRunOneWorkerRecovery(t *testing.T) {
	t.Parallel()

	t.Run("recovered_error_not_error", func(t *testing.T) {
		fake := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
			},
			Errors: []error{errors.New("drain failed")},
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 5, LastInstruction: "continue"}
		log, _ := newTestLogger(t)
		rs := newWorkerRunResult(w)
		res := runOneWorker(t.Context(), w, rs, NewCandidatePool(), log)
		assert.Empty(t, res.EscalationReason)
	})

	t.Run("interrupted_run_skips_recovery", func(t *testing.T) {
		fake := &agent.FakeAgent{
			Turns:  []agent.TurnSummary{{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}}},
			Errors: []error{agent.ErrDrainInterrupted},
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 5, LastInstruction: "continue"}
		log, _ := newTestLogger(t)
		rs := newWorkerRunResult(w)
		res := runOneWorker(t.Context(), w, rs, NewCandidatePool(), log)
		assert.Empty(t, res.EscalationReason)
		// the recovery re-Query never ran; the refire owns fresh state
		assert.Empty(t, fake.QueriedInputs)
	})

	t.Run("unrecovered_error_stays_error", func(t *testing.T) {
		fake := &agent.FakeAgent{
			Turns: []agent.TurnSummary{
				{ToolCalls: []agent.ToolCallRecord{{Name: "t"}}},
			},
			Errors: []error{errors.New("drain failed"), errors.New("still failing")},
		}
		w := &WorkerState{ID: 1, Agent: fake, Alive: true, AutonomousBudget: 5, LastInstruction: "continue"}
		log, _ := newTestLogger(t)
		rs := newWorkerRunResult(w)
		res := runOneWorker(t.Context(), w, rs, NewCandidatePool(), log)
		assert.Equal(t, EscalationError, res.EscalationReason)
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

	t.Run("success_keeps_coached_sig", func(t *testing.T) {
		rs := &workerRunResult{CoachedErrorSig: "e1", RecentToolErrors: []string{"e1", "e1"}}
		updateToolErrorSignatures(rs, agent.TurnSummary{
			ToolCalls: []agent.ToolCallRecord{
				{Name: "ok", IsError: false, ResultSummary: "done"},
			},
		})
		assert.Equal(t, "e1", rs.CoachedErrorSig)
	})

	t.Run("clean_turn_decays_window", func(t *testing.T) {
		rs := &workerRunResult{RecentToolErrors: []string{"a", "b", "c"}}
		updateToolErrorSignatures(rs, agent.TurnSummary{
			ToolCalls: []agent.ToolCallRecord{{Name: "ok", IsError: false}},
		})
		assert.Equal(t, []string{"b", "c"}, rs.RecentToolErrors)
	})

	t.Run("error_turn_no_decay", func(t *testing.T) {
		rs := &workerRunResult{RecentToolErrors: []string{"a", "b"}}
		updateToolErrorSignatures(rs, agent.TurnSummary{
			ToolCalls: []agent.ToolCallRecord{{Name: "x", IsError: true, ResultSummary: "c"}},
		})
		assert.Equal(t, []string{"a", "b", "c"}, rs.RecentToolErrors)
	})

	t.Run("coached_sig_clears_when_decayed_out", func(t *testing.T) {
		rs := &workerRunResult{CoachedErrorSig: "a", RecentToolErrors: []string{"a"}}
		updateToolErrorSignatures(rs, agent.TurnSummary{
			ToolCalls: []agent.ToolCallRecord{{Name: "ok", IsError: false}},
		})
		assert.Empty(t, rs.RecentToolErrors)
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
