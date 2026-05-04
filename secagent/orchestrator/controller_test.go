package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestIsDeadIteration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		runs        map[int][]agent.TurnSummary
		candsBefore int
		candsAfter  int
		wantDead    bool
	}{
		{
			name:        "all_empty_no_new_candidates",
			runs:        map[int][]agent.TurnSummary{1: {{}, {}}, 2: {{}}},
			candsBefore: 0,
			candsAfter:  0,
			wantDead:    true,
		},
		{
			name:        "any_tool_call_not_dead",
			runs:        map[int][]agent.TurnSummary{1: {{ToolCalls: []agent.ToolCallRecord{{Name: "x"}}}}},
			candsBefore: 0,
			candsAfter:  0,
			wantDead:    false,
		},
		{
			name:        "new_candidate_not_dead",
			runs:        map[int][]agent.TurnSummary{1: {{}}},
			candsBefore: 0,
			candsAfter:  1,
			wantDead:    false,
		},
		{
			name:        "empty_runs_map_is_dead",
			runs:        map[int][]agent.TurnSummary{},
			candsBefore: 5,
			candsAfter:  5,
			wantDead:    true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.wantDead, isDeadIteration(c.runs, c.candsBefore, c.candsAfter))
		})
	}
}

func TestWorkerStateClose(t *testing.T) {
	t.Parallel()

	t.Run("closes_underlying_agent", func(t *testing.T) {
		a := &agent.FakeAgent{}
		w := &WorkerState{ID: 1, Agent: a}
		w.Close()
		assert.True(t, a.Closed)
	})

	t.Run("nil_safe", func(t *testing.T) {
		require.NotPanics(t, func() {
			(*WorkerState)(nil).Close()
			(&WorkerState{}).Close()
		})
	})
}

func TestRunWorkerUntilEscalationBudget(t *testing.T) {
	t.Parallel()

	t.Run("budget_exhausted", func(t *testing.T) {
		a := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{ToolCalls: []agent.ToolCallRecord{{Name: "x"}}},
			{ToolCalls: []agent.ToolCallRecord{{Name: "y"}}},
		}}
		w := &WorkerState{ID: 1, Alive: true, Agent: a, AutonomousBudget: 2, LastInstruction: "go"}
		log, _ := newTestLogger(t)
		runs, err := RunWorkerUntilEscalation(t.Context(), w, NewCandidatePool(), log)
		require.NoError(t, err)
		assert.Len(t, runs, 2)
		assert.Equal(t, "budget", w.EscalationReason)
		require.Len(t, a.QueriedInputs, 1)
		assert.Contains(t, a.QueriedInputs[0], "Continue")
	})

	t.Run("clamps_zero_to_one", func(t *testing.T) {
		a := &agent.FakeAgent{Turns: []agent.TurnSummary{{ToolCalls: []agent.ToolCallRecord{{Name: "x"}}}}}
		w := &WorkerState{ID: 1, Alive: true, Agent: a, AutonomousBudget: 0}
		log, _ := newTestLogger(t)
		runs, err := RunWorkerUntilEscalation(t.Context(), w, NewCandidatePool(), log)
		require.NoError(t, err)
		assert.Len(t, runs, 1)
	})
}
