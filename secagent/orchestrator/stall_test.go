package orchestrator

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestUpdateStallStreaks(t *testing.T) {
	t.Parallel()

	t.Run("escalation_reason_streaks", func(t *testing.T) {
		flowsTurn := []agent.TurnSummary{{FlowIDs: []string{"abc123"}}}
		cases := []struct {
			name          string
			initial       *WorkerState
			wantStreak    int
			wantStallWarn bool
		}{
			{
				name:       "silent_increments_from_zero",
				initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "silent"},
				wantStreak: 1,
			},
			{
				name:       "silent_increments_further",
				initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "silent", ProgressNoneStreak: 1},
				wantStreak: 2,
			},
			{
				// Hard errors (HTTP 400, crashed drain) feed the same threshold
				// as silent so consistently-crashing workers die naturally
				name:       "error_increments_like_silent",
				initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "error", ProgressNoneStreak: 2},
				wantStreak: 3,
			},
			{
				name:       "candidate_resets_streak_and_warn",
				initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "candidate", ProgressNoneStreak: 2, StallWarned: true},
				wantStreak: 0,
			},
			{
				// silent always increments before flow-reset check (else-if ordering)
				name:       "silent_wins_over_flows",
				initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "silent", AutonomousTurns: flowsTurn},
				wantStreak: 1,
			},
			{
				name:       "flows_reset_without_silent_or_error",
				initial:    &WorkerState{ID: 1, Alive: true, EscalationReason: "budget", AutonomousTurns: flowsTurn, ProgressNoneStreak: 2, StallWarned: true},
				wantStreak: 0,
			},
			{
				name:          "dead_worker_untouched",
				initial:       &WorkerState{ID: 1, Alive: false, EscalationReason: "silent", ProgressNoneStreak: 4, StallWarned: true},
				wantStreak:    4,
				wantStallWarn: true,
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				UpdateStallStreaks([]*WorkerState{c.initial})
				assert.Equal(t, c.wantStreak, c.initial.ProgressNoneStreak)
				assert.Equal(t, c.wantStallWarn, c.initial.StallWarned)
			})
		}
	})

	t.Run("repeated_tool_errors", func(t *testing.T) {
		cases := []struct {
			name          string
			initialStreak int
			reason        string
			errors        []string
			wantStreak    int
		}{
			{"threshold_increments_streak", 0, "budget", []string{"e", "e", "e"}, 1},
			{"below_threshold_noop", 0, "budget", []string{"e", "e"}, 0},
			{"candidate_wins_over_errors", 2, "candidate", []string{"e", "e", "e"}, 0},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				w := &WorkerState{
					ID: 1, Alive: true,
					EscalationReason:   c.reason,
					ProgressNoneStreak: c.initialStreak,
					RecentToolErrors:   c.errors,
					Agent:              &agent.FakeAgent{},
				}
				UpdateStallStreaks([]*WorkerState{w})
				assert.Equal(t, c.wantStreak, w.ProgressNoneStreak)
			})
		}
	})

	t.Run("coaching_same_sig_fires_once", func(t *testing.T) {
		fa := &agent.FakeAgent{}
		w := &WorkerState{
			ID: 1, Alive: true,
			EscalationReason: "budget",
			RecentToolErrors: []string{"same err", "same err", "same err"},
			Agent:            fa,
		}
		for range 3 {
			UpdateStallStreaks([]*WorkerState{w})
		}
		var coachings int
		for _, q := range fa.QueriedInputs {
			if strings.Contains(q, "same err") {
				coachings++
			}
		}
		assert.Equal(t, 1, coachings)
		assert.Equal(t, "same err", w.CoachedErrorSig)
	})

	t.Run("coaching_new_sig_fires_again", func(t *testing.T) {
		fa := &agent.FakeAgent{}
		w := &WorkerState{
			ID: 1, Alive: true,
			EscalationReason: "budget",
			RecentToolErrors: []string{"sig A", "sig A", "sig A"},
			Agent:            fa,
		}
		UpdateStallStreaks([]*WorkerState{w})
		w.RecentToolErrors = []string{"sig B", "sig B", "sig B"}
		UpdateStallStreaks([]*WorkerState{w})
		var coachings int
		for _, q := range fa.QueriedInputs {
			if strings.Contains(q, "sig ") {
				coachings++
			}
		}
		assert.Equal(t, 2, coachings)
	})
}

func TestHasProductiveTurn(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []agent.TurnSummary
		want bool
	}{
		{"empty_slice", nil, false},
		{"single_zero_turn", []agent.TurnSummary{{}}, false},
		{"tokens_alone_not_productive", []agent.TurnSummary{{TokensIn: 50}}, false},
		{"tool_call_is_productive", []agent.TurnSummary{{ToolCalls: []agent.ToolCallRecord{{Name: "x"}}}}, true},
		{"flow_id_is_productive", []agent.TurnSummary{{FlowIDs: []string{"f1"}}}, true},
		{"mixed_with_tool_call", []agent.TurnSummary{{}, {ToolCalls: []agent.ToolCallRecord{{Name: "x"}}}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, hasProductiveTurn(c.in))
		})
	}
}

func TestFormatStallWarnings(t *testing.T) {
	t.Parallel()

	t.Run("sorts_multiple_warnings_by_id", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 5, Alive: true, ProgressNoneStreak: 4},
			{ID: 2, Alive: true, ProgressNoneStreak: 3},
			{ID: 1, Alive: true, ProgressNoneStreak: 1},
		}
		out := FormatStallWarnings(workers, 3)
		w2Idx := strings.Index(out, "Worker 2")
		w5Idx := strings.Index(out, "Worker 5")
		assert.NotEqual(t, -1, w2Idx)
		assert.Less(t, w2Idx, w5Idx)
		assert.NotContains(t, out, "Worker 1")
	})

	cases := []struct {
		name   string
		worker *WorkerState
		after  int
		want   string
	}{
		{
			"warns_when_streak_met",
			&WorkerState{ID: 2, Alive: true, ProgressNoneStreak: 3},
			3, "Worker 2",
		},
		{
			"suppresses_when_latched",
			&WorkerState{ID: 2, Alive: true, ProgressNoneStreak: 3, StallWarned: true},
			3, "",
		},
		{
			"skips_dead_worker",
			&WorkerState{ID: 2, Alive: false, ProgressNoneStreak: 5},
			3, "",
		},
		{
			"below_threshold_empty",
			&WorkerState{ID: 2, Alive: true, ProgressNoneStreak: 2},
			3, "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := FormatStallWarnings([]*WorkerState{c.worker}, c.after)
			if c.want == "" {
				assert.Empty(t, out)
			} else {
				assert.Contains(t, out, c.want)
			}
		})
	}
}

func TestLatchStallWarnings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		worker *WorkerState
		after  int
		want   bool
	}{
		{"above_threshold_latches", &WorkerState{ID: 1, Alive: true, ProgressNoneStreak: 3}, 3, true},
		{"below_threshold_no_latch", &WorkerState{ID: 1, Alive: true, ProgressNoneStreak: 2}, 3, false},
		{"dead_worker_no_latch", &WorkerState{ID: 1, Alive: false, ProgressNoneStreak: 5}, 3, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			LatchStallWarnings([]*WorkerState{c.worker}, c.after)
			assert.Equal(t, c.want, c.worker.StallWarned)
		})
	}
}
