package orchestrator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

// stubSpawn returns a workerSpawnFunc that produces a FakeAgent-backed worker and counts how many times it was invoked.
func stubSpawn(counter *int) workerSpawnFunc {
	return func(_ context.Context, id, _ int, assignment string) (*WorkerState, error) {
		*counter++
		return &WorkerState{
			ID:              id,
			Agent:           &agent.FakeAgent{},
			Alive:           true,
			LastInstruction: assignment,
		}, nil
	}
}

// stubFire returns a fire callback that records every fired worker id and yields nil turn summaries on join.
func stubFire(t *testing.T) (func(context.Context, *WorkerState) func() []agent.TurnSummary, *[]int) {
	t.Helper()
	fired := []int{}
	return func(_ context.Context, w *WorkerState) func() []agent.TurnSummary {
		fired = append(fired, w.ID)
		return func() []agent.TurnSummary { return nil }
	}, &fired
}

func TestApplyPlanAndFire(t *testing.T) {
	t.Parallel()

	t.Run("spawn_and_fire", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 1, Agent: &agent.FakeAgent{}, Alive: true, LastInstruction: "old1"},
		}
		var built int
		fire, fired := stubFire(t)
		inflight := map[int]func() []agent.TurnSummary{}
		applyPlanAndFire(t.Context(),
			[]PlanEntry{{WorkerID: 1, Assignment: "new plan"}, {WorkerID: 2, Assignment: "second"}},
			&workers, stubSpawn(&built), 5, fire, inflight, nil,
		)
		require.Len(t, workers, 2)
		assert.Equal(t, "new plan", workers[0].LastInstruction)
		assert.Equal(t, 2, workers[1].ID)
		assert.Equal(t, 1, built)
		assert.ElementsMatch(t, []int{1, 2}, *fired)
		assert.Len(t, inflight, 2)
	})

	t.Run("retarget_preserves_streak", func(t *testing.T) {
		w := &WorkerState{
			ID:                 1,
			Agent:              &agent.FakeAgent{},
			Alive:              true,
			ProgressNoneStreak: 3,
			StallWarned:        true,
			AutonomousTurns:    []agent.TurnSummary{{}, {}},
		}
		workers := []*WorkerState{w}
		var built int
		fire, _ := stubFire(t)
		applyPlanAndFire(t.Context(),
			[]PlanEntry{{WorkerID: 1, Assignment: "try something new"}},
			&workers, stubSpawn(&built), 5, fire,
			map[int]func() []agent.TurnSummary{}, nil,
		)
		assert.Equal(t, 3, w.ProgressNoneStreak)
		assert.True(t, w.StallWarned)
	})

	t.Run("retarget_resets_when_productive", func(t *testing.T) {
		w := &WorkerState{
			ID:                 1,
			Agent:              &agent.FakeAgent{},
			Alive:              true,
			ProgressNoneStreak: 3,
			StallWarned:        true,
			AutonomousTurns:    []agent.TurnSummary{{TokensIn: 200, FlowIDs: []string{"f1"}}},
		}
		workers := []*WorkerState{w}
		var built int
		fire, _ := stubFire(t)
		applyPlanAndFire(t.Context(),
			[]PlanEntry{{WorkerID: 1, Assignment: "continue"}},
			&workers, stubSpawn(&built), 5, fire,
			map[int]func() []agent.TurnSummary{}, nil,
		)
		assert.Equal(t, 0, w.ProgressNoneStreak)
		assert.False(t, w.StallWarned)
	})

	t.Run("max_workers_cap", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 1, Agent: &agent.FakeAgent{}, Alive: true},
			{ID: 2, Agent: &agent.FakeAgent{}, Alive: true},
		}
		var built int
		fire, fired := stubFire(t)
		applyPlanAndFire(t.Context(),
			[]PlanEntry{
				{WorkerID: 3, Assignment: "x"},
				{WorkerID: 4, Assignment: "y"},
				{WorkerID: 5, Assignment: "z"},
			},
			&workers, stubSpawn(&built), 2, fire,
			map[int]func() []agent.TurnSummary{}, nil,
		)
		assert.Len(t, workers, 2)
		assert.Equal(t, 0, built)
		assert.Empty(t, *fired)
	})

	t.Run("skips_dead_id", func(t *testing.T) {
		workers := []*WorkerState{
			{ID: 1, Agent: &agent.FakeAgent{}, Alive: false},
		}
		var built int
		fire, fired := stubFire(t)
		applyPlanAndFire(t.Context(),
			[]PlanEntry{{WorkerID: 1, Assignment: "ghost"}},
			&workers, stubSpawn(&built), 5, fire,
			map[int]func() []agent.TurnSummary{}, nil,
		)
		assert.Len(t, workers, 1)
		assert.Equal(t, 0, built)
		assert.Empty(t, *fired)
	})
}

func TestRefireAlive(t *testing.T) {
	t.Parallel()

	w1 := &WorkerState{ID: 1, Alive: true, Agent: &agent.FakeAgent{}, LastInstruction: "go w1"}
	w2 := &WorkerState{ID: 2, Alive: false, Agent: &agent.FakeAgent{}}
	workers := []*WorkerState{w1, w2}
	fire, fired := stubFire(t)
	inflight := map[int]func() []agent.TurnSummary{}
	refireAlive(t.Context(), workers, fire, inflight, nil)
	assert.Equal(t, []int{1}, *fired)
	assert.Len(t, inflight, 1)
}

func TestHarvestInflight(t *testing.T) {
	t.Parallel()

	inflight := map[int]func() []agent.TurnSummary{
		1: func() []agent.TurnSummary { return []agent.TurnSummary{{AssistantText: "w1"}} },
		2: func() []agent.TurnSummary { return nil },
	}
	out := harvestInflight(inflight)
	assert.Len(t, out, 2)
	require.Len(t, out[1], 1)
	assert.Equal(t, "w1", out[1][0].AssistantText)
}
