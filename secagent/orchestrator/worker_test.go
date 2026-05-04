package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWorkerStateAppendHistory(t *testing.T) {
	t.Parallel()

	t.Run("before_wrap", func(t *testing.T) {
		var w WorkerState
		for i := 1; i <= 3; i++ {
			w.AppendHistory(IterationEntry{Iteration: i})
		}
		entries := w.RecentHistory()
		assert.Len(t, entries, 3)
		assert.Equal(t, 1, entries[0].Iteration)
		assert.Equal(t, 3, entries[2].Iteration)
	})

	t.Run("wraps_around", func(t *testing.T) {
		var w WorkerState
		total := WorkerHistoryRing + 2
		for i := 1; i <= total; i++ {
			w.AppendHistory(IterationEntry{
				Iteration: i,
				Angle:     "angle",
				Outcome:   OutcomeSilent,
			})
		}
		entries := w.RecentHistory()
		assert.Len(t, entries, WorkerHistoryRing)
		assert.Equal(t, 3, entries[0].Iteration)
		assert.Equal(t, total, entries[len(entries)-1].Iteration)
		for i := 1; i < len(entries); i++ {
			assert.Greater(t, entries[i].Iteration, entries[i-1].Iteration)
		}
	})

	t.Run("empty_returns_nil", func(t *testing.T) {
		var w WorkerState
		assert.Nil(t, w.RecentHistory())
	})
}
