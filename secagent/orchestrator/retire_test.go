package orchestrator

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/history"
)

func TestNewRetireQueue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		capacity    int
		wantSemCap  int
		wantBufSize int
	}{
		{"zero_clamps_to_one", 0, 1, 4},
		{"negative_clamps_to_one", -3, 1, 4},
		{"explicit_capacity", 3, 3, 12},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := newRetireQueue(t.Context(), nil, "m", nil, c.capacity)
			require.NotNil(t, q)
			assert.Equal(t, c.wantSemCap, cap(q.sem))
			assert.Equal(t, c.wantBufSize, cap(q.results))
		})
	}
}

func TestRetireQueueSubmit(t *testing.T) {
	t.Parallel()

	t.Run("flips_alive_and_summarizes", func(t *testing.T) {
		client := &scriptedClient{response: "third-person recap"}
		s := &history.Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: history.NopLogger{}}
		q := newRetireQueue(t.Context(), s, "mission", nil, 1)
		fa := &agent.FakeAgent{}
		w := &WorkerState{
			ID: 4, Alive: true, Agent: fa,
			Chronicle: history.NewChronicle([]agent.Message{
				{Role: "user", Content: "directive"},
				{Role: "assistant", Content: "did real work"},
			}, nil),
		}
		q.Submit(w, "exhausted angle", 7)

		assert.False(t, w.Alive)
		assert.True(t, fa.Closed)

		q.Wait()
		results := q.DrainCompleted()
		require.Len(t, results, 1)
		assert.Equal(t, 4, results[0].WorkerID)
		assert.Equal(t, 7, results[0].Iter)
		assert.Equal(t, "exhausted angle", results[0].Reason)
		assert.Equal(t, "third-person recap", results[0].Summary)
	})

	t.Run("empty_chronicle_skips_llm", func(t *testing.T) {
		client := &scriptedClient{response: "should not be used"}
		s := &history.Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: history.NopLogger{}}
		q := newRetireQueue(t.Context(), s, "mission", nil, 1)
		w := &WorkerState{ID: 1, Alive: true, Agent: &agent.FakeAgent{}}
		q.Submit(w, "no work done", 2)
		q.Wait()

		results := q.DrainCompleted()
		require.Len(t, results, 1)
		assert.Empty(t, results[0].Summary)
		assert.Equal(t, int32(0), atomic.LoadInt32(&client.calls))
	})

	t.Run("summarizer_error_records_empty_summary", func(t *testing.T) {
		client := &scriptedClient{err: errors.New("upstream down")}
		s := &history.Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: history.NopLogger{}}
		q := newRetireQueue(t.Context(), s, "mission", nil, 1)
		w := &WorkerState{
			ID: 9, Alive: true, Agent: &agent.FakeAgent{},
			Chronicle: history.NewChronicle([]agent.Message{
				{Role: "user", Content: "x"},
				{Role: "assistant", Content: "y"},
			}, nil),
		}
		q.Submit(w, "err", 3)
		q.Wait()

		results := q.DrainCompleted()
		require.Len(t, results, 1)
		assert.Empty(t, results[0].Summary)
		assert.Equal(t, 9, results[0].WorkerID)
	})

	t.Run("canceled_ctx_skips_summarize", func(t *testing.T) {
		client := &scriptedClient{response: "n/a"}
		s := &history.Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: history.NopLogger{}}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		q := newRetireQueue(ctx, s, "mission", nil, 1)
		w := &WorkerState{
			ID: 1, Alive: true, Agent: &agent.FakeAgent{},
			Chronicle: history.NewChronicle([]agent.Message{{Role: "assistant", Content: "x"}}, nil),
		}
		q.Submit(w, "stop", 1)
		q.Wait()

		assert.Equal(t, int32(0), atomic.LoadInt32(&client.calls))
		assert.Empty(t, q.DrainCompleted())
	})

	t.Run("nil_receiver_noop", func(t *testing.T) {
		var q *RetireQueue
		require.NotPanics(t, func() {
			q.Submit(&WorkerState{ID: 1}, "r", 1)
			q.Wait()
			assert.Nil(t, q.DrainCompleted())
		})
	})
}

func TestRetireQueueDrainCompleted(t *testing.T) {
	t.Parallel()

	t.Run("returns_nil_when_empty", func(t *testing.T) {
		q := newRetireQueue(t.Context(), nil, "m", nil, 1)
		assert.Nil(t, q.DrainCompleted())
	})

	t.Run("drains_all_buffered", func(t *testing.T) {
		client := &scriptedClient{response: "ok"}
		s := &history.Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: history.NopLogger{}}
		q := newRetireQueue(t.Context(), s, "m", nil, 3)
		for i := 1; i <= 3; i++ {
			q.Submit(&WorkerState{
				ID: i, Alive: true, Agent: &agent.FakeAgent{},
				Chronicle: history.NewChronicle([]agent.Message{
					{Role: "user", Content: "x"},
					{Role: "assistant", Content: "y"},
				}, nil),
			}, "r", i)
		}
		q.Wait()

		got := q.DrainCompleted()
		assert.Len(t, got, 3)
		ids := []int{got[0].WorkerID, got[1].WorkerID, got[2].WorkerID}
		assert.ElementsMatch(t, []int{1, 2, 3}, ids)
	})
}

func TestRetireQueueWaitOne(t *testing.T) {
	t.Parallel()

	t.Run("returns_first_completed", func(t *testing.T) {
		client := &scriptedClient{response: "ok"}
		s := &history.Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: history.NopLogger{}}
		q := newRetireQueue(t.Context(), s, "m", nil, 1)
		q.Submit(&WorkerState{
			ID: 5, Alive: true, Agent: &agent.FakeAgent{},
			Chronicle: history.NewChronicle([]agent.Message{
				{Role: "user", Content: "x"},
				{Role: "assistant", Content: "y"},
			}, nil),
		}, "done", 2)

		res, ok := q.WaitOne(t.Context())
		require.True(t, ok)
		assert.Equal(t, 5, res.WorkerID)
		assert.Equal(t, "ok", res.Summary)
	})

	t.Run("ctx_cancel_unblocks", func(t *testing.T) {
		q := newRetireQueue(t.Context(), nil, "m", nil, 1)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, ok := q.WaitOne(ctx)
		assert.False(t, ok)
	})

	t.Run("nil_receiver_returns_false", func(t *testing.T) {
		var q *RetireQueue
		_, ok := q.WaitOne(t.Context())
		assert.False(t, ok)
	})
}
