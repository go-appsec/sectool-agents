package orchestrator

import (
	"context"
	"sync"

	"github.com/go-appsec/secagent/history"
)

// RetireResult holds one retirement result. Empty Summary indicates
// summarize failure; retirement is still recorded.
type RetireResult struct {
	WorkerID int
	Iter     int
	Reason   string
	Summary  string
}

// RetireQueue summarizes retired workers asynchronously and buffers results for polled draining.
type RetireQueue struct {
	ctx     context.Context
	sum     *history.Summarizer
	mission string
	log     *Logger
	sem     chan struct{}
	wg      sync.WaitGroup
	results chan RetireResult
}

// newRetireQueue returns a RetireQueue; capacity caps simultaneous summarize calls.
func newRetireQueue(ctx context.Context, sum *history.Summarizer, mission string, log *Logger, capacity int) *RetireQueue {
	if capacity < 1 {
		capacity = 1
	}
	return &RetireQueue{
		ctx:     ctx,
		sum:     sum,
		mission: mission,
		log:     log,
		sem:     make(chan struct{}, capacity),
		results: make(chan RetireResult, capacity*4),
	}
}

// Submit closes w's agent, sets w.Alive=false, and queues a background
// summarize call. The same worker must not be submitted twice.
func (q *RetireQueue) Submit(w *WorkerState, reason string, iter int) {
	if q == nil {
		return
	}
	w.Alive = false
	chronicle := w.Chronicle.Messages()
	w.Close()
	q.log.Log("retire", "enqueued", map[string]any{
		"worker_id": w.ID, "reason": reason, "iter": iter,
		"chronicle_msgs": len(chronicle),
	})
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		// pre-cancel bail
		if err := q.ctx.Err(); err != nil {
			return
		}
		select {
		case q.sem <- struct{}{}:
		case <-q.ctx.Done():
			return
		}
		defer func() { <-q.sem }()
		var summary string
		if len(chronicle) > 0 && q.sum != nil {
			s, err := q.sum.SummarizeCompletedWorker(q.ctx, chronicle, q.mission, reason, w.ID)
			if err != nil {
				q.log.Log("retire", "summarize-fallback", map[string]any{
					"worker_id": w.ID, "err": err.Error(),
				})
			} else {
				summary = s
			}
		}
		res := RetireResult{WorkerID: w.ID, Iter: iter, Reason: reason, Summary: summary}
		select {
		case q.results <- res:
		case <-q.ctx.Done():
			return
		}
		q.log.Log("retire", "summary-ready", map[string]any{
			"worker_id": w.ID, "iter": iter, "summary_chars": len(summary),
		})
	}()
}

// DrainCompleted returns every retire result available without blocking, or nil when none are ready.
func (q *RetireQueue) DrainCompleted() []RetireResult {
	if q == nil {
		return nil
	}
	var out []RetireResult
	for {
		select {
		case r := <-q.results:
			out = append(out, r)
		default:
			return out
		}
	}
}

// WaitOne blocks until one retire result is available or ctx is done (returning zero and false).
func (q *RetireQueue) WaitOne(ctx context.Context) (RetireResult, bool) {
	if q == nil {
		return RetireResult{}, false
	}
	select {
	case r := <-q.results:
		return r, true
	case <-ctx.Done():
		return RetireResult{}, false
	}
}

// Wait blocks until every submitted retire completes. Does not drain results.
func (q *RetireQueue) Wait() {
	if q == nil {
		return
	}
	q.wg.Wait()
}
