package orchestrator

import (
	"context"
	"sync"
)

// asyncMerger implements MergeSubmitter by running merges on a
// bounded-concurrency goroutine pool; submissions beyond the backlog cap fail
// fast into the candidate pool.
type asyncMerger struct {
	ctx      context.Context
	reviewer DedupReviewer
	writer   *FindingWriter
	// candidates receives the evidence of any merge that fails so the
	// verifier and the shutdown dump can recover it; nil disables the fallback.
	candidates *CandidatePool
	log        *Logger
	sem        chan struct{}
	// mu guards pending/quiesced so late submissions from unwinding tool-handler
	// goroutines can never race Wait (sync.WaitGroup Add/Wait misuse)
	mu       sync.Mutex
	idle     *sync.Cond
	pending  int
	quiesced bool
}

// newAsyncMerger returns an asyncMerger; capacity caps simultaneous merges.
func newAsyncMerger(ctx context.Context, reviewer DedupReviewer, writer *FindingWriter,
	candidates *CandidatePool, log *Logger, capacity int) *asyncMerger {
	if capacity < 1 {
		capacity = 1
	}
	m := &asyncMerger{
		ctx:        ctx,
		reviewer:   reviewer,
		writer:     writer,
		candidates: candidates,
		log:        log,
		sem:        make(chan struct{}, capacity),
	}
	m.idle = sync.NewCond(&m.mu)
	return m
}

// Submit queues a merge of incoming into matchedFilename and returns
// immediately. Cancellation of the run-level ctx aborts in-flight merges;
// any merge that cannot complete preserves its evidence in the candidate pool.
// Submissions after Wait, or while maxPendingMerges merges are already queued
// or running, are rejected and recovered the same way.
func (m *asyncMerger) Submit(matchedFilename string, incoming AddInput) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.quiesced {
		m.mu.Unlock()
		m.rescue(incoming, matchedFilename, "merger quiesced")
		return
	}
	if m.pending >= maxPendingMerges {
		m.mu.Unlock()
		m.rescue(incoming, matchedFilename, "merger backlog full")
		return
	}
	m.pending++
	m.mu.Unlock()
	go func() {
		defer m.mergeDone()
		// pre-cancel bail: select races a canceled ctx against semaphore send
		if err := m.ctx.Err(); err != nil {
			m.rescue(incoming, matchedFilename, "canceled before merge")
			return
		}
		select {
		case m.sem <- struct{}{}:
		case <-m.ctx.Done():
			m.rescue(incoming, matchedFilename, "canceled before merge")
			return
		}
		defer func() { <-m.sem }()
		m.runOne(matchedFilename, incoming)
	}()
}

// Wait rejects further submissions and blocks until every previously accepted
// merge completes. Rejected submissions preserve their evidence in the
// candidate pool. Safe to call more than once.
func (m *asyncMerger) Wait() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.quiesced = true
	for m.pending > 0 {
		m.idle.Wait()
	}
	m.mu.Unlock()
}

// mergeDone records a merge goroutine finishing and wakes a waiting Wait.
func (m *asyncMerger) mergeDone() {
	m.mu.Lock()
	m.pending--
	if m.pending == 0 {
		m.idle.Broadcast()
	}
	m.mu.Unlock()
}

func (m *asyncMerger) runOne(matchedFilename string, incoming AddInput) {
	// resolve by sequence number at execution time: renames keep the sequence
	// but change the slug, so a filename captured earlier may be stale
	_, path, ok := m.writer.LookupBySequence(findingSeqFromPath(matchedFilename))
	if !ok {
		m.log.Log("finding", "async-merge target missing", map[string]any{
			"matched_filename": matchedFilename,
		})
		m.rescue(incoming, matchedFilename, "target missing")
		return
	}
	secondary := candidateAsFindingFiled(incoming)
	newPath, err := m.writer.MergeExisting(path, func(existing FindingFiled) (FindingFiled, error) {
		return m.reviewer.Merge(m.ctx, existing, secondary)
	})
	if err != nil {
		m.log.Log("finding", "async-merge error", map[string]any{
			"matched_filename": matchedFilename,
			"err":              err.Error(),
		})
		m.rescue(incoming, matchedFilename, err.Error())
		return
	}
	m.log.Log("finding", "async-merge applied", map[string]any{
		"matched_filename": matchedFilename,
		"path":             newPath,
	})
}

// rescue preserves the evidence of a failed merge as a pending candidate so
// the verifier and the shutdown dump can recover it.
func (m *asyncMerger) rescue(in AddInput, matchedFilename, cause string) {
	if m.candidates == nil {
		return
	}
	cid := m.candidates.Add(in)
	m.log.Log("finding", "async-merge evidence preserved", map[string]any{
		"candidate_id":     cid,
		"matched_filename": matchedFilename,
		"cause":            cause,
	})
}

// candidateAsFindingFiled converts an AddInput to the FindingFiled shape expected by reviewer.Merge.
func candidateAsFindingFiled(in AddInput) FindingFiled {
	return FindingFiled{
		Title:             in.Title,
		Severity:          in.Severity,
		Endpoint:          in.Endpoint,
		Description:       in.Summary,
		ReproductionSteps: in.ReproductionHint,
		Evidence:          in.EvidenceNotes,
	}
}
