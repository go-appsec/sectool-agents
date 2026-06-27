package orchestrator

import (
	"context"
	"sync"
)

// asyncMerger implements MergeSubmitter by running each merge in a bounded-concurrency goroutine.
type asyncMerger struct {
	ctx      context.Context
	reviewer DedupReviewer
	writer   *FindingWriter
	log      *Logger
	sem      chan struct{}
	wg       sync.WaitGroup
}

// newAsyncMerger returns an asyncMerger; capacity caps simultaneous merges.
func newAsyncMerger(ctx context.Context, reviewer DedupReviewer, writer *FindingWriter, log *Logger, capacity int) *asyncMerger {
	if capacity < 1 {
		capacity = 1
	}
	return &asyncMerger{
		ctx:      ctx,
		reviewer: reviewer,
		writer:   writer,
		log:      log,
		sem:      make(chan struct{}, capacity),
	}
}

// Submit queues a merge of incoming into matchedFilename and returns
// immediately. Cancellation of the run-level ctx aborts in-flight merges.
func (m *asyncMerger) Submit(matchedFilename string, incoming AddInput) {
	if m == nil {
		return
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		// pre-cancel bail: select races a canceled ctx against semaphore send
		if err := m.ctx.Err(); err != nil {
			return
		}
		select {
		case m.sem <- struct{}{}:
		case <-m.ctx.Done():
			return
		}
		defer func() { <-m.sem }()
		m.runOne(matchedFilename, incoming)
	}()
}

// Wait blocks until every submitted merge completes.
func (m *asyncMerger) Wait() {
	if m == nil {
		return
	}
	m.wg.Wait()
}

func (m *asyncMerger) runOne(matchedFilename string, incoming AddInput) {
	_, path, ok := m.writer.LookupByFilename(matchedFilename)
	if !ok {
		m.log.Log("finding", "async-merge target missing", map[string]any{
			"matched_filename": matchedFilename,
		})
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
		return
	}
	m.log.Log("finding", "async-merge applied", map[string]any{
		"matched_filename": matchedFilename,
		"path":             newPath,
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
