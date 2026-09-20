package orchestrator

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
)

// Shutdown phase constants.
const (
	ShutdownPhaseRunning         int32 = 0
	ShutdownPhaseVerifyOnly      int32 = 1
	ShutdownPhaseDumpUnvalidated int32 = 2
	ShutdownPhaseKill            int32 = 3
)

// Shutdown coordinates a graceful, multi-stage termination of a Run.
// Stage 1 cancels WorkersCtx (verify-only); stage 2 also cancels
// VerifierCtx (dump unvalidated); stage 3 records a kill request.
type Shutdown struct {
	phase atomic.Int32

	// WorkersCtx is canceled at stage 1; handed to workers and directors.
	WorkersCtx    context.Context
	workersCancel context.CancelFunc

	// VerifierCtx is canceled at stage 2; handed to the verifier loop.
	VerifierCtx    context.Context
	verifierCancel context.CancelFunc

	// RootCtx is the parent context for teardown work outliving both worker- and verifier-level cancellations.
	RootCtx context.Context

	// mu guards the bound cancels; signal handling may race with Run binding them.
	mu           sync.Mutex
	workerStop   []context.CancelFunc // extra cancels for contexts Run derives from its own ctx
	verifierStop []context.CancelFunc

	log *Logger
}

// NewShutdown returns a Shutdown in the running state with WorkersCtx and VerifierCtx derived from parent.
func NewShutdown(parent context.Context, log *Logger) *Shutdown {
	wctx, wcancel := context.WithCancel(parent)
	vctx, vcancel := context.WithCancel(parent)
	return &Shutdown{
		WorkersCtx:     wctx,
		workersCancel:  wcancel,
		VerifierCtx:    vctx,
		verifierCancel: vcancel,
		RootCtx:        parent,
		log:            log,
	}
}

// BindWorkerCancel registers cancel so stage transitions also stop a worker
// context Run derives from its own ctx (rather than WorkersCtx).
func (s *Shutdown) BindWorkerCancel(cancel context.CancelFunc) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.workerStop = append(s.workerStop, cancel)
	s.mu.Unlock()
}

// BindVerifierCancel registers cancel so stage transitions also stop a verifier
// context Run derives from its own ctx (rather than VerifierCtx).
func (s *Shutdown) BindVerifierCancel(cancel context.CancelFunc) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.verifierStop = append(s.verifierStop, cancel)
	s.mu.Unlock()
}

func (s *Shutdown) stopWorkers() {
	s.workersCancel()
	s.mu.Lock()
	stops := slices.Clone(s.workerStop)
	s.mu.Unlock()
	for _, cancel := range stops {
		cancel()
	}
}

func (s *Shutdown) stopVerifiers() {
	s.verifierCancel()
	s.mu.Lock()
	stops := slices.Clone(s.verifierStop)
	s.mu.Unlock()
	for _, cancel := range stops {
		cancel()
	}
}

// Phase returns the current shutdown phase.
func (s *Shutdown) Phase() int32 {
	if s == nil {
		return ShutdownPhaseRunning
	}
	return s.phase.Load()
}

// RequestVerifyOnly transitions to phase 1 and cancels WorkersCtx. No-op when already at phase 2 or 3.
func (s *Shutdown) RequestVerifyOnly() {
	if s == nil {
		return
	}
	if s.phase.CompareAndSwap(ShutdownPhaseRunning, ShutdownPhaseVerifyOnly) {
		s.stopWorkers()
		s.log.Log("shutdown", "verify-only requested", map[string]any{"phase": ShutdownPhaseVerifyOnly})
	}
}

// RequestDumpUnvalidated transitions to phase 2 and cancels both
// VerifierCtx and WorkersCtx. No-op when already at phase 2 or 3.
func (s *Shutdown) RequestDumpUnvalidated() {
	if s == nil {
		return
	}
	for {
		cur := s.phase.Load()
		if cur >= ShutdownPhaseDumpUnvalidated {
			return
		}
		if s.phase.CompareAndSwap(cur, ShutdownPhaseDumpUnvalidated) {
			s.stopWorkers()
			s.stopVerifiers()
			s.log.Log("shutdown", "dump-unvalidated requested", map[string]any{"phase": ShutdownPhaseDumpUnvalidated})
			return
		}
	}
}

// DumpUnvalidatedCandidates writes each pending candidate via
// writer.WriteUnvalidated and returns the number of successful writes.
func DumpUnvalidatedCandidates(pending []FindingCandidate, writer *FindingWriter, log *Logger) int {
	var written int
	for _, c := range pending {
		path, err := writer.WriteUnvalidated(c)
		if err != nil {
			log.Log("unvalidated", "write failed", map[string]any{
				"candidate_id": c.CandidateID, "title": c.Title, "err": err.Error(),
			})
			continue
		}
		written++
		log.Log("unvalidated", "written", map[string]any{
			"candidate_id": c.CandidateID, "path": path, "title": c.Title,
		})
	}
	log.Log("shutdown", "dumped unvalidated", map[string]any{
		"written": written, "pending": len(pending),
	})
	return written
}

// RequestKill transitions to phase 3 and cancels both child contexts.
// The caller is responsible for terminating the process.
func (s *Shutdown) RequestKill() {
	if s == nil {
		return
	}
	for {
		cur := s.phase.Load()
		if cur >= ShutdownPhaseKill {
			return
		}
		if s.phase.CompareAndSwap(cur, ShutdownPhaseKill) {
			s.stopWorkers()
			s.stopVerifiers()
			s.log.Log("shutdown", "kill requested", map[string]any{"phase": ShutdownPhaseKill})
			return
		}
	}
}
