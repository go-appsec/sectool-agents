package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/sectool-agents/secagent/agent"
)

func TestShutdownPhaseTransitions(t *testing.T) {
	t.Parallel()

	t.Run("running_to_verify_only", func(t *testing.T) {
		sd := NewShutdown(t.Context(), nil)
		assert.Equal(t, ShutdownPhaseRunning, sd.Phase())
		assert.NoError(t, sd.WorkersCtx.Err())
		assert.NoError(t, sd.VerifierCtx.Err())

		sd.RequestVerifyOnly()
		assert.Equal(t, ShutdownPhaseVerifyOnly, sd.Phase())
		require.ErrorIs(t, sd.WorkersCtx.Err(), context.Canceled)
		require.NoError(t, sd.VerifierCtx.Err(), "verifier still alive at stage 1")
	})

	t.Run("verify_then_dump", func(t *testing.T) {
		sd := NewShutdown(t.Context(), nil)
		sd.RequestVerifyOnly()
		sd.RequestDumpUnvalidated()
		assert.Equal(t, ShutdownPhaseDumpUnvalidated, sd.Phase())
		require.ErrorIs(t, sd.WorkersCtx.Err(), context.Canceled)
		require.ErrorIs(t, sd.VerifierCtx.Err(), context.Canceled)
	})

	t.Run("dump_without_verify_first", func(t *testing.T) {
		// Skipping straight to phase 2 still cancels both ctxs
		sd := NewShutdown(t.Context(), nil)
		sd.RequestDumpUnvalidated()
		assert.Equal(t, ShutdownPhaseDumpUnvalidated, sd.Phase())
		require.ErrorIs(t, sd.WorkersCtx.Err(), context.Canceled)
		require.ErrorIs(t, sd.VerifierCtx.Err(), context.Canceled)
	})

	t.Run("late_bind_worker_cancel", func(t *testing.T) {
		// Cancel bound after stage 1 fires immediately, closing the bind race
		sd := NewShutdown(t.Context(), nil)
		sd.RequestVerifyOnly()
		wctx, wcancel := context.WithCancel(t.Context())
		sd.BindWorkerCancel(wcancel)
		require.ErrorIs(t, wctx.Err(), context.Canceled)
	})

	t.Run("late_bind_verifier_cancel", func(t *testing.T) {
		// Cancel bound after stage 2 fires immediately, closing the bind race
		sd := NewShutdown(t.Context(), nil)
		sd.RequestDumpUnvalidated()
		vctx, vcancel := context.WithCancel(t.Context())
		sd.BindVerifierCancel(vcancel)
		require.ErrorIs(t, vctx.Err(), context.Canceled)
	})

	t.Run("late_bind_after_kill", func(t *testing.T) {
		sd := NewShutdown(t.Context(), nil)
		sd.RequestKill()
		wctx, wcancel := context.WithCancel(t.Context())
		sd.BindWorkerCancel(wcancel)
		require.ErrorIs(t, wctx.Err(), context.Canceled)
		vctx, vcancel := context.WithCancel(t.Context())
		sd.BindVerifierCancel(vcancel)
		require.ErrorIs(t, vctx.Err(), context.Canceled)
	})

	t.Run("kill_func_runs_once", func(t *testing.T) {
		sd := NewShutdown(t.Context(), nil)
		var calls atomic.Int32
		sd.SetKillFunc(func() { calls.Add(1) })
		sd.RequestKill()
		sd.RequestKill()
		assert.Equal(t, int32(1), calls.Load())
	})

	t.Run("kill_is_terminal", func(t *testing.T) {
		sd := NewShutdown(t.Context(), nil)
		sd.RequestKill()
		assert.Equal(t, ShutdownPhaseKill, sd.Phase())
		// Once kill, lower-priority requests are ignored
		sd.RequestVerifyOnly()
		sd.RequestDumpUnvalidated()
		assert.Equal(t, ShutdownPhaseKill, sd.Phase())
	})

	t.Run("idempotent", func(t *testing.T) {
		sd := NewShutdown(t.Context(), nil)
		sd.RequestVerifyOnly()
		sd.RequestVerifyOnly()
		sd.RequestVerifyOnly()
		assert.Equal(t, ShutdownPhaseVerifyOnly, sd.Phase())
		sd.RequestDumpUnvalidated()
		sd.RequestDumpUnvalidated()
		assert.Equal(t, ShutdownPhaseDumpUnvalidated, sd.Phase())
	})

	t.Run("nil_safe", func(t *testing.T) {
		var sd *Shutdown
		assert.Equal(t, ShutdownPhaseRunning, sd.Phase())
		require.NotPanics(t, func() {
			sd.RequestVerifyOnly()
			sd.RequestDumpUnvalidated()
			sd.RequestKill()
		})
	})

	t.Run("parent_cancellation", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		sd := NewShutdown(parent, nil)

		cancel()
		// Both child ctxs propagate parent cancellation even without a stage transition
		<-sd.WorkersCtx.Done()
		<-sd.VerifierCtx.Done()
		// Phase remains 0; we only flipped the parent ctx, not the shutdown state
		assert.Equal(t, ShutdownPhaseRunning, sd.Phase())
	})
}

func TestDumpUnvalidatedCandidates(t *testing.T) {
	t.Parallel()

	t.Run("writes_unvalidated_files", func(t *testing.T) {
		dir := t.TempDir()
		writer := newTestFindingWriter(t, dir)
		pending := []FindingCandidate{
			{
				CandidateID: "c001", WorkerID: 2, Title: "Reflected XSS",
				Severity: "high", Endpoint: "GET /search",
				Summary: "q reflects raw", FlowIDs: []string{"f-1"},
			},
			{
				CandidateID: "c002", WorkerID: 3, Title: "SSRF candidate",
				Severity: "critical", Endpoint: "POST /fetch",
			},
		}

		written := DumpUnvalidatedCandidates(pending, writer, "test", nil)
		assert.Equal(t, 2, written)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 2)
		for _, e := range entries {
			assert.True(t, strings.HasPrefix(e.Name(), "unvalidated-"), e.Name())
			body, err := os.ReadFile(filepath.Join(dir, e.Name()))
			require.NoError(t, err)
			assert.Contains(t, string(body), "**THIS FINDING IS UNVALIDATED.**")
		}
	})
}

// TestShutdownEscalateMidVerify covers a 2nd Ctrl+C arriving while the final
// verifier substep is in progress: RunVerificationPhase breaks out, leaving
// the still-pending candidate for the post-loop stage-2 dump path.
func TestShutdownEscalateMidVerify(t *testing.T) {
	t.Parallel()

	candidates := NewCandidatePool()
	c1 := candidates.Add(AddInput{
		WorkerID: 1, Title: "candidate one",
		Severity: "med", Endpoint: "GET /x",
	})
	candidates.Add(AddInput{
		WorkerID: 1, Title: "candidate two",
		Severity: "med", Endpoint: "GET /y",
	})

	writer := newTestFindingWriter(t, t.TempDir())
	decisions := NewDecisionQueue()
	sd := NewShutdown(t.Context(), nil)

	// First Drain files candidate one then escalates to stage 2; sd.VerifierCtx
	// cancels, next Drain returns context.Canceled, candidate two stays pending
	verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}, {}}}
	verifier.OnDrain = func(_ int) {
		decisions.AddFinding(FindingFiled{
			Title: "candidate one", Severity: "med", Endpoint: "GET /x",
			VerificationNotes:      "ok",
			SupersedesCandidateIDs: []string{c1},
		})
		sd.RequestDumpUnvalidated()
	}

	RunVerificationPhase(sd.VerifierCtx, verifier, decisions, candidates, writer, nil, nil)

	assert.Equal(t, CandidateStatusVerified, candidates.ByID(c1).Status)
	pending := candidates.Pending()
	require.Len(t, pending, 1)
	assert.Equal(t, "candidate two", pending[0].Title)

	// Dump persists the remaining pending candidate as UNVALIDATED
	written := DumpUnvalidatedCandidates(pending, writer, "test", nil)
	assert.Equal(t, 1, written)
	assert.Equal(t, 1, writer.UnvalidatedCount)
}

// TestDumpNormalExit covers the non-shutdown exit path: pending candidates
// left by a normal run end (end_run, max-iterations) are persisted so worker
// evidence survives.
func TestDumpNormalExit(t *testing.T) {
	t.Parallel()

	t.Run("writes_pending_with_reason", func(t *testing.T) {
		dir := t.TempDir()
		writer := newTestFindingWriter(t, dir)
		candidates := NewCandidatePool()
		candidates.Add(AddInput{
			WorkerID: 1, Title: "leftover candidate",
			Severity: "med", Endpoint: "GET /z",
		})

		// mirrors the post-loop dump in Run for sd.Phase() == Running
		pending := candidates.Pending()
		require.Len(t, pending, 1)
		written := DumpUnvalidatedCandidates(pending, writer, "normal-exit", nil)

		assert.Equal(t, 1, written)
		assert.Equal(t, 1, writer.UnvalidatedCount)
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
	})

	t.Run("no_pending_writes_nothing", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		written := DumpUnvalidatedCandidates(nil, writer, "normal-exit", nil)
		assert.Equal(t, 0, written)
		assert.Equal(t, 0, writer.UnvalidatedCount)
	})
}
