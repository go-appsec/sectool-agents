package orchestrator

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestRunVerificationPhase(t *testing.T) {
	t.Parallel()

	t.Run("files_and_dismisses", func(t *testing.T) {
		dir := t.TempDir()
		writer := NewFindingWriter(dir)
		candidates := NewCandidatePool()
		c1 := candidates.Add(AddInput{
			WorkerID: 1, Title: "Reflected XSS in search",
			Severity: "high", Endpoint: "GET /search",
			Summary: "q param reflects without encoding",
		})
		c2 := candidates.Add(AddInput{
			WorkerID: 1, Title: "Leaked stack trace on /debug",
			Severity: "low", Endpoint: "GET /debug",
		})

		decisions := NewDecisionQueue()

		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "substep 1 done"}}}
		verifier.OnDrain = func(_ int) {
			decisions.AddFinding(FindingFiled{
				Title: "Reflected XSS in search", Severity: "high",
				Endpoint:               "GET /search",
				VerificationNotes:      "Reproduced via replay_send on flow abc12345",
				SupersedesCandidateIDs: []string{c1},
			})
			decisions.AddDismissal(CandidateDismissal{CandidateID: c2, Reason: "insufficient impact"})
			decisions.SetVerificationDone("filed 1, dismissed 1")
		}

		summary := RunVerificationPhase(
			t.Context(), verifier, decisions, candidates, writer, nil, nil,
		)

		assert.Equal(t, "filed 1, dismissed 1", summary)
		assert.Empty(t, candidates.Pending())
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.True(t, strings.HasPrefix(entries[0].Name(), "finding-"))
		body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
		require.NoError(t, err)
		assert.Contains(t, string(body), "Reflected XSS in search")
	})

	t.Run("no_pending_skips", func(t *testing.T) {
		writer := NewFindingWriter(t.TempDir())
		candidates := NewCandidatePool()
		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{} // no scripted turns, would error if reached
		summary := RunVerificationPhase(
			t.Context(), verifier, decisions, candidates, writer, nil, nil,
		)
		assert.Contains(t, summary, "No pending candidates")
	})

	t.Run("dismiss_dedup_logs_once_per_id", func(t *testing.T) {
		writer := NewFindingWriter(t.TempDir())
		candidates := NewCandidatePool()
		c1 := candidates.Add(AddInput{WorkerID: 1, Title: "x"})

		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}, {}}}
		var call int
		verifier.OnDrain = func(_ int) {
			call++
			// Record duplicate dismissals for the same candidate twice in a row
			decisions.AddDismissal(CandidateDismissal{CandidateID: c1, Reason: "first"})
			decisions.AddDismissal(CandidateDismissal{CandidateID: c1, Reason: "second"})
			decisions.AddDismissal(CandidateDismissal{CandidateID: c1, Reason: "third"})
			if call == 2 {
				decisions.SetVerificationDone("done")
			}
		}

		log, path, _ := newCapturedLogger(t)
		RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, log)
		require.NoError(t, log.Close())

		content := mustReadFile(t, path)
		count := strings.Count(content, `"msg":"candidate dismissed"`)
		assert.Equal(t, 1, count)
		assert.Equal(t, "dismissed", candidates.ByID(c1).Status)
	})

	t.Run("dismiss_cannot_override_verified", func(t *testing.T) {
		writer := NewFindingWriter(t.TempDir())
		candidates := NewCandidatePool()
		c1 := candidates.Add(AddInput{
			WorkerID: 1, Title: "Dup title",
			Severity: "high", Endpoint: "GET /x",
		})

		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
		verifier.OnDrain = func(_ int) {
			// File the finding first (marks c1 verified), then try to dismiss the same candidate in the same substep
			decisions.AddFinding(FindingFiled{
				Title: "Dup title", Severity: "high", Endpoint: "GET /x",
				VerificationNotes:      "ok",
				SupersedesCandidateIDs: []string{c1},
			})
			decisions.AddDismissal(CandidateDismissal{CandidateID: c1, Reason: "race"})
			decisions.SetVerificationDone("done")
		}

		RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, nil)
		assert.Equal(t, "verified", candidates.ByID(c1).Status)
	})

	t.Run("duplicate_finding_skipped", func(t *testing.T) {
		dir := t.TempDir()
		writer := NewFindingWriter(dir)
		// Prime the writer with an existing finding so the next is a duplicate
		_, err := writer.Write(FindingFiled{
			Title: "Reflected XSS in search", Severity: "high", Endpoint: "GET /search",
			VerificationNotes: "initial write",
		})
		require.NoError(t, err)

		candidates := NewCandidatePool()
		candidates.Add(AddInput{WorkerID: 1, Title: "Reflected XSS in search", Endpoint: "GET /search"})
		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
		verifier.OnDrain = func(_ int) {
			decisions.AddFinding(FindingFiled{
				Title: "Reflected XSS in search", Severity: "high", Endpoint: "GET /search",
				VerificationNotes: "dup",
			})
			decisions.SetVerificationDone("done")
		}
		RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, nil)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Len(t, entries, 1)
	})

	t.Run("match_fallback_logs_tier", func(t *testing.T) {
		// Title diverges but endpoint matches: verified via endpoint-only tier with match-fallback log
		writer := NewFindingWriter(t.TempDir())
		candidates := NewCandidatePool()
		c1 := candidates.Add(AddInput{
			WorkerID: 1, Title: "Standard User Cookie Reuse on Admin API",
			Severity: "high", Endpoint: "GET /admin/api/settings",
		})

		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
		verifier.OnDrain = func(_ int) {
			decisions.AddFinding(FindingFiled{
				Title:             "Admin API Requires JWT Bearer Auth",
				Severity:          "informational",
				Endpoint:          "GET /admin/api/settings",
				VerificationNotes: "ok",
			})
			decisions.SetVerificationDone("done")
		}

		log, path, _ := newCapturedLogger(t)
		RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, log)
		require.NoError(t, log.Close())

		assert.Equal(t, "verified", candidates.ByID(c1).Status)
		content := mustReadFile(t, path)
		assert.Contains(t, content, `"msg":"candidate match-fallback"`)
		assert.Contains(t, content, `"tier":"endpoint-only"`)
	})

	t.Run("orphan_candidate_logged_when_no_match", func(t *testing.T) {
		writer := NewFindingWriter(t.TempDir())
		candidates := NewCandidatePool()
		orphan := candidates.Add(AddInput{
			WorkerID: 1, Title: "completely_unrelated",
			Severity: "high", Endpoint: "POST /other",
		})

		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
		verifier.OnDrain = func(_ int) {
			decisions.AddFinding(FindingFiled{
				Title:             "Reflected XSS in Search",
				Severity:          "high",
				Endpoint:          "GET /search",
				VerificationNotes: "ok",
			})
			decisions.SetVerificationDone("done")
		}

		log, path, _ := newCapturedLogger(t)
		RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, log)
		require.NoError(t, log.Close())

		assert.Equal(t, "pending", candidates.ByID(orphan).Status)
		content := mustReadFile(t, path)
		assert.Contains(t, content, "orphan")
	})

	t.Run("finding_duplicate_logged_once_per_substep", func(t *testing.T) {
		writer := NewFindingWriter(t.TempDir())
		// Prime the writer with an existing finding so the burst below all match as duplicates against disk
		_, err := writer.Write(FindingFiled{
			Title: "Same title", Severity: "high", Endpoint: "GET /x",
			VerificationNotes: "initial",
		})
		require.NoError(t, err)

		candidates := NewCandidatePool()
		candidates.Add(AddInput{WorkerID: 1, Title: "Same title", Endpoint: "GET /x"})
		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
		verifier.OnDrain = func(_ int) {
			// Verifier calls file_finding four times in one substep with the identical title
			for range 4 {
				decisions.AddFinding(FindingFiled{
					Title: "Same title", Severity: "high", Endpoint: "GET /x",
					VerificationNotes: "dup",
				})
			}
			decisions.SetVerificationDone("done")
		}
		log, path, _ := newCapturedLogger(t)
		RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, log)
		require.NoError(t, log.Close())

		content := mustReadFile(t, path)
		count := strings.Count(content, `"msg":"duplicate skipped"`)
		assert.Equal(t, 1, count)
	})

	t.Run("llm_wedge_leaves_candidate_pending", func(t *testing.T) {
		// Pure LLM-side wedge (drain errors twice). The next iteration's fresh-compose gives it a clean shot.
		writer := NewFindingWriter(t.TempDir())
		candidates := NewCandidatePool()
		c1 := candidates.Add(AddInput{
			WorkerID: 1, Title: "Stuck finding",
			Severity: "high", Endpoint: "GET /stuck",
		})
		decisions := NewDecisionQueue()
		boom := errors.New("simulated drain error")
		verifier := &agent.FakeAgent{
			Turns:  []agent.TurnSummary{{}, {}},
			Errors: []error{boom, boom},
		}
		RunVerificationPhase(
			t.Context(), verifier, decisions, candidates, writer, nil, nil,
		)

		c := candidates.ByID(c1)
		require.NotNil(t, c)
		assert.Equal(t, "pending", c.Status)
		assert.Empty(t, decisions.Dismissals)
	})
}

func TestAutoDismissOnContextOverflow(t *testing.T) {
	t.Parallel()

	candidates := NewCandidatePool()
	c1 := candidates.Add(AddInput{WorkerID: 1, Title: "Pending A"})
	c2 := candidates.Add(AddInput{WorkerID: 1, Title: "Pending B"})
	decisions := NewDecisionQueue()

	log, path, _ := newCapturedLogger(t)
	AutoDismissOnContextOverflow(candidates, decisions, log)
	require.NoError(t, log.Close())

	assert.Equal(t, "dismissed", candidates.ByID(c1).Status)
	assert.Equal(t, "dismissed", candidates.ByID(c2).Status)
	require.Len(t, decisions.Dismissals, 2)
	assert.Contains(t, decisions.Dismissals[0].Reason, "context budget exhausted")
	assert.Contains(t, mustReadFile(t, path), `"msg":"auto-dismiss on context-budget overflow"`)
}
