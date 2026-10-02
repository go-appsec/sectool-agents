package orchestrator

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/sectool-agents/secagent/agent"
)

func TestRunVerificationPhase(t *testing.T) {
	t.Parallel()

	t.Run("files_and_dismisses", func(t *testing.T) {
		dir := t.TempDir()
		writer := newTestFindingWriter(t, dir)
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
		writer := newTestFindingWriter(t, t.TempDir())
		candidates := NewCandidatePool()
		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{} // no scripted turns, would error if reached
		summary := RunVerificationPhase(
			t.Context(), verifier, decisions, candidates, writer, nil, nil,
		)
		assert.Contains(t, summary, "No pending candidates")
	})

	t.Run("dismiss_dedup_logs_once_per_id", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
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
		summary := RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, log)
		require.NoError(t, log.Close())

		content := mustReadFile(t, path)
		count := strings.Count(content, `"msg":"candidate dismissed"`)
		assert.Equal(t, 1, count)
		assert.Equal(t, "dismissed", candidates.ByID(c1).Status)
		assert.Equal(t, "Verification phase ended with 0 filed, 1 dismissed, 0 still pending.", summary)
	})

	t.Run("dismiss_cannot_override_verified", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
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
		writer := newTestFindingWriter(t, dir)
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

	t.Run("implicit_title_endpoint_resolves", func(t *testing.T) {
		// Title similar AND endpoint matches: implicit link resolves verified
		writer := newTestFindingWriter(t, t.TempDir())
		candidates := NewCandidatePool()
		c1 := candidates.Add(AddInput{
			WorkerID: 1, Title: "Reflected XSS in search param",
			Severity: "high", Endpoint: "GET /search",
		})

		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
		verifier.OnDrain = func(_ int) {
			decisions.AddFinding(FindingFiled{
				Title:             "Reflected XSS in search",
				Severity:          "high",
				Endpoint:          "GET /search",
				VerificationNotes: "ok",
			})
			decisions.SetVerificationDone("done")
		}

		RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, nil)
		assert.Equal(t, "verified", candidates.ByID(c1).Status)
	})

	t.Run("match_fallback_leaves_pending", func(t *testing.T) {
		// Title diverges but endpoint matches: too ambiguous to resolve,
		// candidate stays pending with a match-fallback log for audit
		writer := newTestFindingWriter(t, t.TempDir())
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

		assert.Equal(t, "pending", candidates.ByID(c1).Status)
		content := mustReadFile(t, path)
		assert.Contains(t, content, `"msg":"candidate match-fallback"`)
		assert.Contains(t, content, `"tier":"endpoint-only"`)
		assert.Contains(t, content, "Standard User Cookie Reuse on Admin API")
	})

	t.Run("title_only_fallback_leaves_pending", func(t *testing.T) {
		// Similar title but diverging endpoint: candidate stays pending
		writer := newTestFindingWriter(t, t.TempDir())
		candidates := NewCandidatePool()
		c1 := candidates.Add(AddInput{
			WorkerID: 1, Title: "Reflected XSS in search",
			Severity: "high", Endpoint: "GET /other",
		})

		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
		verifier.OnDrain = func(_ int) {
			decisions.AddFinding(FindingFiled{
				Title:             "Reflected XSS in search",
				Severity:          "high",
				Endpoint:          "GET /search",
				VerificationNotes: "ok",
			})
			decisions.SetVerificationDone("done")
		}

		log, path, _ := newCapturedLogger(t)
		RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, log)
		require.NoError(t, log.Close())

		assert.Equal(t, "pending", candidates.ByID(c1).Status)
		assert.Contains(t, mustReadFile(t, path), `"tier":"title-only"`)
	})

	t.Run("orphan_candidate_logged_when_no_match", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
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

	t.Run("duplicate_filing_resolves_explicit_links", func(t *testing.T) {
		// A seen-duplicate filing must still resolve the candidates it explicitly links
		writer := newTestFindingWriter(t, t.TempDir())
		candidates := NewCandidatePool()
		c1 := candidates.Add(AddInput{
			WorkerID: 1, Title: "Dup filing",
			Severity: "high", Endpoint: "GET /x",
		})
		c2 := candidates.Add(AddInput{
			WorkerID: 1, Title: "Other angle",
			Severity: "high", Endpoint: "GET /y",
		})

		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
		verifier.OnDrain = func(_ int) {
			decisions.AddFinding(FindingFiled{
				Title: "Dup filing", Severity: "high", Endpoint: "GET /x",
				VerificationNotes:      "first",
				SupersedesCandidateIDs: []string{c1},
			})
			decisions.AddFinding(FindingFiled{
				Title: "Dup filing", Severity: "high", Endpoint: "GET /x",
				VerificationNotes:      "dup of the first",
				SupersedesCandidateIDs: []string{c2},
			})
			decisions.SetVerificationDone("done")
		}

		RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, nil)

		assert.Equal(t, "verified", candidates.ByID(c1).Status)
		assert.Equal(t, "verified", candidates.ByID(c2).Status)
		assert.Empty(t, candidates.Pending())
	})

	t.Run("finding_duplicate_logged_once_per_substep", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
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

	t.Run("duplicate_filings_count_once", func(t *testing.T) {
		// four identical filings in one substep collapse to one applied write
		writer := newTestFindingWriter(t, t.TempDir())
		candidates := NewCandidatePool()
		candidates.Add(AddInput{WorkerID: 1, Title: "Same title", Endpoint: "GET /x"})
		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
		verifier.OnDrain = func(_ int) {
			for range 4 {
				decisions.AddFinding(FindingFiled{
					Title: "Same title", Severity: "high", Endpoint: "GET /x",
					VerificationNotes: "dup",
				})
			}
		}

		summary := RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, nil)
		assert.Equal(t, "Verification phase ended with 1 filed, 0 dismissed, 0 still pending.", summary)
	})

	t.Run("repeat_dismissal_counts_once", func(t *testing.T) {
		// duplicate dismissals collapse to one applied transition in the summary
		writer := newTestFindingWriter(t, t.TempDir())
		candidates := NewCandidatePool()
		c1 := candidates.Add(AddInput{WorkerID: 1, Title: "x"})

		decisions := NewDecisionQueue()
		verifier := &agent.FakeAgent{Turns: []agent.TurnSummary{{}}}
		verifier.OnDrain = func(_ int) {
			for range 3 {
				decisions.AddDismissal(CandidateDismissal{CandidateID: c1, Reason: "again"})
			}
		}

		summary := RunVerificationPhase(t.Context(), verifier, decisions, candidates, writer, nil, nil)
		assert.Equal(t, "Verification phase ended with 0 filed, 1 dismissed, 0 still pending.", summary)
	})

	t.Run("errored_substep_still_writes_findings", func(t *testing.T) {
		// A drain that files a finding and then fails must not lose the filed work
		dir := t.TempDir()
		writer := newTestFindingWriter(t, dir)
		candidates := NewCandidatePool()
		c1 := candidates.Add(AddInput{
			WorkerID: 1, Title: "Late drain finding",
			Severity: "high", Endpoint: "GET /late",
		})

		decisions := NewDecisionQueue()
		boom := errors.New("simulated drain error")
		verifier := &agent.FakeAgent{
			Turns:  []agent.TurnSummary{{}, {}},
			Errors: []error{boom, boom},
		}
		var drained int
		verifier.OnDrain = func(_ int) {
			drained++
			if drained == 1 {
				decisions.AddFinding(FindingFiled{
					Title: "Late drain finding", Severity: "high",
					Endpoint:               "GET /late",
					VerificationNotes:      "ok",
					SupersedesCandidateIDs: []string{c1},
				})
			}
		}

		summary := RunVerificationPhase(
			t.Context(), verifier, decisions, candidates, writer, nil, nil,
		)

		assert.Contains(t, summary, "1 filed")
		assert.Equal(t, "verified", candidates.ByID(c1).Status)
		assert.Empty(t, candidates.Pending())
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
		require.NoError(t, err)
		assert.Contains(t, string(body), "Late drain finding")
	})

	t.Run("llm_wedge_leaves_candidate_pending", func(t *testing.T) {
		// Pure LLM-side wedge (drain errors twice). The next iteration's fresh-compose gives it a clean shot.
		writer := newTestFindingWriter(t, t.TempDir())
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
