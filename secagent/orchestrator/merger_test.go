package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeReviewer satisfies DedupReviewer for asyncMerger tests. Records the merge calls; Classify is unused here.
type fakeReviewer struct {
	mu       sync.Mutex
	merges   []fakeMergeCall
	mergeErr error
	merged   FindingFiled
	// block, when set, makes Merge wait until closed after recording the call.
	block chan struct{}
}

type fakeMergeCall struct {
	primary, secondary FindingFiled
}

func (r *fakeReviewer) Classify(context.Context, FindingFiled, FindingFiled) (DedupVerdict, error) {
	return DedupVerdict{Action: "unique"}, nil
}

func (r *fakeReviewer) Merge(_ context.Context, primary, secondary FindingFiled) (FindingFiled, error) {
	r.mu.Lock()
	r.merges = append(r.merges, fakeMergeCall{primary, secondary})
	r.mu.Unlock()
	if r.block != nil {
		<-r.block
	}
	if r.mergeErr != nil {
		return FindingFiled{}, r.mergeErr
	}
	if r.merged.Title != "" {
		return r.merged, nil
	}
	// default: pretend the merger combined both descriptions.
	return FindingFiled{
		Title:       primary.Title,
		Severity:    primary.Severity,
		Endpoint:    primary.Endpoint,
		Description: primary.Description + " | " + secondary.Description,
		Evidence:    primary.Evidence + " + " + secondary.Evidence,
	}, nil
}

func TestAsyncMerger(t *testing.T) {
	t.Parallel()

	t.Run("submit_merges_into_existing", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		path, err := writer.Write(FindingFiled{
			Title: "OAuth client enum", Severity: "medium", Endpoint: "GET /oauth2/authorize",
			Description: "Existing notes.",
		})
		require.NoError(t, err)
		filename := filepath.Base(path)

		rev := &fakeReviewer{}
		m := newAsyncMerger(t.Context(), rev, writer, nil, nil, 2)

		m.Submit(filename, AddInput{
			Title: "OAuth client enum (more)", Severity: "medium", Endpoint: "GET /oauth2/authorize",
			Summary: "Discovered additional client_ids", EvidenceNotes: "tested 5 IDs",
		})
		m.Wait()

		rev.mu.Lock()
		require.Len(t, rev.merges, 1)
		assert.Equal(t, "OAuth client enum", rev.merges[0].primary.Title)
		assert.Equal(t, "tested 5 IDs", rev.merges[0].secondary.Evidence)
		rev.mu.Unlock()

		body, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(body), "Existing notes.")
		assert.Contains(t, string(body), "tested 5 IDs")
	})

	t.Run("target_missing_preserves_evidence", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		rev := &fakeReviewer{}
		log, path, _ := newCapturedLogger(t)
		candidates := NewCandidatePool()

		m := newAsyncMerger(t.Context(), rev, writer, candidates, log, 1)
		m.Submit("does-not-exist.md", AddInput{Title: "x", Severity: "low", Endpoint: "GET /"})
		m.Wait()
		require.NoError(t, log.Close())

		assert.Empty(t, rev.merges)
		logged := mustReadFile(t, path)
		assert.Contains(t, logged, "async-merge target missing")
		assert.Contains(t, logged, "async-merge evidence preserved")
		pending := candidates.Pending()
		require.Len(t, pending, 1)
		assert.Equal(t, "x", pending[0].Title)
	})

	t.Run("stale_filename_resolves_by_seq", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		path, err := writer.Write(FindingFiled{
			Title: "OAuth client enum", Severity: "medium", Endpoint: "GET /oauth2/authorize",
		})
		require.NoError(t, err)
		stale := filepath.Base(path)

		// rename via merge so the snapshot filename no longer resolves
		_, err = writer.MergeExisting(path, func(existing FindingFiled) (FindingFiled, error) {
			existing.Title = "OAuth client enumeration"
			return existing, nil
		})
		require.NoError(t, err)

		rev := &fakeReviewer{}
		m := newAsyncMerger(t.Context(), rev, writer, nil, nil, 1)
		m.Submit(stale, AddInput{Title: "more", Severity: "medium", Endpoint: "GET /oauth2/authorize"})
		m.Wait()

		rev.mu.Lock()
		require.Len(t, rev.merges, 1)
		assert.Equal(t, "OAuth client enumeration", rev.merges[0].primary.Title)
		rev.mu.Unlock()
	})

	t.Run("logs_classify_error", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		p, err := writer.Write(FindingFiled{
			Title: "T", Severity: "low", Endpoint: "GET /",
		})
		require.NoError(t, err)
		rev := &fakeReviewer{mergeErr: errors.New("boom")}
		log, lpath, _ := newCapturedLogger(t)
		candidates := NewCandidatePool()

		m := newAsyncMerger(t.Context(), rev, writer, candidates, log, 1)
		m.Submit(filepath.Base(p), AddInput{Title: "y", Severity: "low", Endpoint: "GET /"})
		m.Wait()
		require.NoError(t, log.Close())

		logged := mustReadFile(t, lpath)
		assert.Contains(t, logged, "async-merge error")
		pending := candidates.Pending()
		require.Len(t, pending, 1)
		assert.Equal(t, "y", pending[0].Title)
	})

	t.Run("concurrent_merges_preserve_all", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		path, err := writer.Write(FindingFiled{
			Title: "Base", Severity: "low", Endpoint: "GET /x", Evidence: "base",
		})
		require.NoError(t, err)

		rev := &fakeReviewer{}
		var wg sync.WaitGroup
		for i := range 4 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				secondary := FindingFiled{Evidence: fmt.Sprintf("ev%d", i)}
				_, merr := writer.MergeExisting(path, func(existing FindingFiled) (FindingFiled, error) {
					return rev.Merge(context.Background(), existing, secondary)
				})
				assert.NoError(t, merr)
			}(i)
		}
		wg.Wait()

		body := mustReadFile(t, path)
		assert.Contains(t, body, "base")
		for i := range 4 {
			assert.Contains(t, body, fmt.Sprintf("ev%d", i))
		}
	})

	t.Run("wait_blocks_on_submits", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		for i := range 3 {
			_, err := writer.Write(FindingFiled{
				Title: "F" + string(rune('A'+i)), Severity: "low", Endpoint: "GET /",
			})
			require.NoError(t, err)
		}
		rev := &fakeReviewer{}
		m := newAsyncMerger(t.Context(), rev, writer, nil, nil, 1)

		digests := writer.Digests()
		for _, d := range digests {
			m.Submit(d.Filename, AddInput{Title: "extra", Severity: "low", Endpoint: "GET /"})
		}
		m.Wait()

		rev.mu.Lock()
		assert.Len(t, rev.merges, 3, "Wait must block until every submitted merge completes")
		rev.mu.Unlock()
	})

	t.Run("backlog_full_fails_fast", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		path, err := writer.Write(FindingFiled{
			Title: "T", Severity: "low", Endpoint: "GET /",
		})
		require.NoError(t, err)
		rev := &fakeReviewer{block: make(chan struct{})}
		candidates := NewCandidatePool()
		log, lpath, _ := newCapturedLogger(t)
		m := newAsyncMerger(t.Context(), rev, writer, candidates, log, 1)

		// the blocked reviewer pins pending at the cap; the next submit is rejected
		for range maxPendingMerges {
			m.Submit(filepath.Base(path), AddInput{Title: "x", Severity: "low", Endpoint: "GET /"})
		}
		m.Submit(filepath.Base(path), AddInput{Title: "overflow", Severity: "low", Endpoint: "GET /"})
		pending := candidates.Pending()
		require.Len(t, pending, 1)
		assert.Equal(t, "overflow", pending[0].Title)

		close(rev.block)
		m.Wait()
		rev.mu.Lock()
		assert.Len(t, rev.merges, maxPendingMerges)
		rev.mu.Unlock()
		require.NoError(t, log.Close())
		assert.Contains(t, mustReadFile(t, lpath), "merger backlog full")
	})

	t.Run("canceled_context_skips", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		p, err := writer.Write(FindingFiled{
			Title: "T", Severity: "low", Endpoint: "GET /",
		})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // pre-cancel

		rev := &fakeReviewer{}
		candidates := NewCandidatePool()
		m := newAsyncMerger(ctx, rev, writer, candidates, nil, 1)
		m.Submit(filepath.Base(p), AddInput{Title: "y"})
		m.Wait()

		rev.mu.Lock()
		defer rev.mu.Unlock()
		// Goroutine hits ctx.Done in the semaphore acquire and returns without touching the reviewer
		// May or may not have entered runOne, assert that it did NOT issue a merge
		assert.Empty(t, rev.merges)
		// but the evidence still landed in the pool
		pending := candidates.Pending()
		require.Len(t, pending, 1)
		assert.Equal(t, "y", pending[0].Title)
	})

	t.Run("nil_receiver_safe", func(t *testing.T) {
		var m *asyncMerger
		m.Submit("x", AddInput{}) // must not panic
		m.Wait()                  // must not panic
	})

	t.Run("wait_quiesces_late_submits", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		path, err := writer.Write(FindingFiled{
			Title: "T", Severity: "low", Endpoint: "GET /",
		})
		require.NoError(t, err)
		rev := &fakeReviewer{}
		candidates := NewCandidatePool()
		m := newAsyncMerger(t.Context(), rev, writer, candidates, nil, 1)
		m.Wait()

		m.Submit(filepath.Base(path), AddInput{Title: "late", Severity: "low", Endpoint: "GET /"})

		rev.mu.Lock()
		assert.Empty(t, rev.merges)
		rev.mu.Unlock()
		pending := candidates.Pending()
		require.Len(t, pending, 1)
		assert.Equal(t, "late", pending[0].Title)
	})

	t.Run("concurrent_wait_and_submit", func(t *testing.T) {
		writer := newTestFindingWriter(t, t.TempDir())
		path, err := writer.Write(FindingFiled{
			Title: "T", Severity: "low", Endpoint: "GET /",
		})
		require.NoError(t, err)
		rev := &fakeReviewer{}
		candidates := NewCandidatePool()
		m := newAsyncMerger(t.Context(), rev, writer, candidates, nil, 1)

		// mimic a straggler tool-handler goroutine racing Wait during shutdown
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				m.Submit(filepath.Base(path), AddInput{Title: "x", Severity: "low", Endpoint: "GET /"})
			}
		}()
		m.Wait()
		wg.Wait()
		m.Wait() // idempotent, must not panic

		rev.mu.Lock()
		merges := len(rev.merges)
		rev.mu.Unlock()
		// every submit either merged or was recovered into the pool
		pending := len(candidates.Pending())
		assert.Equal(t, 50, merges+pending)
	})
}
