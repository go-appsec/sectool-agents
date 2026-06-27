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
}

type fakeMergeCall struct {
	primary, secondary FindingFiled
}

func (r *fakeReviewer) Classify(context.Context, FindingFiled, FindingFiled) (DedupVerdict, error) {
	return DedupVerdict{Action: "unique"}, nil
}

func (r *fakeReviewer) Merge(_ context.Context, primary, secondary FindingFiled) (FindingFiled, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.merges = append(r.merges, fakeMergeCall{primary, secondary})
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
		writer := NewFindingWriter(t.TempDir())
		path, err := writer.Write(FindingFiled{
			Title: "OAuth client enum", Severity: "medium", Endpoint: "GET /oauth2/authorize",
			Description: "Existing notes.",
		})
		require.NoError(t, err)
		filename := filepath.Base(path)

		rev := &fakeReviewer{}
		m := newAsyncMerger(t.Context(), rev, writer, nil, 2)

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

	t.Run("logs_target_missing", func(t *testing.T) {
		writer := NewFindingWriter(t.TempDir())
		rev := &fakeReviewer{}
		log, path, _ := newCapturedLogger(t)

		m := newAsyncMerger(t.Context(), rev, writer, log, 1)
		m.Submit("does-not-exist.md", AddInput{Title: "x", Severity: "low", Endpoint: "GET /"})
		m.Wait()
		require.NoError(t, log.Close())

		assert.Empty(t, rev.merges)
		logged := mustReadFile(t, path)
		assert.Contains(t, logged, "async-merge target missing")
	})

	t.Run("logs_classify_error", func(t *testing.T) {
		writer := NewFindingWriter(t.TempDir())
		p, err := writer.Write(FindingFiled{
			Title: "T", Severity: "low", Endpoint: "GET /",
		})
		require.NoError(t, err)
		rev := &fakeReviewer{mergeErr: errors.New("boom")}
		log, lpath, _ := newCapturedLogger(t)

		m := newAsyncMerger(t.Context(), rev, writer, log, 1)
		m.Submit(filepath.Base(p), AddInput{Title: "y", Severity: "low", Endpoint: "GET /"})
		m.Wait()
		require.NoError(t, log.Close())

		logged := mustReadFile(t, lpath)
		assert.Contains(t, logged, "async-merge error")
	})

	t.Run("concurrent_merges_preserve_all", func(t *testing.T) {
		writer := NewFindingWriter(t.TempDir())
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
		writer := NewFindingWriter(t.TempDir())
		for i := range 3 {
			_, err := writer.Write(FindingFiled{
				Title: "F" + string(rune('A'+i)), Severity: "low", Endpoint: "GET /",
			})
			require.NoError(t, err)
		}
		rev := &fakeReviewer{}
		m := newAsyncMerger(t.Context(), rev, writer, nil, 1)

		digests := writer.Digests()
		for _, d := range digests {
			m.Submit(d.Filename, AddInput{Title: "extra", Severity: "low", Endpoint: "GET /"})
		}
		m.Wait()

		rev.mu.Lock()
		assert.Len(t, rev.merges, 3, "Wait must block until every submitted merge completes")
		rev.mu.Unlock()
	})

	t.Run("canceled_context_skips", func(t *testing.T) {
		writer := NewFindingWriter(t.TempDir())
		p, err := writer.Write(FindingFiled{
			Title: "T", Severity: "low", Endpoint: "GET /",
		})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // pre-cancel

		rev := &fakeReviewer{}
		m := newAsyncMerger(ctx, rev, writer, nil, 1)
		m.Submit(filepath.Base(p), AddInput{Title: "y"})
		m.Wait()

		rev.mu.Lock()
		defer rev.mu.Unlock()
		// Goroutine hits ctx.Done in the semaphore acquire and returns without touching the reviewer
		// May or may not have entered runOne, assert that it did NOT issue a merge
		assert.Empty(t, rev.merges)
	})

	t.Run("nil_receiver_safe", func(t *testing.T) {
		var m *asyncMerger
		m.Submit("x", AddInput{}) // must not panic
		m.Wait()                  // must not panic
	})
}
