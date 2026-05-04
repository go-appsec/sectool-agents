package orchestrator

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCandidateVerdict(t *testing.T) {
	t.Parallel()

	digests := []FindingDigest{
		{Filename: "finding-01-x.md"},
		{Filename: "finding-02-y.md"},
	}
	cases := []struct {
		name    string
		raw     string
		want    CandidateDedupVerdict
		wantErr bool
	}{
		{"unique", `{"action":"unique"}`, CandidateDedupVerdict{Action: "unique"}, false},
		{
			"duplicate_with_match",
			`{"action":"duplicate","matched_filename":"finding-02-y.md","reason":"same vuln"}`,
			CandidateDedupVerdict{Action: "duplicate", MatchedFilename: "finding-02-y.md", Reason: "same vuln"},
			false,
		},
		{
			"merge_with_match",
			`{"action":"merge","matched_filename":"finding-01-x.md","reason":"adds detail"}`,
			CandidateDedupVerdict{Action: "merge", MatchedFilename: "finding-01-x.md", Reason: "adds detail"},
			false,
		},
		{"duplicate_missing_match", `{"action":"duplicate"}`, CandidateDedupVerdict{}, true},
		{"unknown_filename", `{"action":"merge","matched_filename":"finding-99-z.md"}`, CandidateDedupVerdict{}, true},
		{"unknown_action", `{"action":"absorb"}`, CandidateDedupVerdict{}, true},
		{"malformed_json", `not json`, CandidateDedupVerdict{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseCandidateVerdict(c.raw, digests)
			if c.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestCandidateClassifyPromptIncludesDigests(t *testing.T) {
	t.Parallel()

	digests := []FindingDigest{
		{Filename: "finding-01-foo.md", Title: "Foo", Severity: "high", Endpoint: "GET /foo", FirstLines: "First line\nSecond line"},
		{Filename: "finding-02-bar.md", Title: "Bar", Severity: "low", Endpoint: "POST /bar"},
	}
	in := AddInput{Title: "New thing", Severity: "medium", Endpoint: "GET /new", Summary: "summary"}
	prompt := candidateClassifyPrompt(in, digests)
	assert.Contains(t, prompt, "finding-01-foo.md")
	assert.Contains(t, prompt, "Title: New thing")
	assert.Contains(t, prompt, "First line")
	assert.Contains(t, prompt, "Second line")
	assert.Contains(t, prompt, `"action": "unique"`)
	assert.Contains(t, prompt, `"action": "duplicate"`)
	assert.Contains(t, prompt, `"action": "merge"`)
}

// fakeDedupReviewer scripts Classify and Merge for tests.
type fakeDedupReviewer struct {
	classifyFn func(existing, incoming FindingFiled) (DedupVerdict, error)
	mergeFn    func(primary, secondary FindingFiled) (FindingFiled, error)
	merged     []FindingFiled // captures each merge call's primary for assertions
}

func (f *fakeDedupReviewer) Classify(_ context.Context, existing, incoming FindingFiled) (DedupVerdict, error) {
	return f.classifyFn(existing, incoming)
}

func (f *fakeDedupReviewer) Merge(_ context.Context, primary, secondary FindingFiled) (FindingFiled, error) {
	f.merged = append(f.merged, primary)
	return f.mergeFn(primary, secondary)
}

func TestParseVerdict(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		want    DedupVerdict
		wantErr bool
	}{
		{"unique", `{"action":"unique"}`, DedupVerdict{Action: "unique"}, false},
		{"duplicate_keep_existing", `{"action":"duplicate","more_complete":"existing"}`,
			DedupVerdict{Action: "duplicate", MoreComplete: "existing"}, false},
		{"partial_keep_new", `{"action":"partial","more_complete":"new"}`,
			DedupVerdict{Action: "partial", MoreComplete: "new"}, false},
		{"fenced_json", "```json\n{\"action\":\"unique\"}\n```",
			DedupVerdict{Action: "unique"}, false},
		{"leading_prose", "Here's my answer:\n{\"action\":\"unique\"}",
			DedupVerdict{Action: "unique"}, false},
		{"missing_more_complete", `{"action":"duplicate"}`, DedupVerdict{}, true},
		{"unknown_action", `{"action":"maybe"}`, DedupVerdict{}, true},
		{"malformed", `not json`, DedupVerdict{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseVerdict(c.raw)
			if c.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestParseMerge(t *testing.T) {
	t.Parallel()

	fallback := FindingFiled{
		Title:                  "Original",
		Severity:               "high",
		Endpoint:               "GET /",
		SupersedesCandidateIDs: []string{"c1"},
		FollowUpHint:           "look at logs",
	}
	t.Run("happy_path", func(t *testing.T) {
		raw := `{"title":"Merged","severity":"critical","endpoint":"GET /search","description":"d","reproduction_steps":"s","evidence":"e","impact":"i","verification_notes":"v"}`
		got, err := parseMerge(raw, fallback)
		require.NoError(t, err)
		assert.Equal(t, "Merged", got.Title)
		assert.Equal(t, "critical", got.Severity)
		assert.Equal(t, "d", got.Description)
		assert.Equal(t, []string{"c1"}, got.SupersedesCandidateIDs)
		assert.Equal(t, "look at logs", got.FollowUpHint)
	})
	t.Run("partial_fields_preserve_fallback", func(t *testing.T) {
		raw := `{"title":"","severity":"low"}`
		got, err := parseMerge(raw, fallback)
		require.NoError(t, err)
		assert.Equal(t, "Original", got.Title)
		assert.Equal(t, "low", got.Severity)
	})
}

func TestReviewAndWrite(t *testing.T) {
	t.Parallel()

	seed := func(t *testing.T) (*FindingWriter, string) {
		t.Helper()

		w := NewFindingWriter(t.TempDir())
		path, err := w.Write(FindingFiled{
			Title: "Reflected XSS in search", Severity: "high",
			Endpoint: "GET /search", Description: "existing desc",
		})
		require.NoError(t, err)
		return w, path
	}

	t.Run("exact_slug_skips_review", func(t *testing.T) {
		w, _ := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				t.Fatal("classify must not be called for exact slug duplicate")
				return DedupVerdict{}, nil
			},
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w,
			FindingFiled{Title: "Reflected XSS in search", Endpoint: "GET /search"}, nil)
		require.NoError(t, err)
		assert.False(t, wrote)
		assert.Empty(t, path)
	})

	t.Run("no_similar_writes_normally", func(t *testing.T) {
		w, _ := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				t.Fatal("classify must not be called when no similar entries")
				return DedupVerdict{}, nil
			},
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w,
			FindingFiled{Title: "SQL Injection", Endpoint: "POST /api"}, nil)
		require.NoError(t, err)
		assert.True(t, wrote)
		assert.NotEmpty(t, path)
	})

	t.Run("nil_reviewer_falls_through_to_write", func(t *testing.T) {
		w, _ := seed(t)
		wrote, path, err := ReviewAndWrite(t.Context(), nil, w,
			FindingFiled{Title: "Reflected XSS", Endpoint: ""}, nil)
		require.NoError(t, err)
		assert.True(t, wrote)
		assert.NotEmpty(t, path)
	})

	t.Run("verdict_unique_writes_both", func(t *testing.T) {
		w, _ := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				return DedupVerdict{Action: "unique"}, nil
			},
		}
		wrote, _, err := ReviewAndWrite(t.Context(), rev, w,
			FindingFiled{Title: "Reflected XSS in search v2", Endpoint: ""}, nil)
		require.NoError(t, err)
		assert.True(t, wrote)
		assert.Equal(t, 2, w.Count)
	})

	t.Run("verdict_duplicate_keep_existing_discards_new", func(t *testing.T) {
		w, existingPath := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				return DedupVerdict{Action: "duplicate", MoreComplete: "existing"}, nil
			},
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w,
			FindingFiled{Title: "Reflected XSS", Endpoint: "", Description: "new desc"}, nil)
		require.NoError(t, err)
		assert.False(t, wrote)
		assert.Equal(t, existingPath, path)
		assert.Equal(t, 1, w.Count)
	})

	t.Run("verdict_duplicate_keep_new_replaces_existing", func(t *testing.T) {
		w, existingPath := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				return DedupVerdict{Action: "duplicate", MoreComplete: "new"}, nil
			},
		}
		incoming := FindingFiled{
			Title: "Reflected XSS", Severity: "critical",
			Endpoint: "", Description: "more thorough writeup",
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w, incoming, nil)
		require.NoError(t, err)
		assert.False(t, wrote)
		assert.NotEmpty(t, path)
		_, err = os.Stat(existingPath)
		assert.True(t, os.IsNotExist(err))
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(body), "more thorough writeup")
		assert.Equal(t, 1, w.Count)
	})

	t.Run("verdict_partial_merges_and_replaces", func(t *testing.T) {
		w, existingPath := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				return DedupVerdict{Action: "partial", MoreComplete: "existing"}, nil
			},
			mergeFn: func(primary, _ FindingFiled) (FindingFiled, error) {
				out := primary
				out.Description = "merged: " + primary.Description
				return out, nil
			},
		}
		incoming := FindingFiled{
			Title: "Reflected XSS", Endpoint: "", Description: "new pov",
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w, incoming, nil)
		require.NoError(t, err)
		assert.False(t, wrote)
		require.Len(t, rev.merged, 1)
		assert.Equal(t, "Reflected XSS in search", rev.merged[0].Title)
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(body), "merged: existing desc")
		assert.Equal(t, existingPath, path)
	})

	t.Run("classifier_error_falls_through_to_write", func(t *testing.T) {
		w, _ := seed(t)
		rev := &fakeDedupReviewer{
			classifyFn: func(_, _ FindingFiled) (DedupVerdict, error) {
				return DedupVerdict{}, errors.New("model down")
			},
		}
		wrote, path, err := ReviewAndWrite(t.Context(), rev, w,
			FindingFiled{Title: "Reflected XSS", Endpoint: ""}, nil)
		require.NoError(t, err)
		assert.True(t, wrote)
		assert.NotEmpty(t, path)
	})
}
