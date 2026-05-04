package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalEndpoint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		out  string
	}{
		{"method_and_numeric_id", "GET /users/123", "/users/:id"},
		{"trailing_slash_and_query", "POST /api/v1/items/?x=1", "/api/v1/items"},
		{"uppercase_path", "/Users/42", "/users/:id"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.out, CanonicalEndpoint(c.in))
		})
	}
}

func TestTitlesSimilar(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"case_insensitive", "Reflected XSS in search", "reflected xss in search", true},
		{"prefix_substring", "Reflected XSS", "Reflected XSS in login flow", true},
		{"different_vulns", "SQL Injection", "Reflected XSS", false},
		{
			"cors_near_duplicate",
			"Wildcard CORS Enables Cross-Origin Token Status Enumeration and Response Leakage",
			"Wildcard CORS Enables Cross-OAuth Response Leakage at Token and Introspection Endpoints",
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, TitlesSimilar(c.a, c.b))
		})
	}
}

func TestParseFindingMarkdown(t *testing.T) {
	t.Parallel()

	full := FindingFiled{
		Title:             "Reflected XSS in /search",
		Severity:          "high",
		Endpoint:          "GET /search",
		Description:       "User input from `q` is echoed unencoded.",
		ReproductionSteps: "1. GET /search?q=<script>\n2. Observe reflected payload",
		Evidence:          "Response body contains `<script>` verbatim.",
		Impact:            "Attacker-controlled JS in victim browser.",
		VerificationNotes: "Verifier reproduced via curl.",
	}

	t.Run("round_trips_all_fields", func(t *testing.T) {
		got, ok := parseFindingMarkdown(renderFinding(full))
		require.True(t, ok)
		assert.Equal(t, full, got)
	})

	t.Run("na_endpoint_normalized_to_empty", func(t *testing.T) {
		// "N/A" on disk must round-trip back to "" so dedup keys match
		blank := full
		blank.Endpoint = ""
		got, ok := parseFindingMarkdown(renderFinding(blank))
		require.True(t, ok)
		assert.Empty(t, got.Endpoint)
	})

	t.Run("missing_title_header_returns_false", func(t *testing.T) {
		_, ok := parseFindingMarkdown("not a finding\n\nsome content")
		assert.False(t, ok)
	})

	t.Run("disk_round_trip_seeds_dedup_index", func(t *testing.T) {
		// Guards against silent dedup loss across process restart
		dir := t.TempDir()
		w := NewFindingWriter(dir)
		_, err := w.Write(full)
		require.NoError(t, err)

		w2 := NewFindingWriter(dir)
		assert.True(t, w2.IsDuplicate(full))
	})
}

func TestFindingWriterIsDuplicate(t *testing.T) {
	t.Parallel()
	finding := FindingFiled{
		Title:             "Reflected XSS",
		Severity:          "high",
		Endpoint:          "GET /search",
		Description:       "body",
		ReproductionSteps: "steps",
		Evidence:          "evidence",
		Impact:            "impact",
		VerificationNotes: "notes",
	}

	t.Run("detects_duplicate", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(finding)
		require.NoError(t, err)
		assert.True(t, w.IsDuplicate(finding))
	})

	t.Run("different_title_not_duplicate", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(finding)
		require.NoError(t, err)
		other := finding
		other.Title = "Completely Different Thing"
		assert.False(t, w.IsDuplicate(other))
	})

	t.Run("underscore_vs_hyphen_client_secret", func(t *testing.T) {
		// Regression: underscore/hyphen punctuation must collapse to same slug
		first := FindingFiled{
			Title:    "Plaintext client_secret Exposure in OAuth2 Registration Response",
			Severity: "high",
			Endpoint: "POST /oauth2/register",
		}
		second := FindingFiled{
			Title:    "Plaintext Client Secret Exposure in OAuth2 Registration Response",
			Severity: "high",
			Endpoint: "POST /oauth2/register",
		}
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(first)
		require.NoError(t, err)
		assert.True(t, w.IsDuplicate(second))
	})

	t.Run("same_title_missing_endpoint_not_duplicate", func(t *testing.T) {
		// Endpoint divergence (one side empty) is not treated as duplicate here
		// it falls through to FindSimilarEntries so the LLM reviewer can decide
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(finding)
		require.NoError(t, err)
		other := finding
		other.Endpoint = ""
		assert.False(t, w.IsDuplicate(other))
	})

	t.Run("same_title_different_endpoint_not_duplicate", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(finding)
		require.NoError(t, err)
		other := finding
		other.Endpoint = "GET /login"
		assert.False(t, w.IsDuplicate(other))
	})

	t.Run("similar_title_not_exact_slug_not_duplicate", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(finding)
		require.NoError(t, err)
		other := FindingFiled{
			Title:    "Reflected XSS in login flow",
			Severity: "high",
			Endpoint: "GET /login",
		}
		assert.False(t, w.IsDuplicate(other))
	})
}

func TestFindSimilarEntries(t *testing.T) {
	t.Parallel()

	w := NewFindingWriter(t.TempDir())
	_, err := w.Write(FindingFiled{
		Title: "Reflected XSS in search", Severity: "high", Endpoint: "GET /search",
	})
	require.NoError(t, err)

	t.Run("exact_slug_surfaced", func(t *testing.T) {
		// FindSimilarEntries no longer dedupes exact matches, that's the
		// upstream IsDuplicate's job. Slug match always surfaces here so
		// the LLM reviewer adjudicates if IsDuplicate didn't short-circuit.
		got := w.FindSimilarEntries(FindingFiled{Title: "Reflected XSS in search", Endpoint: "GET /search"})
		require.Len(t, got, 1)
	})

	t.Run("same_slug_different_endpoint_surfaced", func(t *testing.T) {
		got := w.FindSimilarEntries(FindingFiled{Title: "Reflected XSS in search", Endpoint: "GET /admin"})
		require.Len(t, got, 1)
		assert.Equal(t, "Reflected XSS in search", got[0].Filed.Title)
	})

	t.Run("similar_title_missing_endpoint", func(t *testing.T) {
		got := w.FindSimilarEntries(FindingFiled{Title: "Reflected XSS", Endpoint: ""})
		require.Len(t, got, 1)
		assert.Equal(t, "Reflected XSS in search", got[0].Filed.Title)
	})

	t.Run("similar_title_explicit_different_endpoint", func(t *testing.T) {
		got := w.FindSimilarEntries(FindingFiled{Title: "Reflected XSS in login", Endpoint: "GET /login"})
		require.Len(t, got, 1)
		assert.Equal(t, "Reflected XSS in search", got[0].Filed.Title)
	})

	t.Run("different_title_no_match", func(t *testing.T) {
		got := w.FindSimilarEntries(FindingFiled{Title: "SQL Injection", Endpoint: "GET /search"})
		assert.Empty(t, got)
	})
}

func TestFindingWriterReplace(t *testing.T) {
	t.Parallel()

	t.Run("preserves_sequence_renames_on_title_change", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		p1, err := w.Write(FindingFiled{Title: "Original Title", Severity: "low", Endpoint: "GET /"})
		require.NoError(t, err)

		p2, err := w.Replace(p1, FindingFiled{Title: "Merged Title", Severity: "high", Endpoint: "GET /x"})
		require.NoError(t, err)
		assert.NotEqual(t, p1, p2, "rename on slug change")
		assert.Contains(t, filepath.Base(p2), "finding-01-")
		_, err = os.Stat(p1)
		assert.True(t, os.IsNotExist(err))
		body, err := os.ReadFile(p2)
		require.NoError(t, err)
		assert.Contains(t, string(body), "Merged Title")
	})

	t.Run("same_title_writes_in_place", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		p1, err := w.Write(FindingFiled{Title: "Same", Severity: "low", Endpoint: "GET /"})
		require.NoError(t, err)
		p2, err := w.Replace(p1, FindingFiled{Title: "Same", Severity: "high", Endpoint: "GET /"})
		require.NoError(t, err)
		assert.Equal(t, p1, p2)
	})

	t.Run("untracked_path_errors", func(t *testing.T) {
		dir := t.TempDir()
		w := NewFindingWriter(dir)
		_, err := w.Replace(filepath.Join(dir, "finding-01-nope.md"), FindingFiled{Title: "x"})
		assert.Error(t, err)
	})
}

func TestFindingWriterMatchesFiled(t *testing.T) {
	t.Parallel()

	seed := FindingFiled{
		Title:    "Reflected XSS in search",
		Severity: "high",
		Endpoint: "GET /search",
	}

	t.Run("exact_slug_match", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(seed)
		require.NoError(t, err)
		title, path, ok := w.MatchesFiled("Reflected XSS in search", "GET /search")
		assert.True(t, ok)
		assert.Equal(t, seed.Title, title)
		assert.NotEmpty(t, path)
	})

	t.Run("endpoint_plus_similar_title_miss", func(t *testing.T) {
		// Fuzzy title match no longer satisfies the deterministic fallback,
		// it routes to the LLM CandidateDedupReviewer instead.
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(seed)
		require.NoError(t, err)
		_, _, ok := w.MatchesFiled("Reflected XSS in search endpoint", "GET /search")
		assert.False(t, ok)
	})

	t.Run("same_title_different_endpoint_miss", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(seed)
		require.NoError(t, err)
		_, _, ok := w.MatchesFiled("Reflected XSS in search", "GET /admin")
		assert.False(t, ok)
	})

	t.Run("distinct_title_and_endpoint_miss", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(seed)
		require.NoError(t, err)
		_, _, ok := w.MatchesFiled("SQL Injection in login", "POST /login")
		assert.False(t, ok)
	})

	t.Run("endpoint_equal_but_unrelated_title_miss", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(seed)
		require.NoError(t, err)
		_, _, ok := w.MatchesFiled("Open Redirect via return_to", "GET /search")
		assert.False(t, ok)
	})
}

func TestFindingWriterSummaryForWorker(t *testing.T) {
	t.Parallel()

	t.Run("empty_returns_empty_string", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		assert.Empty(t, w.SummaryForWorker())
	})

	t.Run("lists_titles_and_endpoints_without_severity", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())
		_, err := w.Write(FindingFiled{
			Title: "Reflected XSS", Severity: "critical", Endpoint: "GET /search",
		})
		require.NoError(t, err)
		_, err = w.Write(FindingFiled{
			Title: "Open Redirect", Severity: "high", Endpoint: "GET /go",
		})
		require.NoError(t, err)

		out := w.SummaryForWorker()
		assert.Contains(t, out, "Reflected XSS")
		assert.Contains(t, out, "GET /search")
		assert.Contains(t, out, "Open Redirect")
		assert.Contains(t, out, "do not re-file")
		// severity omitted to keep worker from arguing with verifier
		assert.NotContains(t, out, "critical")
		assert.NotContains(t, out, "high")
	})
}

func TestNewFindingWriter(t *testing.T) {
	t.Parallel()

	t.Run("seeds_count_from_existing_files", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"finding-03-foo.md", "finding-07-bar.md", "unrelated.md"} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644))
		}
		w := NewFindingWriter(dir)
		assert.Equal(t, 7, w.Count)
		assert.Equal(t, 0, w.RunCount, "RunCount must not be seeded from disk")

		path, err := w.Write(FindingFiled{Title: "New Finding", Severity: "low", Endpoint: "GET /"})
		require.NoError(t, err)
		assert.Equal(t, "finding-08-new-finding.md", filepath.Base(path))
		assert.Equal(t, 8, w.Count)
		assert.Equal(t, 1, w.RunCount, "RunCount increments only on in-process Write")
	})

	t.Run("missing_dir_starts_at_zero", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "does-not-exist")
		w := NewFindingWriter(dir)
		assert.Equal(t, 0, w.Count)

		path, err := w.Write(FindingFiled{Title: "First", Severity: "low", Endpoint: "GET /"})
		require.NoError(t, err)
		assert.Equal(t, "finding-01-first.md", filepath.Base(path))
	})

	t.Run("ignores_malformed_names", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"finding-ab-x.md", "finding-.md", "other.md"} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644))
		}
		assert.Equal(t, 0, NewFindingWriter(dir).Count)
	})
}

func TestMatchPendingCandidates(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		filed   FindingFiled
		pending []FindingCandidate
		want    []string
	}{
		{
			"matches_similar_title_same_endpoint",
			FindingFiled{Title: "Reflected XSS in search", Endpoint: "GET /search"},
			[]FindingCandidate{
				{CandidateID: "c001", Title: "Reflected XSS in search param", Endpoint: "GET /search"},
				{CandidateID: "c002", Title: "SQL Injection", Endpoint: "POST /api/x"},
			},
			[]string{"c001"},
		},
		{
			"matches_multiple_pending",
			FindingFiled{Title: "Reflected XSS in search", Endpoint: "GET /search"},
			[]FindingCandidate{
				{CandidateID: "c001", Title: "Reflected XSS in search param", Endpoint: "GET /search"},
				{CandidateID: "c002", Title: "Reflected XSS in search area", Endpoint: "GET /search"},
			},
			[]string{"c001", "c002"},
		},
		{
			"different_endpoint_title_tier_matches",
			FindingFiled{Title: "Reflected XSS in search", Endpoint: "GET /search"},
			[]FindingCandidate{
				{CandidateID: "c001", Title: "Reflected XSS in search", Endpoint: "GET /other"},
			},
			[]string{"c001"},
		},
		{
			"truly_unrelated_no_match",
			FindingFiled{Title: "Reflected XSS in search", Endpoint: "GET /search"},
			[]FindingCandidate{
				{CandidateID: "c001", Title: "SQL Injection", Endpoint: "POST /api/x"},
			},
			nil,
		},
		{
			"missing_filed_title_falls_back_to_endpoint",
			FindingFiled{Title: "", Endpoint: "GET /search"},
			[]FindingCandidate{{CandidateID: "c001", Title: "anything", Endpoint: "GET /search"}},
			[]string{"c001"},
		},
		{
			"missing_filed_endpoint_falls_back_to_title",
			FindingFiled{Title: "Reflected XSS", Endpoint: ""},
			[]FindingCandidate{{CandidateID: "c001", Title: "Reflected XSS", Endpoint: "GET /search"}},
			[]string{"c001"},
		},
		{
			"both_empty_returns_nil",
			FindingFiled{Title: "", Endpoint: ""},
			[]FindingCandidate{{CandidateID: "c001", Title: "x", Endpoint: "GET /x"}},
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, MatchPendingCandidates(c.filed, c.pending))
		})
	}
}

func TestMatchPendingCandidatesTiered(t *testing.T) {
	t.Parallel()

	pending := []FindingCandidate{
		{CandidateID: "c001", Title: "Standard User Session Cookie Reuse on Admin API", Endpoint: "GET /admin/api/settings"},
	}

	t.Run("title_plus_endpoint_wins_strict", func(t *testing.T) {
		ids, tier := MatchPendingCandidatesTiered(FindingFiled{
			Title:    "Standard User Session Cookie Reuse on Admin API Endpoints",
			Endpoint: "GET /admin/api/settings",
		}, pending)
		assert.Equal(t, []string{"c001"}, ids)
		assert.Equal(t, MatchTitleAndEndpoint, tier)
	})

	t.Run("endpoint_only_when_title_diverged", func(t *testing.T) {
		ids, tier := MatchPendingCandidatesTiered(FindingFiled{
			Title:    "Admin API Endpoints Require JWT Bearer Auth",
			Endpoint: "GET /admin/api/settings",
		}, pending)
		assert.Equal(t, []string{"c001"}, ids)
		assert.Equal(t, MatchEndpointOnly, tier)
	})

	t.Run("title_only_when_endpoint_absent", func(t *testing.T) {
		ids, tier := MatchPendingCandidatesTiered(FindingFiled{
			Title:    "Standard User Session Cookie Reuse on Admin API",
			Endpoint: "",
		}, pending)
		assert.Equal(t, []string{"c001"}, ids)
		assert.Equal(t, MatchTitleOnly, tier)
	})

	t.Run("no_match_returns_none_tier", func(t *testing.T) {
		ids, tier := MatchPendingCandidatesTiered(FindingFiled{
			Title:    "Totally unrelated vulnerability",
			Endpoint: "POST /different/endpoint",
		}, pending)
		assert.Empty(t, ids)
		assert.Equal(t, MatchNone, tier)
	})
}

func TestFindingWriterWriteUnvalidated(t *testing.T) {
	t.Parallel()

	t.Run("writes_with_unvalidated_prefix_and_banner", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())

		path, err := w.WriteUnvalidated(FindingCandidate{
			CandidateID:      "c001",
			WorkerID:         3,
			Title:            "Reflected XSS in search",
			Severity:         "high",
			Endpoint:         "GET /search",
			FlowIDs:          []string{"f-abc", "f-def"},
			Summary:          "user input echoed unencoded",
			EvidenceNotes:    "<script>alert(1)</script> reflected verbatim",
			ReproductionHint: "send q=<script>",
		})
		require.NoError(t, err)
		assert.Equal(t, "unvalidated-01-reflected-xss-in-search.md", filepath.Base(path))
		assert.Equal(t, 1, w.UnvalidatedCount)
		assert.Equal(t, 0, w.Count, "writing an unvalidated must not bump the verified count")
		assert.Equal(t, 0, w.RunCount, "writing an unvalidated must not bump RunCount")

		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		body := string(raw)
		assert.Contains(t, body, "# UNVALIDATED — Reflected XSS in search")
		assert.Contains(t, body, "**THIS FINDING IS UNVALIDATED.**")
		assert.Contains(t, body, "**Severity (claimed)**: high")
		assert.Contains(t, body, "**Affected Endpoint (claimed)**: GET /search")
		assert.Contains(t, body, "**Originating Worker**: 3")
		assert.Contains(t, body, "**Candidate ID**: c001")
		assert.Contains(t, body, "user input echoed unencoded")
		assert.Contains(t, body, "- f-abc")
		assert.Contains(t, body, "- f-def")
	})

	t.Run("seeds_unvalidated_count_from_existing_files", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{
			"unvalidated-02-old.md", "unvalidated-05-other.md",
			"finding-01-real.md", "unrelated.md",
		} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644))
		}
		w := NewFindingWriter(dir)
		assert.Equal(t, 5, w.UnvalidatedCount)
		assert.Equal(t, 1, w.Count, "finding-01-real.md still bumps Count via filename")

		path, err := w.WriteUnvalidated(FindingCandidate{
			CandidateID: "c042",
			Title:       "Next One",
			Severity:    "low",
			Endpoint:    "GET /x",
		})
		require.NoError(t, err)
		assert.Equal(t, "unvalidated-06-next-one.md", filepath.Base(path))
	})

	t.Run("untitled_fallback", func(t *testing.T) {
		w := NewFindingWriter(t.TempDir())

		path, err := w.WriteUnvalidated(FindingCandidate{CandidateID: "c001"})
		require.NoError(t, err)
		assert.Equal(t, "unvalidated-01-untitled.md", filepath.Base(path))
	})

	t.Run("does_not_pollute_finding_index", func(t *testing.T) {
		dir := t.TempDir()
		w := NewFindingWriter(dir)
		_, err := w.WriteUnvalidated(FindingCandidate{Title: "tip"})
		require.NoError(t, err)

		// A fresh writer over the same dir must NOT see the unvalidated file
		// as a real finding (would otherwise inflate Count and confuse dedup)
		w2 := NewFindingWriter(dir)
		assert.Equal(t, 0, w2.Count)
		assert.Equal(t, 1, w2.UnvalidatedCount)
	})
}
