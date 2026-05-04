package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCanonicalToolName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "single_underscore_typo", in: "mcp_sectool__proxy_poll", want: "mcp_sectool_proxy_poll"},
		{name: "double_underscore_real", in: "mcp__sectool__proxy_poll", want: "mcp_sectool_proxy_poll"},
		{name: "uppercase_normalized", in: "MCP__sectool__X", want: "mcp_sectool_x"},
		{name: "already_canonical", in: "mcp_sectool_proxy_poll", want: "mcp_sectool_proxy_poll"},
		{name: "triple_underscore", in: "mcp___sectool___X", want: "mcp_sectool_x"},
		{name: "leading_trailing_underscore", in: "__foo__", want: "_foo_"},
		{name: "no_underscores", in: "poll", want: "poll"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, canonicalToolName(tc.in))
		})
	}
}

func TestFuzzyContainsToolMatch(t *testing.T) {
	t.Parallel()

	registered := map[string]string{
		"decide_worker":               "decide_worker",
		"mcp_sectool_proxy_poll":      "mcp__sectool__proxy_poll",
		"mcp_sectool_proxy_rule_list": "mcp__sectool__proxy_rule_list",
		"hash":                        "hash",
		"report_finding_candidate":    "report_finding_candidate",
	}

	cases := []struct {
		name string
		req  string
		want string
	}{
		{
			name: "model_added_mcp_prefix",
			req:  "mcp_sectool_decide_worker",
			want: "decide_worker",
		},
		{
			name: "model_stripped_prefix",
			req:  "proxy_poll",
			want: "mcp_sectool_proxy_poll",
		},
		{
			name: "exact_canonical_skipped",
			req:  "decide_worker",
			want: "",
		},
		{
			name: "no_match",
			req:  "totally_unknown_tool",
			want: "",
		},
		{
			name: "non_word_boundary_rejected",
			req:  "rehash_things",
			want: "",
		},
		{
			name: "ambiguous_returns_empty",
			req:  "decide_worker_then_hash",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fuzzyContainsToolMatch(tc.req, registered))
		})
	}
}

func TestWordBoundedContains(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		haystack string
		needle   string
		want     bool
	}{
		{name: "suffix_after_underscore", haystack: "mcp_sectool_decide_worker", needle: "decide_worker", want: true},
		{name: "prefix_before_underscore", haystack: "decide_worker_extra", needle: "decide_worker", want: true},
		{name: "whole_string", haystack: "hash", needle: "hash", want: true},
		{name: "embedded_no_boundary", haystack: "rehash", needle: "hash", want: false},
		{name: "embedded_partial_boundary", haystack: "rehash_things", needle: "hash", want: false},
		{name: "boundary_at_end", haystack: "do_hash", needle: "hash", want: true},
		{name: "needle_longer", haystack: "hash", needle: "hashing", want: false},
		{name: "empty_needle", haystack: "hash", needle: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, wordBoundedContains(tc.haystack, tc.needle))
		})
	}
}
