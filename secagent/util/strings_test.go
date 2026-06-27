package util

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestTruncate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{name: "empty", in: "", n: 10, want: ""},
		{name: "within_limit", in: "hello", n: 10, want: "hello"},
		{name: "exact_limit", in: "hello", n: 5, want: "hello"},
		{name: "over_limit", in: "hello world", n: 7, want: "hello …"},
		{name: "zero_n", in: "hello", n: 0, want: "…"},
		{name: "trims_whitespace", in: "  hi  ", n: 10, want: "hi"},
		{name: "trims_then_truncates", in: "  hello world  ", n: 7, want: "hello …"},
		{name: "multibyte_rune_boundary", in: "héllo wörld", n: 7, want: "héllo …"},
		{name: "emoji_runes_counted_once", in: "🦀🚀🎉test", n: 4, want: "🦀🚀🎉…"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Truncate(tc.in, tc.n))
		})
	}
}

func TestTruncateBytes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		in       string
		maxBytes int
		want     string
	}{
		{name: "empty", in: "", maxBytes: 10, want: ""},
		{name: "within_limit", in: "hello", maxBytes: 10, want: "hello"},
		{name: "exact_limit", in: "hello", maxBytes: 5, want: "hello"},
		{name: "ascii_cut", in: "hello world", maxBytes: 7, want: "hello w"},
		{name: "zero_max", in: "hello", maxBytes: 0, want: ""},
		{name: "negative_max", in: "hello", maxBytes: -1, want: ""},
		{name: "multibyte_not_split", in: "héllo", maxBytes: 2, want: "h"},
		{name: "multibyte_kept_whole", in: "héllo", maxBytes: 3, want: "hé"},
		{name: "emoji_not_split", in: "🦀x", maxBytes: 2, want: ""},
		{name: "emoji_kept_whole", in: "🦀x", maxBytes: 4, want: "🦀"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := TruncateBytes(tc.in, tc.maxBytes)
			assert.Equal(t, tc.want, got)
			assert.True(t, utf8.ValidString(got))
		})
	}
}

func TestStripCodeFences(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "no_fence", in: "hello world", want: "hello world"},
		{name: "bare_fence_pair", in: "```\nhello\n```", want: "hello"},
		{name: "language_tag", in: "```json\n{\"foo\":\"bar\"}\n```", want: `{"foo":"bar"}`},
		{name: "leading_blanks_fence", in: "\n\n```\nline one\nline two\n```\n", want: "line one\nline two"},
		{name: "leading_only", in: "```md\nprose", want: "prose"},
		{name: "trailing_only", in: "prose\n```", want: "prose"},
		{name: "fence_only", in: "```", want: ""},
		{name: "two_fences_only", in: "```\n```", want: ""},
		{name: "inline_backticks_untouched", in: "the `foo` bar", want: "the `foo` bar"},
		{name: "opener_trailer_not_stripped", in: "prose\n```json", want: "prose\n```json"},
		{name: "fence_in_body_preserved", in: "intro\n```\ncode\n```\noutro", want: "intro\n```\ncode\n```\noutro"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, StripCodeFences(tc.in))
		})
	}
}

func TestSlugify(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		out  string
	}{
		{"path_and_spaces", "Reflected XSS in /search", "reflected-xss-in-search"},
		{"extra_whitespace", "  Hello   World!  ", "hello-world"},
		{"underscore_equals_hyphen", "plaintext client_secret exposure", "plaintext-client-secret-exposure"},
		{"hyphen_equivalence", "plaintext client-secret exposure", "plaintext-client-secret-exposure"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.out, Slugify(c.in))
		})
	}
}
