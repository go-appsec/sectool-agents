package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractMarkedOutput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "no_marker", in: "just plain prose without markers", want: ""},
		{name: "final_picks_sentence", in: "thinking about it... Final: The worker scanned endpoints.", want: "The worker scanned endpoints."},
		{name: "output_case_insensitive", in: "Done. OUTPUT: Investigating OAuth scopes.", want: "Investigating OAuth scopes."},
		{name: "stops_at_newline", in: "Answer: One line of output\n(meta noise)", want: "One line of output"},
		{name: "last_marker_wins", in: "Output: first thought.\nFinal: real answer.", want: "real answer."},
		{name: "drops_parenthetical_noise", in: "Final: The agent just dispatched a request. (16 words) -> foo", want: "The agent just dispatched a request."},
		{name: "response_marker", in: "Let me think... Response: scanning now.", want: "scanning now."},
		{name: "exclamation_terminator", in: "Final: Got it!", want: "Got it!"},
		{name: "question_terminator", in: "Final: Is this right?", want: "Is this right?"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ExtractMarkedOutput(tc.in))
		})
	}
}

func TestExtractProse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain_prose", in: "The worker is scanning OAuth endpoints.", want: "The worker is scanning OAuth endpoints."},
		{name: "strips_think_and_fences", in: "<think>planning</think>```\nworker is scanning OAuth endpoints\n```", want: "worker is scanning OAuth endpoints"},
		// Unclosed think survives the stripper; caller must fall back to Tail.
		{name: "unclosed_think_empty", in: "<think>I was planning to test the OAuth redirect next", want: ""},
		{name: "summary_field", in: `{"summary": "running replay_send"}`, want: "running replay_send"},
		{name: "text_field", in: `{"text": "analyzing response."}`, want: "analyzing response."},
		{name: "summary_beats_status", in: `{"status": "ok", "summary": "probing OAuth scopes"}`, want: "probing OAuth scopes"},
		{name: "alphabetical_fallback", in: `{"z_other": "last-resort value"}`, want: "last-resort value"},
		{name: "empty_object", in: `{}`, want: ""},
		{name: "trims_outer_whitespace", in: "\n{\n  \"summary\": \"the worker tried X\"\n}\n", want: "the worker tried X"},
		{name: "malformed_json_falls_back", in: "{\nunterminated json is noise\nbut this line is prose", want: "unterminated json is noise"},
		{name: "marker_beats_first_line", in: "Thinking about it.\nMatches constraints.\nFinal: The worker just probed /admin/api/clients.", want: "The worker just probed /admin/api/clients."},
		{name: "skips_leading_brace", in: "{\n\"summary\": real answer", want: `"summary": real answer`},
		{name: "skips_leading_quote", in: "\"\nactual prose", want: "actual prose"},
		{name: "skips_leading_fences", in: "```\n```\nbare prose after fences", want: "bare prose after fences"},
		{name: "final_after_meta", in: `(14) -> 14 words. Very concise. Matches all constraints. Output matches.✅ Final: The agent just dispatched another test request and is currently evaluating the network response for security analysis. (16 words) ->`,
			want: "The agent just dispatched another test request and is currently evaluating the network response for security analysis."},
		{name: "json_brace_fallback", in: "{\n  \"summary\": \"Currently investigating residual OIDC state-machines\"\n}", want: "Currently investigating residual OIDC state-machines"},
		{name: "field_priority_status", in: `{"status": "started", "description": "later"}`, want: "started"},
		{name: "field_priority_message", in: `{"message": "first", "text": "later"}`, want: "first"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ExtractProse(tc.in))
		})
	}
}

func TestFirstSentenceOrLine(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "sentence_terminator", in: "one sentence. second sentence.", want: "one sentence."},
		{name: "newline_split", in: "first line\nsecond line", want: "first line"},
		{name: "no_terminator", in: "no terminator", want: "no terminator"},
		{name: "trim_whitespace", in: "   trim whitespace.   ", want: "trim whitespace."},
		{name: "exclamation", in: "shout it!", want: "shout it!"},
		{name: "question", in: "really?", want: "really?"},
		{name: "whitespace_empty", in: "   ", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, firstSentenceOrLine(tc.in))
		})
	}
}

func TestFirstMeaningfulLine(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain_line", in: "plain line", want: "plain line"},
		{name: "brace_skipped", in: "{\nreal content", want: "real content"},
		{name: "punctuation_skipped", in: "\"\n'\n`\n,\nprose", want: "prose"},
		{name: "structural_only", in: strings.Join([]string{"{", "}", "[", "]"}, "\n"), want: ""},
		{name: "fence_skipped", in: "```\nprose inside fence", want: "prose inside fence"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, firstMeaningfulLine(tc.in))
		})
	}
}
