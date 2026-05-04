package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripThinkBlocks(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "no_think", in: "hello", want: "hello"},
		{name: "think_lower", in: "a<think>hidden</think>b", want: "ab"},
		{name: "think_upper", in: "a<THINK>hidden</THINK>b", want: "ab"},
		{name: "multiline", in: "a<think>line1\nline2</think>b", want: "ab"},
		{name: "thinking_tag", in: "a<thinking>x</thinking>b", want: "ab"},
		{name: "reasoning_tag", in: "a<reasoning>x</reasoning>b", want: "ab"},
		{name: "pipe_tag", in: "a<|thinking|>x<|/thinking|>b", want: "ab"},
		{name: "two_blocks", in: "a<think>x</think>b<think>y</think>c", want: "abc"},
		{name: "unclosed_left_intact", in: "a<think>truncated", want: "a<think>truncated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, StripThinkBlocks(tc.in))
		})
	}
}

func TestFilterThinkBlocks(t *testing.T) {
	t.Parallel()

	build := func() []Message {
		return []Message{
			{Role: RoleSystem, Content: "sys"},
			{Role: RoleUser, Content: "assignment"},
			{Role: RoleAssistant, Content: "<think>turn1</think>done1"},
			{Role: RoleTool, Content: "<think>not-stripped-in-tools</think>payload", ToolCallID: "c1"},
			{Role: RoleAssistant, Content: "<think>turn2</think>done2"},
			{Role: RoleAssistant, Content: "<think>turn3</think>done3"},
		}
	}

	cases := []struct {
		name           string
		keepLastN      int
		wantAssistants []string
	}{
		{name: "keep_all", keepLastN: 10, wantAssistants: []string{
			"<think>turn1</think>done1",
			"<think>turn2</think>done2",
			"<think>turn3</think>done3",
		}},
		{name: "keep_two", keepLastN: 2, wantAssistants: []string{
			"done1",
			"<think>turn2</think>done2",
			"<think>turn3</think>done3",
		}},
		{name: "keep_zero", keepLastN: 0, wantAssistants: []string{
			"done1", "done2", "done3",
		}},
		{name: "negative_keeps_none", keepLastN: -3, wantAssistants: []string{
			"done1", "done2", "done3",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := FilterThinkBlocks(build(), tc.keepLastN)
			var assistants []string
			for _, m := range msgs {
				if m.Role == RoleAssistant {
					assistants = append(assistants, m.Content)
				}
			}
			assert.Equal(t, tc.wantAssistants, assistants)
			// Non-assistant roles must pass through untouched
			assert.Equal(t, "sys", msgs[0].Content)
			assert.Equal(t, "assignment", msgs[1].Content)
			assert.Equal(t, "<think>not-stripped-in-tools</think>payload", msgs[3].Content)
		})
	}

	t.Run("nil_safe", func(t *testing.T) {
		assert.Nil(t, FilterThinkBlocks(nil, 2))
	})

	t.Run("empty_safe", func(t *testing.T) {
		assert.Empty(t, FilterThinkBlocks([]Message{}, 2))
	})

	t.Run("returns_copy", func(t *testing.T) {
		orig := build()
		_ = FilterThinkBlocks(orig, 0)
		assert.Equal(t, "<think>turn1</think>done1", orig[2].Content)
	})
}

func TestTruncatedThinkTail(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("word ", 200)
	prefixA := strings.Repeat("a ", 200)

	cases := []struct {
		name string
		in   string
		want string // exact value, or empty to use checks
	}{
		{name: "closed_block_empty", in: "<think>planning</think>done", want: ""},
		{name: "no_tag_empty", in: "just a normal response", want: ""},
		{name: "empty_input_empty", in: "", want: ""},
		{name: "unclosed_think", in: "<think>I am investigating the login flow", want: "I am investigating the login flow"},
		{name: "unclosed_thinking", in: "<thinking>checking JWT kid confusion", want: "checking JWT kid confusion"},
		{name: "case_insensitive_tag", in: "<THINK>reviewing endpoints", want: "reviewing endpoints"},
		{name: "later_unclosed_wins", in: "<think>first closed thought</think>some text<think>second unclosed thought", want: "second unclosed thought"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, TruncatedThinkTail(tc.in))
		})
	}

	t.Run("long_tail_ellipsis_prefix", func(t *testing.T) {
		got := TruncatedThinkTail("<think>" + long)
		assert.True(t, strings.HasPrefix(got, "…"))
		assert.Less(t, len(got), len(long))
	})

	t.Run("collapses_newlines", func(t *testing.T) {
		got := TruncatedThinkTail("<think>line one\n\nline two\n  line three")
		assert.NotContains(t, got, "\n")
		assert.Contains(t, got, "line one")
		assert.Contains(t, got, "line three")
	})

	t.Run("prefers_sentence_start", func(t *testing.T) {
		got := TruncatedThinkTail("<think>" + prefixA + "An earlier sentence. The latest thought is about OAuth.")
		assert.Contains(t, got, "The latest thought is about OAuth.")
	})
}

func TestHasLeadingThinkOpen(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "think_lower", in: "<think>x", want: true},
		{name: "think_upper", in: "<THINK>x", want: true},
		{name: "thinking", in: "<thinking>x", want: true},
		{name: "pipe_thinking", in: "<|thinking|>x", want: true},
		{name: "reasoning", in: "<reasoning>x", want: true},
		{name: "leading_whitespace", in: "  \n<think>x", want: true},
		{name: "no_tag", in: "plain text", want: false},
		{name: "empty", in: "", want: false},
		{name: "tag_in_middle", in: "prefix <think>x", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, HasLeadingThinkOpen(tc.in))
		})
	}
}

func TestHasInlineThink(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "balanced_think", in: "a<think>x</think>b", want: true},
		{name: "balanced_thinking", in: "<thinking>x</thinking>", want: true},
		{name: "balanced_pipe", in: "<|thinking|>x<|/thinking|>", want: true},
		{name: "balanced_reasoning", in: "<reasoning>x</reasoning>", want: true},
		{name: "unclosed", in: "<think>truncated", want: false},
		{name: "stray_brackets", in: "1 < 2 and 3 > 0", want: false},
		{name: "empty", in: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, HasInlineThink(tc.in))
		})
	}
}
