package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReasoningFormatString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		f    ReasoningFormat
		want string
	}{
		{name: "none", f: ReasoningFormatNone, want: "none"},
		{name: "inline", f: ReasoningFormatInline, want: "inline"},
		{name: "structured", f: ReasoningFormatStructured, want: "structured"},
		{name: "unknown", f: ReasoningFormatUnknown, want: "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.f.String())
		})
	}
}

func TestNewReasoningHandler(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   ReasoningFormat
		want ReasoningFormat
	}{
		{name: "none", in: ReasoningFormatNone, want: ReasoningFormatNone},
		{name: "inline", in: ReasoningFormatInline, want: ReasoningFormatInline},
		{name: "structured", in: ReasoningFormatStructured, want: ReasoningFormatStructured},
		{name: "unknown_maps_inline", in: ReasoningFormatUnknown, want: ReasoningFormatInline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NewReasoningHandler(tc.in).Format())
		})
	}
}

func TestDetectReasoningFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		resp    ChatResponse
		err     error
		want    ReasoningFormat
		wantErr bool
	}{
		{name: "structured", resp: ChatResponse{ReasoningContent: "working through it"}, want: ReasoningFormatStructured},
		{name: "inline", resp: ChatResponse{Content: "<think>reasoning here</think>final answer"}, want: ReasoningFormatInline},
		{name: "none", resp: ChatResponse{Content: "plain prose answer — no thinking shown."}, want: ReasoningFormatNone},
		{name: "probe_error_unknown", err: errors.New("probe failed"), want: ReasoningFormatUnknown, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeChatClient{responses: []ChatResponse{tc.resp}}
			if tc.err != nil {
				client.errors = []error{tc.err}
			}
			f, err := DetectReasoningFormat(t.Context(), client, "m")
			if tc.wantErr {
				require.Error(t, err)
				assert.Equal(t, tc.want, f)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, f)
			require.Len(t, client.calls, 1)
			assert.Contains(t, client.calls[0].Messages[0].Content, "sky is blue")
		})
	}
}

func TestReasoningFormatCache_Resolve(t *testing.T) {
	t.Parallel()

	t.Run("dedups_per_key", func(t *testing.T) {
		client := &fakeChatClient{responses: []ChatResponse{
			{ReasoningContent: "x"},
			{ReasoningContent: "x"},
		}}
		cache := NewReasoningFormatCache()
		var detectCount int
		onDetect := func(ReasoningFormat, time.Duration, error) { detectCount++ }

		f1 := cache.Resolve(t.Context(), client, "u1", "m", onDetect)
		f2 := cache.Resolve(t.Context(), client, "u1", "m", onDetect)
		f3 := cache.Resolve(t.Context(), client, "u2", "m", onDetect)

		assert.Equal(t, ReasoningFormatStructured, f1)
		assert.Equal(t, ReasoningFormatStructured, f2)
		assert.Equal(t, ReasoningFormatStructured, f3)
		assert.Equal(t, 2, detectCount)
	})

	t.Run("caches_error_as_unknown", func(t *testing.T) {
		client := &fakeChatClient{
			responses: []ChatResponse{{}, {}},
			errors:    []error{errors.New("probe failed"), errors.New("should not fire")},
		}
		cache := NewReasoningFormatCache()
		var detectCount int
		onDetect := func(ReasoningFormat, time.Duration, error) { detectCount++ }

		f1 := cache.Resolve(t.Context(), client, "u", "m", onDetect)
		f2 := cache.Resolve(t.Context(), client, "u", "m", onDetect)

		assert.Equal(t, ReasoningFormatUnknown, f1)
		assert.Equal(t, ReasoningFormatUnknown, f2)
		assert.Equal(t, 1, detectCount)
	})

	t.Run("nil_on_detect_safe", func(t *testing.T) {
		client := &fakeChatClient{responses: []ChatResponse{{ReasoningContent: "x"}}}
		cache := NewReasoningFormatCache()
		assert.NotPanics(t, func() {
			cache.Resolve(t.Context(), client, "u", "m", nil)
		})
	})
}

func TestReasoningHandler_Ingest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		format        ReasoningFormat
		resp          ChatResponse
		wantContent   string
		wantReasoning string
	}{
		{name: "inline_drops_reasoning", format: ReasoningFormatInline,
			resp:        ChatResponse{Content: "<think>x</think>answer", ReasoningContent: "ignored"},
			wantContent: "<think>x</think>answer"},
		{name: "structured_splits_fields", format: ReasoningFormatStructured,
			resp:          ChatResponse{Content: "final", ReasoningContent: "my reasoning"},
			wantContent:   "final",
			wantReasoning: "my reasoning"},
		{name: "none_drops_reasoning", format: ReasoningFormatNone,
			resp:        ChatResponse{Content: "hi", ReasoningContent: "ignored"},
			wantContent: "hi"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content, reasoning := NewReasoningHandler(tc.format).Ingest(tc.resp)
			assert.Equal(t, tc.wantContent, content)
			assert.Equal(t, tc.wantReasoning, reasoning)
		})
	}
}

func TestReasoningHandler_Replay(t *testing.T) {
	t.Parallel()

	t.Run("inline_keeps_last_n", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatInline)
		msgs := []Message{
			{Role: RoleSystem, Content: "sys"},
			{Role: RoleAssistant, Content: "<think>turn1</think>done1"},
			{Role: RoleAssistant, Content: "<think>turn2</think>done2"},
			{Role: RoleAssistant, Content: "<think>turn3</think>done3"},
		}
		out := h.Replay(msgs, 1)
		assert.Equal(t, "done1", out[1].Content)
		assert.Equal(t, "done2", out[2].Content)
		assert.Equal(t, "<think>turn3</think>done3", out[3].Content)
	})

	t.Run("structured_blanks_reasoning", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatStructured)
		msgs := []Message{
			{Role: RoleAssistant, Content: "a1", ReasoningContent: "r1"},
			{Role: RoleAssistant, Content: "a2", ReasoningContent: "r2"},
			{Role: RoleAssistant, Content: "a3", ReasoningContent: "r3"},
		}
		for _, keep := range []int{0, 1, 5} {
			out := h.Replay(msgs, keep)
			for i, m := range out {
				assert.Empty(t, m.ReasoningContent)
				assert.Equal(t, msgs[i].Content, m.Content)
			}
		}
		// Replay must clone, not mutate
		assert.Equal(t, "r1", msgs[0].ReasoningContent)
	})

	t.Run("structured_skips_non_assistant", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatStructured)
		msgs := []Message{
			{Role: RoleSystem, Content: "sys", ReasoningContent: "preserved"},
			{Role: RoleUser, Content: "u", ReasoningContent: "preserved"},
			{Role: RoleAssistant, Content: "a", ReasoningContent: "blanked"},
		}
		out := h.Replay(msgs, 0)
		assert.Equal(t, "preserved", out[0].ReasoningContent)
		assert.Equal(t, "preserved", out[1].ReasoningContent)
		assert.Empty(t, out[2].ReasoningContent)
	})
}

func TestReasoningHandler_ForSummary(t *testing.T) {
	t.Parallel()

	t.Run("inline_passes_through", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatInline)
		msgs := []Message{{Role: RoleAssistant, Content: "<think>x</think>y"}}
		out := h.ForSummary(msgs)
		assert.Equal(t, msgs[0].Content, out[0].Content)
	})

	t.Run("structured_wraps_as_think", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatStructured)
		msgs := []Message{
			{Role: RoleSystem, Content: "sys"},
			{Role: RoleUser, Content: "assignment"},
			{Role: RoleAssistant, Content: "", ReasoningContent: "probing JWT"},
			{Role: RoleAssistant, Content: "final answer", ReasoningContent: "more reasoning"},
		}
		out := h.ForSummary(msgs)
		assert.Equal(t, "sys", out[0].Content)
		assert.Equal(t, "<think>probing JWT</think>", out[2].Content)
		assert.Empty(t, out[2].ReasoningContent)
		assert.Equal(t, "<think>more reasoning</think>\nfinal answer", out[3].Content)
	})

	t.Run("structured_skips_empty_reasoning", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatStructured)
		msgs := []Message{
			{Role: RoleAssistant, Content: "kept", ReasoningContent: ""},
			{Role: RoleUser, Content: "u", ReasoningContent: "should not wrap"},
		}
		out := h.ForSummary(msgs)
		assert.Equal(t, "kept", out[0].Content)
		assert.Equal(t, "u", out[1].Content)
		assert.Equal(t, "should not wrap", out[1].ReasoningContent)
	})
}

func TestReasoningHandler_Extract(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		format ReasoningFormat
		resp   ChatResponse
		want   string
	}{
		{name: "inline_strips_think_fence", format: ReasoningFormatInline,
			resp: ChatResponse{Content: "<think>planning</think>```\nworker is scanning OAuth endpoints\n```"},
			want: "worker is scanning OAuth endpoints"},
		{name: "structured_prefers_content", format: ReasoningFormatStructured,
			resp: ChatResponse{Content: "the clean final answer.", ReasoningContent: "Final: something else"},
			want: "the clean final answer."},
		{name: "structured_salvages_marker", format: ReasoningFormatStructured,
			resp: ChatResponse{
				ReasoningContent: "(14) -> 14 words. Matches all constraints. Output matches.✅ " +
					"Final: The agent just dispatched another test request and is currently evaluating the network response for security analysis. (16 words) ->",
			},
			want: "The agent just dispatched another test request and is currently evaluating the network response for security analysis."},
		{name: "structured_no_marker_empty", format: ReasoningFormatStructured,
			resp: ChatResponse{ReasoningContent: "just meandering thoughts with no output marker"}, want: ""},
		{name: "none_runs_extract_prose", format: ReasoningFormatNone,
			resp: ChatResponse{Content: `{"summary": "plain answer"}`}, want: "plain answer"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NewReasoningHandler(tc.format).Extract(tc.resp))
		})
	}
}

func TestReasoningHandler_Tail(t *testing.T) {
	t.Parallel()

	t.Run("inline_truncates_unclosed", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatInline)
		assert.Equal(t, "I was investigating OAuth", h.Tail(ChatResponse{Content: "<think>I was investigating OAuth"}))
	})

	t.Run("structured_uses_reasoning", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatStructured)
		tail := h.Tail(ChatResponse{ReasoningContent: "planning to probe OAuth redirect validation next"})
		assert.Contains(t, tail, "OAuth redirect validation next")
	})

	t.Run("structured_prefers_content_truncate", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatStructured)
		tail := h.Tail(ChatResponse{
			Content:          "<think>truncated content tail",
			ReasoningContent: "should not surface",
		})
		assert.Equal(t, "truncated content tail", tail)
	})

	t.Run("none_returns_empty", func(t *testing.T) {
		h := NewReasoningHandler(ReasoningFormatNone)
		assert.Empty(t, h.Tail(ChatResponse{Content: "<think>x"}))
	})
}
