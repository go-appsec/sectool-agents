package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterErrorMessages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []Message
		want []Message
	}{
		{name: "nil_input"},
		{name: "empty_input", in: []Message{}},
		{
			name: "no_errors_passthrough",
			in: []Message{
				{Role: RoleSystem, Content: "sys"},
				{Role: RoleUser, Content: "u"},
				{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
				{Role: RoleTool, ToolCallID: "t1", Content: "ok result"},
				{Role: RoleAssistant, Content: "done"},
			},
			want: []Message{
				{Role: RoleSystem, Content: "sys"},
				{Role: RoleUser, Content: "u"},
				{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
				{Role: RoleTool, ToolCallID: "t1", Content: "ok result"},
				{Role: RoleAssistant, Content: "done"},
			},
		},
		{
			name: "drops_flagged_error_call",
			in: []Message{
				{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
				{Role: RoleTool, ToolCallID: "t1", Content: "ERROR: unknown tool \"x\"", IsError: true},
				{Role: RoleAssistant, Content: "moving on"},
			},
			want: []Message{{Role: RoleAssistant, Content: "moving on"}},
		},
		{
			name: "keeps_unflagged_error_prefix",
			// Content starting with "ERROR:" is not classified as an error without the dispatch-time flag
			in: []Message{
				{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
				{Role: RoleTool, ToolCallID: "t1", Content: "ERROR: relayed from target stderr"},
				{Role: RoleAssistant, Content: "done"},
			},
			want: []Message{
				{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
				{Role: RoleTool, ToolCallID: "t1", Content: "ERROR: relayed from target stderr"},
				{Role: RoleAssistant, Content: "done"},
			},
		},
		{
			name: "keeps_partial_success",
			in: []Message{
				{Role: RoleAssistant, Content: "trying both", ToolCalls: []ToolCall{
					{ID: "t1", Function: ToolFunction{Name: "x"}},
					{ID: "t2", Function: ToolFunction{Name: "y"}},
				}},
				{Role: RoleTool, ToolCallID: "t1", Content: "ERROR: bad args", IsError: true},
				{Role: RoleTool, ToolCallID: "t2", Content: "good result"},
			},
			want: []Message{
				{Role: RoleAssistant, Content: "trying both", ToolCalls: []ToolCall{
					{ID: "t2", Function: ToolFunction{Name: "y"}},
				}},
				{Role: RoleTool, ToolCallID: "t2", Content: "good result"},
			},
		},
		{
			name: "keeps_narration_only",
			in: []Message{
				{Role: RoleAssistant, Content: "narration", ToolCalls: []ToolCall{
					{ID: "t1", Function: ToolFunction{Name: "x"}},
				}},
				{Role: RoleTool, ToolCallID: "t1", Content: "ERROR: nope", IsError: true},
			},
			want: []Message{{Role: RoleAssistant, Content: "narration", ToolCalls: []ToolCall{}}},
		},
		{
			name: "drops_repair_errors",
			in: []Message{
				{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "x"}}}},
				{Role: RoleTool, ToolCallID: "t1", Content: "your arguments did not parse", IsRepairError: true},
				{Role: RoleAssistant, Content: "retry"},
			},
			want: []Message{{Role: RoleAssistant, Content: "retry"}},
		},
		{
			name: "preserves_order",
			in: []Message{
				{Role: RoleSystem, Content: "sys"},
				{Role: RoleUser, Content: "go"},
				{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "good"}}}},
				{Role: RoleTool, ToolCallID: "t1", Content: "great"},
				{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t2", Function: ToolFunction{Name: "bad"}}}},
				{Role: RoleTool, ToolCallID: "t2", Content: "ERROR: unknown", IsError: true},
				{Role: RoleAssistant, Content: "summary"},
			},
			want: []Message{
				{Role: RoleSystem, Content: "sys"},
				{Role: RoleUser, Content: "go"},
				{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "good"}}}},
				{Role: RoleTool, ToolCallID: "t1", Content: "great"},
				{Role: RoleAssistant, Content: "summary"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := FilterErrorMessages(tc.in)
			if tc.want == nil {
				assert.Empty(t, out)
				return
			}
			assert.Equal(t, tc.want, out)
		})
	}
}

func TestHasSubstantiveMessages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []Message
		want bool
	}{
		{name: "empty"},
		{name: "system_only", in: []Message{
			{Role: RoleSystem, Content: "sys"},
		}},
		{name: "system_and_user", in: []Message{
			{Role: RoleSystem, Content: "sys"},
			{Role: RoleUser, Content: "u"},
		}},
		{name: "assistant_text", in: []Message{
			{Role: RoleSystem, Content: "sys"},
			{Role: RoleUser, Content: "u"},
			{Role: RoleAssistant, Content: "did a thing"},
		}, want: true},
		{name: "assistant_tool_calls", in: []Message{
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
		}, want: true},
		{name: "whitespace_only", in: []Message{
			{Role: RoleAssistant, Content: "   \n\t"},
		}},
		{name: "tool_result_present", in: []Message{
			{Role: RoleTool, ToolCallID: "t1", Content: "result"},
		}, want: true},
		{name: "empty_tool_calls_slice", in: []Message{
			{Role: RoleAssistant, Content: "", ToolCalls: []ToolCall{}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, HasSubstantiveMessages(tc.in))
		})
	}
}

func TestCollapseSameToolErrorStreaks(t *testing.T) {
	t.Parallel()

	t.Run("no_errors_unchanged", func(t *testing.T) {
		in := []Message{
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: RoleTool, ToolCallID: "t1", ToolName: "x", Content: "ok"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Equal(t, in, out)
		assert.Zero(t, dropped)
	})

	t.Run("collapses_streak_of_three", func(t *testing.T) {
		in := []Message{
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: RoleTool, ToolCallID: "t1", ToolName: "replay_send", IsError: true, Content: "ERROR: bad form"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t2"}}},
			{Role: RoleTool, ToolCallID: "t2", ToolName: "replay_send", IsError: true, Content: "ERROR: bad form again"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t3"}}},
			{Role: RoleTool, ToolCallID: "t3", ToolName: "replay_send", IsError: true, Content: "ERROR: still bad"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Equal(t, 2, dropped)
		require.Len(t, out, 2)
		assert.Equal(t, "t3", out[0].ToolCalls[0].ID)
		assert.Equal(t, "ERROR: still bad", out[1].Content)
	})

	t.Run("different_tool_breaks_streak", func(t *testing.T) {
		in := []Message{
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: RoleTool, ToolCallID: "t1", ToolName: "x", IsError: true, Content: "ERROR: a"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t2"}}},
			{Role: RoleTool, ToolCallID: "t2", ToolName: "y", IsError: true, Content: "ERROR: b"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t3"}}},
			{Role: RoleTool, ToolCallID: "t3", ToolName: "x", IsError: true, Content: "ERROR: c"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Zero(t, dropped)
		assert.Equal(t, in, out)
	})

	t.Run("success_breaks_streak", func(t *testing.T) {
		in := []Message{
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: RoleTool, ToolCallID: "t1", ToolName: "x", IsError: true, Content: "ERROR: a"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t2"}}},
			{Role: RoleTool, ToolCallID: "t2", ToolName: "x", Content: "good"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t3"}}},
			{Role: RoleTool, ToolCallID: "t3", ToolName: "x", IsError: true, Content: "ERROR: c"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Zero(t, dropped)
		assert.Equal(t, in, out)
	})

	t.Run("parallel_strict_semantics", func(t *testing.T) {
		// Assistant calls X and Y in parallel; both error. Next turn errors X again. The "next tool result"
		// after t1 is t2 (different tool name) so t1 is NOT collapsed even though a later same-tool error exists.
		in := []Message{
			{Role: RoleAssistant, Content: "parallel", ToolCalls: []ToolCall{
				{ID: "t1"}, {ID: "t2"},
			}},
			{Role: RoleTool, ToolCallID: "t1", ToolName: "x", IsError: true, Content: "ERROR: a"},
			{Role: RoleTool, ToolCallID: "t2", ToolName: "y", IsError: true, Content: "ERROR: b"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t3"}}},
			{Role: RoleTool, ToolCallID: "t3", ToolName: "x", IsError: true, Content: "ERROR: c"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Zero(t, dropped)
		assert.Equal(t, in, out)
	})

	t.Run("protects_repair_errors", func(t *testing.T) {
		in := []Message{
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: RoleTool, ToolCallID: "t1", ToolName: "x", IsError: true, IsRepairError: true, Content: "your arguments did not parse"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t2"}}},
			{Role: RoleTool, ToolCallID: "t2", ToolName: "x", IsError: true, IsRepairError: true, Content: "your arguments did not parse v2"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Zero(t, dropped)
		assert.Equal(t, in, out)
	})

	t.Run("collapses_within_parallel", func(t *testing.T) {
		// Single assistant turn calls tool X twice in parallel; both error
		// First result's "next" finds the second (same tool, error) and collapses
		in := []Message{
			{Role: RoleAssistant, Content: "parallel x", ToolCalls: []ToolCall{
				{ID: "t1"}, {ID: "t2"},
			}},
			{Role: RoleTool, ToolCallID: "t1", ToolName: "x", IsError: true, Content: "ERROR: a"},
			{Role: RoleTool, ToolCallID: "t2", ToolName: "x", IsError: true, Content: "ERROR: b"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Equal(t, 1, dropped)
		require.Len(t, out, 2)
		require.Len(t, out[0].ToolCalls, 1)
		assert.Equal(t, "t2", out[0].ToolCalls[0].ID)
		assert.Equal(t, "parallel x", out[0].Content)
		assert.Equal(t, "ERROR: b", out[1].Content)
	})

	t.Run("trailing_error_kept", func(t *testing.T) {
		// Final error result with no later tool result must NOT be collapsed
		in := []Message{
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "t1"}}},
			{Role: RoleTool, ToolCallID: "t1", ToolName: "x", IsError: true, Content: "ERROR: trailing"},
		}
		out, dropped := collapseSameToolErrorStreaks(in)
		assert.Zero(t, dropped)
		assert.Equal(t, in, out)
	})
}
