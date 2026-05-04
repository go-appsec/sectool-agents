package history

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestPruneToolResults(t *testing.T) {
	t.Parallel()

	build := func() []agent.Message {
		return []agent.Message{
			{Role: agent.RoleUser, Content: "user1"},
			{
				Role:    agent.RoleAssistant,
				Content: "fan out",
				ToolCalls: []agent.ToolCall{
					{ID: "a", Function: agent.ToolFunction{Name: "proxy_poll"}},
					{ID: "b", Function: agent.ToolFunction{Name: "flow_get"}},
				},
			},
			{Role: agent.RoleTool, ToolCallID: "a", Content: "result a"},
			{Role: agent.RoleTool, ToolCallID: "b", Content: "result b"},
			{
				Role:      agent.RoleAssistant,
				ToolCalls: []agent.ToolCall{{ID: "c", Function: agent.ToolFunction{Name: "proxy_poll"}}},
			},
			{Role: agent.RoleTool, ToolCallID: "c", Content: "result c"},
		}
	}

	t.Run("drops_tool_result_only", func(t *testing.T) {
		dropSet := map[string]struct{}{"a": {}}
		kept, indices, dropped := PruneToolResults(build(), dropSet, nil)
		require.Equal(t, 1, dropped)
		require.Len(t, kept, 5)
		assert.Equal(t, []int{0, 1, 3, 4, 5}, indices)
		require.Len(t, kept[1].ToolCalls, 1)
		assert.Equal(t, "b", kept[1].ToolCalls[0].ID)
	})

	t.Run("strips_tool_calls_keeps_assistant_with_text", func(t *testing.T) {
		dropSet := map[string]struct{}{"a": {}, "b": {}}
		kept, _, dropped := PruneToolResults(build(), dropSet, nil)
		require.Equal(t, 2, dropped)
		require.Len(t, kept, 4)
		assert.Equal(t, "fan out", kept[1].Content)
		assert.Empty(t, kept[1].ToolCalls)
	})

	t.Run("drops_empty_assistant_shell", func(t *testing.T) {
		dropSet := map[string]struct{}{"c": {}}
		kept, indices, dropped := PruneToolResults(build(), dropSet, nil)
		require.Equal(t, 1, dropped)
		require.Len(t, kept, 4)
		assert.Equal(t, []int{0, 1, 2, 3}, indices)
	})

	t.Run("inscope_skips_out_of_scope_messages", func(t *testing.T) {
		msgs := build()
		dropSet := map[string]struct{}{"a": {}, "c": {}}
		// Only allow pruning at index 2 (tool a) and beyond. Index 1 (the assistant with toolcalls a+b)
		// is out-of-scope, so its ToolCalls stay intact even though "a" is in dropSet.
		kept, _, dropped := PruneToolResults(msgs, dropSet, func(i int) bool { return i >= 2 })
		require.Equal(t, 2, dropped)
		require.Len(t, kept[1].ToolCalls, 2)
	})

	t.Run("empty_dropset_keeps_everything", func(t *testing.T) {
		msgs := build()
		kept, indices, dropped := PruneToolResults(msgs, map[string]struct{}{}, nil)
		assert.Zero(t, dropped)
		assert.Len(t, kept, len(msgs))
		assert.Len(t, indices, len(msgs))
	})
}
