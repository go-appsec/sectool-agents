package history

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestChronicle_Install(t *testing.T) {
	t.Parallel()

	t.Run("installs_raw_and_queries", func(t *testing.T) {
		fake := &agent.FakeAgent{}
		c := Chronicle{
			messages: []agent.Message{
				{Role: "user", Content: "iter 1 directive"},
				{Role: "assistant", Content: "I tested /admin"},
			},
			iters: []int{1, 1},
		}
		c.Install(fake, "investigate /api this iteration")
		require.Len(t, fake.LastReplacedHistory, 2)
		assert.Equal(t, "iter 1 directive", fake.LastReplacedHistory[0].Content)
		assert.Equal(t, "I tested /admin", fake.LastReplacedHistory[1].Content)
		require.Len(t, fake.QueriedInputs, 1)
		assert.Equal(t, "investigate /api this iteration", fake.QueriedInputs[0])
		assert.Equal(t, 1, fake.BoundaryCalls)
	})

	t.Run("empty_chronicle_iter_one", func(t *testing.T) {
		fake := &agent.FakeAgent{}
		var c Chronicle
		c.Install(fake, "investigate /login")
		assert.Empty(t, fake.LastReplacedHistory)
		require.Len(t, fake.QueriedInputs, 1)
		assert.Equal(t, "investigate /login", fake.QueriedInputs[0])
		assert.Equal(t, 1, fake.BoundaryCalls)
	})
}

func TestChronicle_ExtractAndAppend(t *testing.T) {
	t.Parallel()

	t.Run("tags_messages_with_iter", func(t *testing.T) {
		fake := &agent.FakeAgent{
			LastBoundaryID: 1,
			SnapshotMessages: []agent.Message{
				{Role: "user", Content: "directive"},
				{Role: "assistant", Content: "thinking"},
				{Role: "tool", ToolName: "proxy_poll", Content: "result"},
			},
		}
		var c Chronicle
		c.ExtractAndAppend(fake, 5)
		require.Len(t, c.messages, 2)
		require.Len(t, c.iters, 2)
		assert.Equal(t, []int{5, 5}, c.iters)
		assert.Equal(t, "assistant", c.messages[0].Role)
		assert.Equal(t, "tool", c.messages[1].Role)
	})

	t.Run("empty_snapshot_is_noop", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{{Role: "user", Content: "preexisting"}},
			iters:    []int{1},
		}
		c.ExtractAndAppend(&agent.FakeAgent{}, 2)
		assert.Len(t, c.messages, 1)
		assert.Equal(t, []int{1}, c.iters)
	})
}

func TestChronicle_Compact(t *testing.T) {
	t.Parallel()

	t.Run("strips_and_stubs_old", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{
				{Role: "assistant", Content: "<think>plotting</think>I will fetch /admin"},
				{Role: "tool", ToolName: "proxy_poll", Content: "(very long tool output here that should be stubbed)"},
				{Role: "user", Content: "iter 2 directive"},
				{Role: "assistant", Content: "<think>recent reasoning</think>Trying again"},
				{Role: "tool", ToolName: "replay_send", Content: "fresh result"},
			},
			iters: []int{1, 1, 2, 2, 2},
		}
		stripped, stubbed := c.Compact(3, 2)
		assert.Equal(t, 1, stripped)
		assert.Equal(t, 1, stubbed)
		assert.NotContains(t, c.messages[0].Content, "<think>")
		assert.Contains(t, c.messages[0].Content, "I will fetch /admin")
		assert.Contains(t, c.messages[1].Content, "compacted:")
		assert.Contains(t, c.messages[3].Content, "<think>recent reasoning</think>")
		assert.Equal(t, "fresh result", c.messages[4].Content)
	})

	t.Run("idempotent", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{
				{Role: "assistant", Content: "<think>plotting</think>fetch /admin"},
				{Role: "tool", ToolName: "proxy_poll", Content: "long output"},
			},
			iters: []int{1, 1},
		}
		stripped1, stubbed1 := c.Compact(5, 2)
		require.Equal(t, 1, stripped1)
		require.Equal(t, 1, stubbed1)
		stripped2, stubbed2 := c.Compact(5, 2)
		assert.Equal(t, 0, stripped2)
		assert.Equal(t, 0, stubbed2)
	})

	t.Run("preserves_length_and_order", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{
				{Role: "user", Content: "directive 1"},
				{Role: "assistant", Content: "<think>x</think>y"},
				{Role: "tool", ToolName: "t", Content: "long"},
				{Role: "user", Content: "directive 2"},
			},
			iters: []int{1, 1, 1, 2},
		}
		preLen := len(c.messages)
		c.Compact(3, 2)
		assert.Len(t, c.messages, preLen)
		assert.Equal(t, "directive 1", c.messages[0].Content)
		assert.Equal(t, "directive 2", c.messages[3].Content)
	})

	t.Run("nothing_old_is_noop", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{
				{Role: "assistant", Content: "<think>x</think>recent"},
			},
			iters: []int{5},
		}
		stripped, stubbed := c.Compact(5, 2)
		assert.Equal(t, 0, stripped)
		assert.Equal(t, 0, stubbed)
		assert.Equal(t, "<think>x</think>recent", c.messages[0].Content)
	})

	t.Run("repair_errors_protected", func(t *testing.T) {
		c := Chronicle{
			messages: []agent.Message{
				{Role: "tool", ToolName: "t", IsRepairError: true,
					Content: "ERROR: your arguments did not parse..."},
			},
			iters: []int{1},
		}
		_, stubbed := c.Compact(5, 2)
		assert.Equal(t, 0, stubbed)
		assert.Contains(t, c.messages[0].Content, "did not parse")
	})
}

func TestChronicle_ApplySelfPrune(t *testing.T) {
	t.Parallel()

	build := func() *Chronicle {
		return &Chronicle{
			messages: []agent.Message{
				{Role: "user", Content: "iter 1 directive"},
				{
					Role:    "assistant",
					Content: "fan out",
					ToolCalls: []agent.ToolCall{
						{ID: "a", Function: agent.ToolFunction{Name: "proxy_poll"}},
						{ID: "b", Function: agent.ToolFunction{Name: "flow_get"}},
					},
				},
				{Role: "tool", ToolCallID: "a", ToolName: "proxy_poll", Content: "result a"},
				{Role: "tool", ToolCallID: "b", ToolName: "flow_get", Content: "result b"},
				{
					Role:      "assistant",
					ToolCalls: []agent.ToolCall{{ID: "c", Function: agent.ToolFunction{Name: "proxy_poll"}}},
				},
				{Role: "tool", ToolCallID: "c", ToolName: "proxy_poll", Content: "result c"},
			},
			iters: []int{1, 1, 1, 1, 2, 2},
		}
	}

	t.Run("drops_tool_result", func(t *testing.T) {
		c := build()
		dropped := c.ApplySelfPrune([]string{"a"})
		assert.Equal(t, 1, dropped)
		// directive(0) + assistant(b only) + tool(b) + assistant(c) + tool(c) = 5
		require.Len(t, c.messages, 5)
		require.Len(t, c.iters, 5)
		assert.Equal(t, []int{1, 1, 1, 2, 2}, c.iters)
		assert.Len(t, c.messages[1].ToolCalls, 1)
		assert.Equal(t, "b", c.messages[1].ToolCalls[0].ID)
		assert.Equal(t, "b", c.messages[2].ToolCallID)
	})

	t.Run("strips_tool_call_keeps_assistant_with_text", func(t *testing.T) {
		c := build()
		dropped := c.ApplySelfPrune([]string{"a", "b"})
		assert.Equal(t, 2, dropped)
		// Assistant with Content="fan out" survives despite both ToolCalls dropped
		// directive + assistant("fan out", no toolcalls) + assistant(c) + tool(c) = 4
		require.Len(t, c.messages, 4)
		require.Len(t, c.iters, 4)
		assert.Equal(t, "fan out", c.messages[1].Content)
		assert.Empty(t, c.messages[1].ToolCalls)
		assert.Equal(t, []int{1, 1, 2, 2}, c.iters)
	})

	t.Run("drops_empty_assistant_shell", func(t *testing.T) {
		c := build()
		dropped := c.ApplySelfPrune([]string{"c"})
		assert.Equal(t, 1, dropped)
		// Assistant shell holding only "c" drops entirely (no Content)
		// directive + assistant(a,b) + tool(a) + tool(b) = 4
		require.Len(t, c.messages, 4)
		require.Len(t, c.iters, 4)
		assert.Equal(t, []int{1, 1, 1, 1}, c.iters)
	})

	t.Run("iters_shorter_than_messages", func(t *testing.T) {
		// Mirrors the chronicle invariant Compact tolerates: iters may be shorter than messages.
		// Drops still happen; the missing-iters tail is silently skipped.
		c := &Chronicle{
			messages: []agent.Message{
				{
					Role:      "assistant",
					ToolCalls: []agent.ToolCall{{ID: "a", Function: agent.ToolFunction{Name: "proxy_poll"}}},
				},
				{Role: "tool", ToolCallID: "a", ToolName: "proxy_poll", Content: "result a"},
				{Role: "assistant", Content: "trailing"},
			},
			iters: []int{1, 1}, // shorter, no entry for the trailing assistant
		}
		dropped := c.ApplySelfPrune([]string{"a"})
		assert.Equal(t, 1, dropped)
		// Empty assistant shell + its tool result both gone; trailing remains
		require.Len(t, c.messages, 1)
		assert.Equal(t, "trailing", c.messages[0].Content)
		assert.Empty(t, c.iters)
	})

	t.Run("empty_inputs_noop", func(t *testing.T) {
		c := build()
		assert.Equal(t, 0, c.ApplySelfPrune(nil))
		assert.Equal(t, 0, c.ApplySelfPrune([]string{""}))
		assert.Len(t, c.messages, 6)
		assert.Len(t, c.iters, 6)
	})

	t.Run("foreign_id_noop", func(t *testing.T) {
		c := build()
		dropped := c.ApplySelfPrune([]string{"not-present"})
		assert.Equal(t, 0, dropped)
		assert.Len(t, c.messages, 6)
		assert.Len(t, c.iters, 6)
	})
}

func TestChronicle_CloneWithDirective(t *testing.T) {
	t.Parallel()

	src := Chronicle{
		messages: []agent.Message{
			{Role: "user", Content: "iter 1 directive"},
			{Role: "assistant", Content: "tested /admin"},
		},
		iters: []int{1, 1},
	}
	clone := src.CloneWithDirective("new fork directive", 2)
	require.Len(t, clone.messages, 3)
	assert.Equal(t, "new fork directive", clone.messages[0].Content)
	assert.Equal(t, "user", clone.messages[0].Role)
	assert.Equal(t, "iter 1 directive", clone.messages[1].Content)
	assert.Equal(t, []int{2, 1, 1}, clone.iters)
	// Source untouched.
	assert.Len(t, src.messages, 2)
	assert.Equal(t, []int{1, 1}, src.iters)
}

func TestChronicle_Reset(t *testing.T) {
	t.Parallel()
	c := Chronicle{
		messages: []agent.Message{{Role: "user", Content: "x"}},
		iters:    []int{1},
	}
	c.Reset()
	assert.Empty(t, c.messages)
	assert.Empty(t, c.iters)
	assert.Equal(t, 0, c.Len())
}

func TestSnapshotSinceBoundary(t *testing.T) {
	t.Parallel()

	t.Run("empty_snapshot_returns_nil", func(t *testing.T) {
		assert.Nil(t, SnapshotSinceBoundary(&agent.FakeAgent{}))
	})

	t.Run("watermark_above_all_ids_returns_nil", func(t *testing.T) {
		// FakeAgent.Snapshot stamps positional IDs (1, 2, ...)
		// A watermark above the highest assigned ID yields no iter content
		fake := &agent.FakeAgent{
			LastBoundaryID:   3,
			SnapshotMessages: []agent.Message{{Role: "user", Content: "x"}},
		}
		assert.Nil(t, SnapshotSinceBoundary(fake))
	})

	t.Run("returns_tail_clone", func(t *testing.T) {
		fake := &agent.FakeAgent{
			LastBoundaryID: 1,
			SnapshotMessages: []agent.Message{
				{Role: "user", Content: "directive"},
				{Role: "assistant", Content: "thinking"},
				{Role: "tool", ToolName: "proxy_poll", Content: "result"},
			},
		}
		out := SnapshotSinceBoundary(fake)
		require.Len(t, out, 2)
		assert.Equal(t, "assistant", out[0].Role)
		assert.Equal(t, "tool", out[1].Role)
		// Mutate the returned slice; the agent's internal snapshot must be untouched
		out[0].Content = "mutated"
		assert.Equal(t, "thinking", fake.SnapshotMessages[1].Content)
	})

	t.Run("watermark_zero_returns_full_history", func(t *testing.T) {
		fake := &agent.FakeAgent{
			LastBoundaryID: 0,
			SnapshotMessages: []agent.Message{
				{Role: "user", Content: "directive"},
				{Role: "assistant", Content: "ack"},
			},
		}
		out := SnapshotSinceBoundary(fake)
		require.Len(t, out, 2)
	})
}
