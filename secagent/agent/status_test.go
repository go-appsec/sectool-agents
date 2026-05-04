package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummarizeStatus(t *testing.T) {
	t.Parallel()

	t.Run("strips_think_first_line", func(t *testing.T) {
		client := &fakeChatClient{responses: []ChatResponse{
			{Content: "<think>plan</think>Investigating auth; will try replay_send next.\n(second line)"},
		}}
		a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
		a.Query("earlier user turn")
		a.history.Append(Message{Role: RoleAssistant, Content: "did some recon"})
		before := a.history.Len()

		line, err := a.SummarizeStatus(t.Context(), 40)
		require.NoError(t, err)
		assert.Equal(t, "Investigating auth; will try replay_send next.", line)
		assert.Equal(t, before, a.history.Len())
		require.Len(t, client.calls, 1)
		last := client.calls[0].Messages
		assert.Equal(t, statusSummaryRequest, last[len(last)-1].Content)
		assert.Equal(t, 40, client.calls[0].MaxTokens)
	})

	t.Run("propagates_error", func(t *testing.T) {
		client := &fakeChatClient{
			responses: []ChatResponse{{}},
			errors:    []error{errors.New("boom")},
		}
		a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
		a.Query("user")
		a.history.Append(Message{Role: RoleAssistant, Content: "did work"})
		_, err := a.SummarizeStatus(t.Context(), 0)
		require.ErrorContains(t, err, "boom")
	})

	t.Run("cancel_during_acquire", func(t *testing.T) {
		// Pool is held empty; context cancel must abort Acquire deterministically
		pool := NewClientPool(&fakeChatClient{}, 1)
		held, err := pool.Acquire(t.Context())
		require.NoError(t, err)
		defer pool.Release(held)

		a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: pool})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err = a.SummarizeStatus(ctx, 0)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("omits_tools", func(t *testing.T) {
		client := &fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}
		a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
		a.SetTools([]ToolDef{{Name: "pretend", Description: "x", Schema: map[string]any{"type": "object"}}})
		a.Query("user turn")
		a.history.Append(Message{Role: RoleAssistant, Content: "did work"})

		_, err := a.SummarizeStatus(t.Context(), 0)
		require.NoError(t, err)
		require.Len(t, client.calls, 1)
		assert.Empty(t, client.calls[0].Tools)
	})

	t.Run("skips_no_substance", func(t *testing.T) {
		// Filtered transcript collapses to system+user only; must not call the LLM
		client := &fakeChatClient{
			responses: []ChatResponse{{Content: "should not be called"}},
			errors:    []error{errors.New("LLM should not fire")},
		}
		a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client), SystemPrompt: "sys"})
		a.Query("user turn")

		line, err := a.SummarizeStatus(t.Context(), 0)
		require.NoError(t, err)
		assert.Empty(t, line)
		assert.Empty(t, client.calls)
	})
}

func TestSummarizeStatusVia(t *testing.T) {
	t.Parallel()

	t.Run("bypasses_agent_pool", func(t *testing.T) {
		// Drained agent pool must not block when an override client is supplied
		pool := NewClientPool(&fakeChatClient{}, 1)
		held, err := pool.Acquire(t.Context())
		require.NoError(t, err)
		defer pool.Release(held)

		override := &fakeChatClient{responses: []ChatResponse{{Content: "summary via override"}}}
		a := NewOpenAIAgent(OpenAIAgentConfig{Model: "agent-model", Pool: pool})
		a.Query("user turn")
		a.history.Append(Message{Role: RoleAssistant, Content: "did some work"})

		line, tail, err := SummarizeStatusVia(t.Context(), a, override, "", 0)
		require.NoError(t, err)
		assert.Equal(t, "summary via override", line)
		assert.Empty(t, tail)
		require.Len(t, override.calls, 1)
		assert.Equal(t, 20000, override.calls[0].MaxTokens)
		assert.Empty(t, override.calls[0].Tools)
		assert.Equal(t, SummaryReasoningEffort, override.calls[0].ReasoningEffort)
		assert.Equal(t, "agent-model", override.calls[0].Model)
	})

	t.Run("model_override", func(t *testing.T) {
		client := &fakeChatClient{responses: []ChatResponse{{Content: "ok"}}}
		a := NewOpenAIAgent(OpenAIAgentConfig{Model: "worker-model-abliterated", Pool: newPoolWith(client)})
		a.Query("user")
		a.history.Append(Message{Role: RoleAssistant, Content: "did work"})
		_, _, err := SummarizeStatusVia(t.Context(), a, client, "summary-model", 0)
		require.NoError(t, err)
		require.Len(t, client.calls, 1)
		assert.Equal(t, "summary-model", client.calls[0].Model)
	})

	t.Run("truncated_think_tail", func(t *testing.T) {
		// Truncation mid-think: no close tag, empty line and tail carries the fragment.
		client := &fakeChatClient{responses: []ChatResponse{{
			Content: "<think>I was planning to test the OAuth redirect next",
		}}}
		a := NewOpenAIAgent(OpenAIAgentConfig{Model: "m", Pool: newPoolWith(client)})
		a.Query("user")
		a.history.Append(Message{Role: RoleAssistant, Content: "did some work"})
		line, tail, err := SummarizeStatusVia(t.Context(), a, nil, "", 0)
		require.NoError(t, err)
		assert.Empty(t, line)
		assert.Equal(t, "I was planning to test the OAuth redirect next", tail)
	})
}

func TestBuildStatusMessages(t *testing.T) {
	t.Parallel()

	t.Run("drops_tool_results_keeps_think", func(t *testing.T) {
		hist := []Message{
			{Role: RoleSystem, Content: "system prompt"},
			{Role: RoleUser, Content: "assignment"},
			{Role: RoleAssistant, Content: "<think>planning reproduction</think>running replay",
				ToolCalls: []ToolCall{{ID: "c1", Type: "function", Function: ToolFunction{Name: "replay_send", Arguments: "{}"}}}},
			{Role: RoleTool, Content: "HTTP/1.1 200 OK\n..." + strings.Repeat("x", 4000), ToolCallID: "c1"},
			{Role: RoleAssistant, Content: "<think>next step</think>checking response"},
		}
		msgs := buildStatusMessages(hist, 2000, 2)
		require.Len(t, msgs, 5)

		assert.Equal(t, RoleSystem, msgs[0].Role)
		assert.Equal(t, RoleUser, msgs[1].Role)
		assert.Equal(t, "<think>planning reproduction</think>running replay", msgs[2].Content)
		require.Len(t, msgs[2].ToolCalls, 1)
		assert.Equal(t, "replay_send", msgs[2].ToolCalls[0].Function.Name)
		assert.Equal(t, RoleTool, msgs[3].Role)
		assert.Equal(t, toolResultPlaceholder, msgs[3].Content)
		assert.Equal(t, "<think>next step</think>checking response", msgs[4].Content)
	})

	t.Run("tail_truncate_budget", func(t *testing.T) {
		hist := make([]Message, 0, 52)
		hist = append(hist, Message{Role: RoleSystem, Content: "sys"}, Message{Role: RoleUser, Content: "do the thing"})
		// 50 x 500-char assistant messages ~6250 tokens of non-anchor content
		for range 50 {
			hist = append(hist, Message{Role: RoleAssistant, Content: strings.Repeat("x", 500)})
		}
		msgs := buildStatusMessages(hist, 2000, 0)

		var total int
		for _, m := range msgs {
			total += len(m.Content)/4 + 4
		}
		assert.LessOrEqual(t, total, 2500)

		last := msgs[len(msgs)-1]
		assert.Equal(t, RoleAssistant, last.Role)
		assert.Len(t, last.Content, 500)
	})

	t.Run("drops_orphan_leading_tool", func(t *testing.T) {
		// Truncation would otherwise start on a tool whose assistant parent was cut off
		hist := []Message{
			{Role: RoleSystem, Content: "sys"},
			{Role: RoleUser, Content: "assignment"},
			{Role: RoleAssistant, Content: "", ToolCalls: []ToolCall{{ID: "c1", Function: ToolFunction{Name: "t", Arguments: "{}"}}}},
			{Role: RoleTool, Content: strings.Repeat("x", 4000), ToolCallID: "c1"},
			{Role: RoleAssistant, Content: strings.Repeat("y", 4000)},
		}
		msgs := buildStatusMessages(hist, 200, 0)
		// First post-anchor message must not be a tool with no parent assistant in scope
		require.GreaterOrEqual(t, len(msgs), 3)
		assert.NotEqual(t, RoleTool, msgs[2].Role)
	})

	t.Run("empty_history", func(t *testing.T) {
		assert.Nil(t, buildStatusMessages(nil, 1000, 0))
	})

	t.Run("no_system_anchor", func(t *testing.T) {
		hist := []Message{
			{Role: RoleUser, Content: "u"},
			{Role: RoleAssistant, Content: "a"},
		}
		msgs := buildStatusMessages(hist, 1000, 0)
		require.GreaterOrEqual(t, len(msgs), 1)
		assert.Equal(t, RoleUser, msgs[0].Role)
	})

	t.Run("zero_budget", func(t *testing.T) {
		hist := []Message{
			{Role: RoleSystem, Content: "sys"},
			{Role: RoleUser, Content: "u"},
			{Role: RoleAssistant, Content: "should be dropped"},
		}
		msgs := buildStatusMessages(hist, 0, 0)
		// Only the anchor (system + first non-system) survives
		require.Len(t, msgs, 2)
		assert.Equal(t, RoleSystem, msgs[0].Role)
		assert.Equal(t, RoleUser, msgs[1].Role)
	})
}
