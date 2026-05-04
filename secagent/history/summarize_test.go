package history

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

func TestRenderSnapshotForSummary(t *testing.T) {
	t.Parallel()

	t.Run("renders_roles", func(t *testing.T) {
		out := RenderSnapshotForSummary([]agent.Message{
			{Role: "user", Content: "directive text"},
			{Role: "assistant", Content: "thinking out loud", ToolCalls: []agent.ToolCall{
				{Function: agent.ToolFunction{Name: "proxy_poll", Arguments: `{"limit":5}`}},
			}},
			{Role: "tool", ToolName: "proxy_poll", Content: "5 flows seen"},
			{Role: "system", Content: "should be skipped"},
		})
		assert.Contains(t, out, "USER: directive text")
		assert.Contains(t, out, "ASSISTANT: thinking out loud")
		assert.Contains(t, out, "call 1: proxy_poll(")
		assert.Contains(t, out, "TOOL [proxy_poll]: 5 flows seen")
		assert.NotContains(t, out, "should be skipped")
	})

	t.Run("assistant_empty_text", func(t *testing.T) {
		out := RenderSnapshotForSummary([]agent.Message{
			{Role: "assistant", Content: "", ToolCalls: []agent.ToolCall{
				{Function: agent.ToolFunction{Name: "x"}},
			}},
			{Role: "assistant", Content: ""},
		})
		assert.Contains(t, out, "call 1: x(")
		assert.Contains(t, out, "ASSISTANT: (empty)")
	})
}

func TestSummarizeReconMission(t *testing.T) {
	t.Parallel()

	t.Run("strips_think_blocks_and_trims", func(t *testing.T) {
		client := &scriptedClient{response: "<think>plan</think>\nMap the SaaS app's surface.\n"}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: NopLogger{}}
		out, err := s.SummarizeReconMission(t.Context(), "Test the auth flows for IDOR")
		require.NoError(t, err)
		assert.Equal(t, "Map the SaaS app's surface.", out)
		require.Len(t, client.requests, 1)
		assert.Contains(t, client.requests[0].Messages[1].Content, "Test the auth flows for IDOR")
	})

	t.Run("rejects_empty_mission", func(t *testing.T) {
		s := &Summarizer{Pool: poolOf(&scriptedClient{}), Model: "m", Log: NopLogger{}}
		_, err := s.SummarizeReconMission(t.Context(), "   ")
		require.Error(t, err)
	})

	t.Run("rejects_unconfigured_summarizer", func(t *testing.T) {
		var s *Summarizer
		_, err := s.SummarizeReconMission(t.Context(), "mission")
		require.Error(t, err)

		s = &Summarizer{Model: "m"}
		_, err = s.SummarizeReconMission(t.Context(), "mission")
		require.Error(t, err)
	})

	t.Run("rejects_empty_llm_output", func(t *testing.T) {
		client := &scriptedClient{response: "<think>only thinking</think>"}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: NopLogger{}}
		_, err := s.SummarizeReconMission(t.Context(), "mission text")
		require.Error(t, err)
	})

	t.Run("propagates_chat_client_error", func(t *testing.T) {
		client := &scriptedClient{err: errors.New("downstream timeout")}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: NopLogger{}}
		_, err := s.SummarizeReconMission(t.Context(), "mission")
		require.Error(t, err)
	})
}

func TestSummarizeCompletedWorker(t *testing.T) {
	t.Parallel()

	t.Run("builds_prompt_with_mission", func(t *testing.T) {
		client := &scriptedClient{response: "the worker tested /admin and confirmed all endpoints return 403."}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: NopLogger{}}
		out, err := s.SummarizeCompletedWorker(t.Context(),
			[]agent.Message{
				{Role: "user", Content: "iter1 directive"},
				{Role: "assistant", Content: "ack"},
				{Role: "tool", ToolName: "proxy_poll", Content: "5 flows"},
			},
			"target the SaaS app",
			"exhausted angle",
			7,
		)
		require.NoError(t, err)
		assert.Equal(t, "the worker tested /admin and confirmed all endpoints return 403.", out)
		require.Len(t, client.requests, 1)
		req := client.requests[0]
		require.Len(t, req.Messages, 2)
		user := req.Messages[1].Content
		assert.Contains(t, user, "worker_id=7")
		assert.Contains(t, user, "exhausted angle")
	})

	t.Run("propagates_chat_client_error", func(t *testing.T) {
		client := &scriptedClient{err: errors.New("downstream timeout")}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: NopLogger{}}
		_, err := s.SummarizeCompletedWorker(t.Context(),
			[]agent.Message{
				{Role: "user", Content: "x"},
				{Role: "assistant", Content: "did work"},
			}, "mission", "reason", 1)
		require.Error(t, err)
	})

	t.Run("rejects_empty_transcript", func(t *testing.T) {
		s := &Summarizer{Pool: poolOf(&scriptedClient{}), Model: "m", Timeout: time.Second, Log: NopLogger{}}
		_, err := s.SummarizeCompletedWorker(t.Context(), nil, "mission", "reason", 1)
		require.Error(t, err)
	})

	t.Run("skips_noise_only_transcript", func(t *testing.T) {
		// A chronicle whose only assistant turn called a tool that errored, after FilterErrorMessages,
		// has no substance left. Verify we short-circuit (nil error, empty summary, no LLM call).
		client := &scriptedClient{response: "should not be called"}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Timeout: time.Second, Log: NopLogger{}}
		out, err := s.SummarizeCompletedWorker(t.Context(),
			[]agent.Message{
				{Role: "user", Content: "do thing"},
				{Role: "assistant", ToolCalls: []agent.ToolCall{
					{ID: "t1", Function: agent.ToolFunction{Name: "x"}},
				}},
				{Role: "tool", ToolCallID: "t1", Content: "ERROR: nope"},
			},
			"mission", "reason", 1,
		)
		require.NoError(t, err)
		assert.Empty(t, out)
		assert.Empty(t, client.requests)
	})
}
