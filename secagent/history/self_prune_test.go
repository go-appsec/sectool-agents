package history

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

// sequenceClient returns each scripted response in order; errors are matched against the same index.
type sequenceClient struct {
	mu        sync.Mutex
	idx       int32
	responses []agent.ChatResponse
	errors    []error
	requests  []agent.ChatRequest
}

func (c *sequenceClient) CreateChatCompletion(_ context.Context, req agent.ChatRequest) (agent.ChatResponse, error) {
	i := int(atomic.AddInt32(&c.idx, 1)) - 1
	c.mu.Lock()
	c.requests = append(c.requests, req)
	c.mu.Unlock()
	if i >= len(c.responses) {
		return agent.ChatResponse{}, errors.New("sequenceClient: out of scripted responses")
	}
	var err error
	if i < len(c.errors) {
		err = c.errors[i]
	}
	return c.responses[i], err
}

func (c *sequenceClient) callCount() int { return int(atomic.LoadInt32(&c.idx)) }

// buildSelfPruneSnapshot seeds a snapshot with the given number of tool
// events. Each event is one assistant.tool_calls fanout of size 1.
func buildSelfPruneSnapshot(n int) []agent.Message {
	out := []agent.Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "do work"},
	}
	for i := 0; i < n; i++ {
		id := "c" + string(rune('A'+i))
		out = append(out,
			agent.Message{
				Role:    "assistant",
				Content: "calling tool",
				ToolCalls: []agent.ToolCall{{
					ID: id,
					Function: agent.ToolFunction{
						Name:      "proxy_poll",
						Arguments: `{"summary":true}`,
					},
				}},
			},
			agent.Message{
				Role:       "tool",
				ToolCallID: id,
				ToolName:   "proxy_poll",
				Content:    "result " + id,
			},
		)
	}
	return out
}

func TestSelfPruneCallback(t *testing.T) {
	t.Parallel()

	t.Run("drops_selected", func(t *testing.T) {
		client := &sequenceClient{
			responses: []agent.ChatResponse{
				{Content: `{"remove":[1,2,4]}`},
			},
		}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := SelfPruneCallback(s)
		snap := buildSelfPruneSnapshot(8)

		dropIDs, err := cb(t.Context(), snap)
		require.NoError(t, err)
		require.Len(t, dropIDs, 3)
		assert.Contains(t, dropIDs, "cA")
		assert.Contains(t, dropIDs, "cB")
		assert.Contains(t, dropIDs, "cD")
		assert.NotContains(t, dropIDs, "cC")
		assert.Equal(t, 1, client.callCount())
	})

	t.Run("empty_selection_no_drops", func(t *testing.T) {
		client := &sequenceClient{
			responses: []agent.ChatResponse{
				{Content: `{"remove":[]}`},
			},
		}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := SelfPruneCallback(s)

		dropIDs, err := cb(t.Context(), buildSelfPruneSnapshot(8))
		require.NoError(t, err)
		assert.Empty(t, dropIDs)
		assert.Equal(t, 1, client.callCount())
	})

	t.Run("below_min_events_skips_llm", func(t *testing.T) {
		client := &sequenceClient{
			responses: []agent.ChatResponse{
				{Content: `{"remove":[1]}`},
			},
		}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := SelfPruneCallback(s)

		dropIDs, err := cb(t.Context(), buildSelfPruneSnapshot(3))
		require.NoError(t, err)
		assert.Empty(t, dropIDs)
		assert.Equal(t, 0, client.callCount())
	})

	t.Run("nil_summarizer_no_calls", func(t *testing.T) {
		cb := SelfPruneCallback(nil)
		dropIDs, err := cb(t.Context(), buildSelfPruneSnapshot(8))
		require.NoError(t, err)
		assert.Empty(t, dropIDs)
	})

	t.Run("selection_parse_error_propagates", func(t *testing.T) {
		client := &sequenceClient{
			responses: []agent.ChatResponse{
				{Content: "not even close to JSON"},
			},
		}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := SelfPruneCallback(s)

		dropIDs, err := cb(t.Context(), buildSelfPruneSnapshot(8))
		require.Error(t, err)
		assert.Empty(t, dropIDs)
	})

	t.Run("empty_then_valid_retries_once", func(t *testing.T) {
		client := &sequenceClient{
			responses: []agent.ChatResponse{
				{Content: ""},
				{Content: `{"remove":[1,3]}`},
			},
		}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := SelfPruneCallback(s)

		dropIDs, err := cb(t.Context(), buildSelfPruneSnapshot(8))
		require.NoError(t, err)
		require.Len(t, dropIDs, 2)
		assert.Contains(t, dropIDs, "cA")
		assert.Contains(t, dropIDs, "cC")
		assert.Equal(t, 2, client.callCount())
		// First attempt: no temperature override; retry: bumped
		assert.Nil(t, client.requests[0].Temperature)
		require.NotNil(t, client.requests[1].Temperature)
		assert.InEpsilon(t, selfPruneRetryTemperature, *client.requests[1].Temperature, 0.0001)
	})

	t.Run("empty_twice_returns_no_selections", func(t *testing.T) {
		client := &sequenceClient{
			responses: []agent.ChatResponse{
				{Content: ""},
				{Content: ""},
			},
		}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := SelfPruneCallback(s)

		dropIDs, err := cb(t.Context(), buildSelfPruneSnapshot(8))
		require.NoError(t, err)
		assert.Empty(t, dropIDs)
		assert.Equal(t, 2, client.callCount())
	})
}

func TestParseEventIndexList(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		raw   string
		total int
		want  []int
	}{
		{"remove_field", `{"remove":[1,3,5]}`, 10, []int{0, 2, 4}},
		{"unknown_field_ignored", `{"retain":[2,4]}`, 10, nil},
		{"out_of_range_dropped", `{"remove":[1,99,2]}`, 5, []int{0, 1}},
		{"deduped", `{"remove":[3,3,3,1]}`, 10, []int{0, 2}},
		{"sorted", `{"remove":[5,1,3]}`, 10, []int{0, 2, 4}},
		{"with_fences", "```json\n{\"remove\":[1]}\n```", 5, []int{0}},
		{"empty", `{"remove":[]}`, 5, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseEventIndexList(tc.raw, tc.total)
			require.NoError(t, err)
			if tc.want == nil {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("empty_raw_returns_sentinel", func(t *testing.T) {
		got, err := parseEventIndexList("", 5)
		require.ErrorIs(t, err, ErrEmptyResponse)
		assert.Empty(t, got)
	})
}

func TestBuildToolEvents(t *testing.T) {
	t.Parallel()

	snap := []agent.Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "go"},
		{
			Role: "assistant", Content: "fan out",
			ToolCalls: []agent.ToolCall{
				{ID: "a", Function: agent.ToolFunction{Name: "tool_one", Arguments: `{}`}},
				{ID: "b", Function: agent.ToolFunction{Name: "tool_two", Arguments: `{}`}},
			},
		},
		{Role: "tool", ToolCallID: "a", ToolName: "tool_one", Content: "ok one"},
		{Role: "tool", ToolCallID: "b", ToolName: "tool_two", Content: "ERROR: bad"},
	}
	events := buildToolEvents(snap)
	require.Len(t, events, 2)
	assert.Equal(t, "tool_one", events[0].ToolName)
	assert.Equal(t, "a", events[0].ToolCallID)
	assert.False(t, events[0].IsError)
	assert.Equal(t, "tool_two", events[1].ToolName)
	assert.True(t, events[1].IsError, "ERROR: prefix marks the event as an error")
}
