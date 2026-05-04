package history

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
)

// buildDistillSnapshot builds a message snapshot with eligibleEvents fat
// tool-result pairs followed by trailingEvents small ones.
func buildDistillSnapshot(eligibleEvents int, eligibleBodyBytes int, trailingEvents int) []agent.Message {
	out := []agent.Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "go"},
	}
	body := strings.Repeat("x", eligibleBodyBytes)
	for i := 0; i < eligibleEvents; i++ {
		id := "old" + string(rune('A'+i))
		out = append(out,
			agent.Message{
				Role:    "assistant",
				Content: "calling",
				ToolCalls: []agent.ToolCall{{
					ID: id,
					Function: agent.ToolFunction{
						Name:      "proxy_poll",
						Arguments: `{"summary":true}`,
					},
				}},
			},
			agent.Message{
				Role: agent.RoleTool, ToolCallID: id, ToolName: "proxy_poll",
				Content: body,
			},
		)
	}
	for i := 0; i < trailingEvents; i++ {
		id := "new" + string(rune('A'+i))
		out = append(out,
			agent.Message{
				Role:    "assistant",
				Content: "calling",
				ToolCalls: []agent.ToolCall{{
					ID: id,
					Function: agent.ToolFunction{
						Name:      "flow_get",
						Arguments: `{}`,
					},
				}},
			},
			agent.Message{
				Role: agent.RoleTool, ToolCallID: id, ToolName: "flow_get",
				Content: "small recent",
			},
		)
	}
	return out
}

func TestDistillCallback(t *testing.T) {
	t.Parallel()

	t.Run("rewrites_eligible_batches", func(t *testing.T) {
		client := &sequenceClient{
			responses: []agent.ChatResponse{
				{Content: "GET /api/v1 → 200 with 12 entries summarizing user activity."},
			},
		}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := DistillCallback(s)
		// 6 eligible events x 1KB each, trailing=4 fills keepWindow exactly
		snap := buildDistillSnapshot(6, 1024, 4)

		out, err := cb(t.Context(), snap)
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Len(t, out, len(snap))

		var rewritten int
		for i := range out {
			if out[i].Role == agent.RoleTool && snap[i].Content != out[i].Content {
				rewritten++
				assert.True(t, strings.HasPrefix(out[i].Content, agent.DistillPrefix))
			}
		}
		assert.Equal(t, 6, rewritten)
		assert.Equal(t, 1, client.callCount())
	})

	t.Run("below_min_events_no_batch", func(t *testing.T) {
		client := &sequenceClient{}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := DistillCallback(s)
		// 2 eligible events < distillMinBatchEvents (3); trailing=4 keeps the
		// keepWindow tight so trailing events don't bleed into the eligible range
		snap := buildDistillSnapshot(2, 4096, 4)

		out, err := cb(t.Context(), snap)
		require.NoError(t, err)
		assert.Nil(t, out)
		assert.Equal(t, 0, client.callCount())
	})

	t.Run("below_min_bytes_no_batch", func(t *testing.T) {
		client := &sequenceClient{}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := DistillCallback(s)
		// 4 eligible events x 50 bytes = 200 bytes < distillMinBatchBytes (2048)
		snap := buildDistillSnapshot(4, 50, 4)

		out, err := cb(t.Context(), snap)
		require.NoError(t, err)
		assert.Nil(t, out)
		assert.Equal(t, 0, client.callCount())
	})

	t.Run("llm_error_fails_open", func(t *testing.T) {
		client := &sequenceClient{
			responses: []agent.ChatResponse{{}},
			errors:    []error{errMsg("upstream")},
		}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := DistillCallback(s)
		snap := buildDistillSnapshot(6, 1024, 4)

		out, err := cb(t.Context(), snap)
		// Callback errors are absorbed per the contract: failed batches stay raw.
		// With only one batch and it failed, no successful batches means nil
		// replacement so maybeCompact knows nothing changed.
		require.NoError(t, err)
		assert.Nil(t, out)
	})

	t.Run("nil_summarizer_no_calls", func(t *testing.T) {
		cb := DistillCallback(nil)
		out, err := cb(t.Context(), buildDistillSnapshot(6, 1024, 4))
		require.NoError(t, err)
		assert.Nil(t, out)
	})

	t.Run("already_distilled_idempotent", func(t *testing.T) {
		client := &sequenceClient{}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := DistillCallback(s)
		snap := buildDistillSnapshot(6, 1024, 4)
		for i := range snap {
			if snap[i].Role == agent.RoleTool {
				snap[i].Content = agent.DistillPrefix + "1: prior summary)"
			}
		}
		out, err := cb(t.Context(), snap)
		require.NoError(t, err)
		assert.Nil(t, out)
		assert.Equal(t, 0, client.callCount())
	})

	t.Run("multiple_batches", func(t *testing.T) {
		// 12 eligible events at distillMaxBatchEvents=6 each, 2 batches
		client := &sequenceClient{
			responses: []agent.ChatResponse{
				{Content: "Batch 1 prose."},
				{Content: "Batch 2 prose."},
			},
		}
		s := &Summarizer{Pool: poolOf(client), Model: "m", Log: NopLogger{}}
		cb := DistillCallback(s)
		snap := buildDistillSnapshot(12, 1024, 4)

		out, err := cb(t.Context(), snap)
		require.NoError(t, err)
		require.NotNil(t, out)
		assert.Equal(t, 2, client.callCount())

		var joined strings.Builder
		for _, m := range out {
			if m.Role == agent.RoleTool && strings.HasPrefix(m.Content, agent.DistillPrefix) {
				joined.WriteString(m.Content)
				joined.WriteString("\n")
			}
		}
		assert.Contains(t, joined.String(), "Batch 1 prose.")
		assert.Contains(t, joined.String(), "Batch 2 prose.")
	})
}

func TestBuildDistillBatches(t *testing.T) {
	t.Parallel()

	t.Run("excludes_repair_errors", func(t *testing.T) {
		snap := []agent.Message{
			{Role: "system", Content: "sys"},
			{Role: "user", Content: "go"},
		}
		body := strings.Repeat("x", 1024)
		for i := 0; i < 3; i++ {
			id := "id" + string(rune('A'+i))
			snap = append(snap,
				agent.Message{
					Role: "assistant", Content: "go",
					ToolCalls: []agent.ToolCall{{ID: id, Function: agent.ToolFunction{Name: "t"}}},
				},
				agent.Message{
					Role: agent.RoleTool, ToolCallID: id, ToolName: "t",
					Content:       body,
					IsRepairError: i == 1,
				},
			)
		}
		for i := 0; i < 4; i++ {
			snap = append(snap, agent.Message{Role: "assistant", Content: "trail"})
		}
		batches := buildDistillBatches(snap)
		// Repair error at the middle event breaks the batch into two single-event runs
		// each is below distillMinBatchEvents so neither qualifies
		assert.Empty(t, batches)
	})
}

// errMsg is a string-typed sentinel error used to drive scripted error paths.
type errMsg string

func (e errMsg) Error() string { return string(e) }
