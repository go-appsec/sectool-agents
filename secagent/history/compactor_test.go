package history_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/history"
)

// buildBigHistory seeds a History past the high watermark so a compactor
// configured against the same MaxContext engages.
func buildBigHistory(maxCtx int, withErrorStreak bool) *agent.History {
	h := agent.NewHistory(maxCtx)
	h.Append(agent.Message{Role: agent.RoleSystem, Content: "sys"})
	big := strings.Repeat("y", 800)
	if withErrorStreak {
		calls := []agent.ToolCall{
			{ID: "e1", Function: agent.ToolFunction{Name: "flaky", Arguments: "{}"}},
			{ID: "e2", Function: agent.ToolFunction{Name: "flaky", Arguments: "{}"}},
			{ID: "e3", Function: agent.ToolFunction{Name: "flaky", Arguments: "{}"}},
			{ID: "e4", Function: agent.ToolFunction{Name: "flaky", Arguments: "{}"}},
		}
		h.Append(agent.Message{Role: agent.RoleAssistant, Content: "fan out", ToolCalls: calls})
		for _, id := range []string{"e1", "e2", "e3", "e4"} {
			h.Append(agent.Message{
				Role:       agent.RoleTool,
				ToolCallID: id,
				ToolName:   "flaky",
				Content:    "ERROR: same failure " + strings.Repeat("z", 600),
			})
		}
	}
	for i := range 4 {
		h.Append(agent.Message{
			Role: agent.RoleAssistant, Content: big,
			ToolCalls: []agent.ToolCall{{ID: "t" + strconv.Itoa(i), Function: agent.ToolFunction{Name: "t", Arguments: "{}"}}},
		})
		h.Append(agent.Message{
			Role: agent.RoleTool, ToolCallID: "t" + strconv.Itoa(i), ToolName: "t",
			Content: big, Summary120: "s",
		})
	}
	return h
}

func TestCompactor_TieredFlow(t *testing.T) {
	t.Parallel()

	t.Run("pass_0_clears_threshold", func(t *testing.T) {
		var bCalls, cCalls int
		h := buildBigHistory(4096, true)
		c := history.NewLayeredCompactor(history.CompactorOptions{
			Compaction: agent.CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				RecoveryThreshold:      0.01,
				HardTruncateOnOverflow: true,
			},
			OnSelfPruneCandidates: func(_ context.Context, _ []agent.Message) ([]string, error) {
				bCalls++
				return nil, nil
			},
			OnDistillResults: func(_ context.Context, _ []agent.Message) ([]agent.Message, error) {
				cCalls++
				return nil, nil
			},
		})
		require.NoError(t, c.MaybeCompact(t.Context(), h))
		assert.Zero(t, bCalls)
		assert.Zero(t, cCalls)
	})

	t.Run("pass_0_short_runs_b", func(t *testing.T) {
		var bCalls, cCalls, bSnapshotLen int
		h := buildBigHistory(4096, false)
		c := history.NewLayeredCompactor(history.CompactorOptions{
			Compaction: agent.CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				RecoveryThreshold:      0.99,
				HardTruncateOnOverflow: true,
			},
			OnSelfPruneCandidates: func(_ context.Context, snap []agent.Message) ([]string, error) {
				bCalls++
				bSnapshotLen = len(snap)
				return []string{"t0", "t1", "t2", "t3"}, nil
			},
			OnDistillResults: func(_ context.Context, _ []agent.Message) ([]agent.Message, error) {
				cCalls++
				return nil, nil
			},
		})
		_ = c.MaybeCompact(t.Context(), h)
		assert.Equal(t, 1, bCalls)
		assert.Positive(t, bSnapshotLen)
	})

	t.Run("b_empty_runs_c", func(t *testing.T) {
		var bCalls, cCalls int
		h := buildBigHistory(4096, false)
		c := history.NewLayeredCompactor(history.CompactorOptions{
			Compaction: agent.CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				RecoveryThreshold:      0.99,
				HardTruncateOnOverflow: true,
			},
			OnSelfPruneCandidates: func(_ context.Context, _ []agent.Message) ([]string, error) {
				bCalls++
				return nil, nil
			},
			OnDistillResults: func(_ context.Context, snap []agent.Message) ([]agent.Message, error) {
				cCalls++
				out := make([]agent.Message, len(snap))
				copy(out, snap)
				for i := range out {
					if out[i].Role == agent.RoleTool {
						out[i].Content = "(distilled batch 1: brief summary)"
						break
					}
				}
				return out, nil
			},
		})
		require.NoError(t, c.MaybeCompact(t.Context(), h))
		assert.Equal(t, 1, bCalls)
		assert.Equal(t, 1, cCalls)
	})

	t.Run("nil_callbacks_mechanical_only", func(t *testing.T) {
		h := buildBigHistory(4096, false)
		c := history.NewLayeredCompactor(history.CompactorOptions{
			Compaction: agent.CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				HardTruncateOnOverflow: true,
			},
		})
		require.NoError(t, c.MaybeCompact(t.Context(), h))
	})

	t.Run("b_error_falls_through", func(t *testing.T) {
		var summarizeErrs int
		h := buildBigHistory(4096, false)
		c := history.NewLayeredCompactor(history.CompactorOptions{
			Compaction: agent.CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				RecoveryThreshold:      0.99,
				HardTruncateOnOverflow: true,
			},
			OnSelfPruneCandidates: func(_ context.Context, _ []agent.Message) ([]string, error) {
				return nil, errors.New("boom")
			},
			OnCallbackError: func(_ error) { summarizeErrs++ },
		})
		require.NoError(t, c.MaybeCompact(t.Context(), h))
		assert.Equal(t, 1, summarizeErrs)
	})

	t.Run("on_self_prune_applied_fires_with_dropped_ids", func(t *testing.T) {
		var appliedCalls int
		var appliedIDs []string
		h := buildBigHistory(4096, false)
		c := history.NewLayeredCompactor(history.CompactorOptions{
			Compaction: agent.CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				RecoveryThreshold:      0.99,
				HardTruncateOnOverflow: true,
			},
			OnSelfPruneCandidates: func(_ context.Context, _ []agent.Message) ([]string, error) {
				return []string{"t0", "t1", "t2", "t3"}, nil
			},
			OnSelfPruneApplied: func(ids []string) {
				appliedCalls++
				appliedIDs = ids
			},
		})
		_ = c.MaybeCompact(t.Context(), h)
		assert.Equal(t, 1, appliedCalls)
		assert.ElementsMatch(t, []string{"t0", "t1", "t2", "t3"}, appliedIDs)
	})

	t.Run("on_self_prune_applied_silent_when_no_drops", func(t *testing.T) {
		var appliedCalls int
		h := buildBigHistory(4096, false)
		c := history.NewLayeredCompactor(history.CompactorOptions{
			Compaction: agent.CompactionOptions{
				HighWatermark: 0.20, LowWatermark: 0.05, KeepTurns: 1,
				RecoveryThreshold:      0.99,
				HardTruncateOnOverflow: true,
			},
			OnSelfPruneCandidates: func(_ context.Context, _ []agent.Message) ([]string, error) {
				return nil, nil
			},
			OnSelfPruneApplied: func(_ []string) {
				appliedCalls++
			},
		})
		_ = c.MaybeCompact(t.Context(), h)
		assert.Zero(t, appliedCalls)
	})
}

func TestCompactor_RetireOnPressureReturnsSentinel(t *testing.T) {
	t.Parallel()

	h := agent.NewHistory(200)
	h.Append(agent.Message{Role: agent.RoleSystem, Content: "sys"})
	h.Append(agent.Message{Role: agent.RoleAssistant, Content: strings.Repeat("x", 600)})

	c := history.NewLayeredCompactor(history.CompactorOptions{
		Compaction:       agent.CompactionOptions{HighWatermark: 0.5, KeepTurns: 2},
		RetireOnPressure: true,
	})
	err := c.MaybeCompact(t.Context(), h)
	assert.ErrorIs(t, err, agent.ErrRetireOnPressure)
}

func TestCompactor_RetireOnPressureSkipsBelowWatermark(t *testing.T) {
	t.Parallel()

	h := agent.NewHistory(4096)
	h.Append(agent.Message{Role: agent.RoleSystem, Content: "sys"})
	h.Append(agent.Message{Role: agent.RoleUser, Content: "go"})

	c := history.NewLayeredCompactor(history.CompactorOptions{
		Compaction:       agent.CompactionOptions{HighWatermark: 0.8, KeepTurns: 2},
		RetireOnPressure: true,
	})
	require.NoError(t, c.MaybeCompact(t.Context(), h))
}
