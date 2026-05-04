package agent

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildFattyHistory seeds a history whose token estimate crosses the watermark.
func buildFattyHistory(maxCtx int, big string) *History {
	h := NewHistory(maxCtx)
	h.Append(Message{Role: RoleSystem, Content: "sys prompt"})
	for range 5 {
		h.Append(Message{
			Role:      RoleAssistant,
			Content:   "<think>internal deliberation goes here</think>summary line.\n" + big,
			ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "tool", Arguments: "{}"}}},
		})
		h.Append(Message{
			Role:       RoleTool,
			ToolCallID: "t1",
			ToolName:   "tool",
			Content:    big,
			Summary120: Summarize120(big),
		})
	}
	h.Append(Message{Role: RoleUser, Content: "continue"})
	h.Append(Message{Role: RoleAssistant, Content: "ok"})
	return h
}

// buildToolCallHistory seeds n assistant/tool turns of identical bulk payload.
func buildToolCallHistory(maxCtx int, big string, n int) *History {
	h := NewHistory(maxCtx)
	h.Append(Message{Role: RoleSystem, Content: "sys"})
	for range n {
		h.Append(Message{
			Role:      RoleAssistant,
			Content:   big,
			ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
		})
		h.Append(Message{
			Role: RoleTool, ToolCallID: "t", ToolName: "t",
			Content: big, Summary120: "summary",
		})
	}
	return h
}

// assertToolPairing verifies every tool message traces back to an assistant-with-tool-calls.
func assertToolPairing(t *testing.T, snap []Message) {
	t.Helper()

	for i, m := range snap {
		if m.Role != RoleTool {
			continue
		}
		require.Positive(t, i)
		j := i - 1
		for j >= 0 && snap[j].Role == RoleTool {
			j--
		}
		require.GreaterOrEqual(t, j, 0)
		assert.Equal(t, RoleAssistant, snap[j].Role)
		assert.NotEmpty(t, snap[j].ToolCalls)
	}
}

func TestMergeReports(t *testing.T) {
	t.Parallel()

	t.Run("preserves_before_from_a", func(t *testing.T) {
		a := CompactionReport{Before: 5000, After: 4000, PassesApplied: []string{"error-collapse"}}
		b := CompactionReport{Before: 4000, After: 3000, PassesApplied: []string{"tool-stub"}}
		got := MergeReports(a, b)
		assert.Equal(t, 5000, got.Before)
		assert.Equal(t, 3000, got.After)
		assert.Equal(t, []string{"error-collapse", "tool-stub"}, got.PassesApplied)
	})

	t.Run("after_falls_back_to_a", func(t *testing.T) {
		a := CompactionReport{Before: 5000, After: 4200}
		b := CompactionReport{} // no work, After=0
		got := MergeReports(a, b)
		assert.Equal(t, 5000, got.Before)
		assert.Equal(t, 4200, got.After)
	})

	t.Run("counters_sum", func(t *testing.T) {
		a := CompactionReport{StubbedResults: 1, DroppedTurns: 2, SelfPrunedCalls: 3}
		b := CompactionReport{StubbedResults: 4, DroppedTurns: 5, SelfPrunedCalls: 6}
		got := MergeReports(a, b)
		assert.Equal(t, 5, got.StubbedResults)
		assert.Equal(t, 7, got.DroppedTurns)
		assert.Equal(t, 9, got.SelfPrunedCalls)
	})
}

func TestForceHardTruncate(t *testing.T) {
	t.Parallel()

	t.Run("reduces_and_pairs", func(t *testing.T) {
		big := strings.Repeat("y", 3_000)
		h := buildToolCallHistory(8192, big, 8)
		before := h.EstimateTokens()
		report := ForceHardTruncate(h, before/4, 2)

		assert.Contains(t, report.PassesApplied, "force-hard-truncate")
		assert.Less(t, h.EstimateTokens(), before)
		assert.Positive(t, report.DroppedTurns)
		assertToolPairing(t, h.Snapshot())
	})

	t.Run("under_target_noop", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.Append(Message{Role: RoleUser, Content: "hi"})
		report := ForceHardTruncate(h, 10_000, 2)
		assert.Zero(t, report.DroppedTurns)
		assert.Empty(t, report.PassesApplied)
	})
}

// buildErrorStreakHistory seeds n consecutive same-tool error tool-results after a single
// assistant tool_calls message. Drives CompactErrorsOnly's streak-collapse path.
func buildErrorStreakHistory(maxCtx int, n int) *History {
	h := NewHistory(maxCtx)
	h.Append(Message{Role: RoleSystem, Content: "sys"})
	calls := make([]ToolCall, n)
	for i := range calls {
		calls[i] = ToolCall{
			ID:       fmt.Sprintf("err%d", i),
			Function: ToolFunction{Name: "flaky", Arguments: "{}"},
		}
	}
	h.Append(Message{
		Role:      RoleAssistant,
		Content:   "calling flaky " + strconv.Itoa(n) + " times",
		ToolCalls: calls,
	})
	for i := range n {
		h.Append(Message{
			Role:       RoleTool,
			ToolCallID: fmt.Sprintf("err%d", i),
			ToolName:   "flaky",
			Content:    "ERROR: same failure mode " + strconv.Itoa(i) + " " + strings.Repeat("x", 1000),
			Summary120: "ERROR: same failure mode",
		})
	}
	h.Append(Message{Role: RoleUser, Content: "continue"})
	h.Append(Message{Role: RoleAssistant, Content: "ok"})
	return h
}

func TestCompactErrorsOnly(t *testing.T) {
	t.Parallel()

	t.Run("collapses_same_tool_streak", func(t *testing.T) {
		h := buildErrorStreakHistory(4096, 5)
		report := CompactErrorsOnly(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		assert.Contains(t, report.PassesApplied, "error-collapse")
		assert.Positive(t, report.CollapsedErrors)
		assert.Less(t, report.After, report.Before)
		// Must not run other passes
		assert.NotContains(t, report.PassesApplied, "tool-stub")
		assert.NotContains(t, report.PassesApplied, "think-strip")
	})

	t.Run("no_errors_noop", func(t *testing.T) {
		// Big history but no error streaks, nothing for pass 0 to do
		big := strings.Repeat("y", 3_000)
		h := buildToolCallHistory(8192, big, 6)
		report := CompactErrorsOnly(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		assert.Empty(t, report.PassesApplied)
		assert.Zero(t, report.CollapsedErrors)
	})
}

func TestCompactRemainder(t *testing.T) {
	t.Parallel()

	t.Run("runs_mechanical_passes", func(t *testing.T) {
		big := strings.Repeat("x", 6_000)
		h := buildFattyHistory(8192, big)
		before := h.EstimateTokens()
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		require.NoError(t, err)
		assert.NotContains(t, report.PassesApplied, "error-collapse")
		assert.Less(t, h.EstimateTokens(), before)
	})

	t.Run("think_strip_tool_stub", func(t *testing.T) {
		big := strings.Repeat("x", 6_000)
		h := buildFattyHistory(8192, big)
		before := h.EstimateTokens()
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		require.NoError(t, err)
		assert.Contains(t, report.PassesApplied, "think-strip")
		assert.Contains(t, report.PassesApplied, "tool-stub")
		assert.Less(t, report.After, before)
	})

	t.Run("drop_turn_fallback", func(t *testing.T) {
		big := strings.Repeat("y", 20_000)
		h := NewHistory(2048)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		for range 6 {
			h.Append(Message{
				Role:      RoleAssistant,
				Content:   big,
				ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: RoleTool, ToolCallID: "t", ToolName: "t",
				Content: big, Summary120: "summary",
			})
		}
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		require.Error(t, err)
		assert.Contains(t, report.PassesApplied, "turn-drop")
	})

	t.Run("fail_fast_no_truncate", func(t *testing.T) {
		big := strings.Repeat("z", 8_000)
		h := NewHistory(1024)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		for range 3 {
			h.Append(Message{Role: RoleAssistant, Content: big})
			h.Append(Message{Role: RoleUser, Content: big})
		}
		_, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 8,
			HardTruncateOnOverflow: false,
		})
		require.ErrorContains(t, err, "high watermark")
	})

	t.Run("under_target_noop", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.Append(Message{Role: RoleUser, Content: "hi"})
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 4,
		})
		require.NoError(t, err)
		assert.Empty(t, report.PassesApplied)
		assert.Equal(t, report.Before, report.After)
	})

	t.Run("repair_errors_protected", func(t *testing.T) {
		big := strings.Repeat("x", 6_000)
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys prompt"})
		repairText := `ERROR: arguments did not parse. schema: {"scope":"request_headers|request_body|response_headers|response_body|all"}`
		for i := range 5 {
			h.Append(Message{
				Role:      RoleAssistant,
				Content:   "try tool",
				ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "flow_get", Arguments: "{}"}}},
			})
			if i%2 == 0 {
				h.Append(Message{
					Role: RoleTool, ToolCallID: "t1", ToolName: "flow_get",
					Content: big, Summary120: Summarize120(big),
				})
			} else {
				h.Append(Message{
					Role: RoleTool, ToolCallID: "t1", ToolName: "flow_get",
					Content: repairText, Summary120: Summarize120(repairText),
					IsRepairError: true,
				})
			}
		}
		h.Append(Message{Role: RoleUser, Content: "continue"})
		h.Append(Message{Role: RoleAssistant, Content: "ok"})

		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		require.NoError(t, err)
		assert.Contains(t, report.PassesApplied, "tool-stub")
		assert.Positive(t, report.RepairsProtected)

		var repairs, stubbedNonRepairs int
		for _, m := range h.Snapshot() {
			if m.IsRepairError && strings.Contains(m.Content, "schema:") {
				repairs++
			}
			if m.Role == RoleTool && !m.IsRepairError && strings.Contains(m.Content, strings.Repeat("x", 200)) {
				stubbedNonRepairs++
			}
		}
		assert.Positive(t, repairs)
		assert.Zero(t, stubbedNonRepairs)
	})

	t.Run("think_strip_breaks_early", func(t *testing.T) {
		think := "<think>" + strings.Repeat("r", 2_000) + "</think>"
		h := NewHistory(4096)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		for range 6 {
			h.Append(Message{
				Role: RoleAssistant, Content: think + "answer",
				ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: RoleTool, ToolCallID: "t", ToolName: "t",
				Content: "ok", Summary120: "ok",
			})
		}
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 2,
		})
		require.NoError(t, err)
		assert.Contains(t, report.PassesApplied, "think-strip")
		assert.Positive(t, report.ThinkStripped)
		assert.Less(t, report.ThinkStripped, 4)
	})

	t.Run("uses_effective_max_context", func(t *testing.T) {
		big := strings.Repeat("y", 3_000)
		h := NewHistory(200_000)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		for range 6 {
			h.Append(Message{
				Role:      RoleAssistant,
				Content:   big,
				ToolCalls: []ToolCall{{ID: "t", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: RoleTool, ToolCallID: "t", ToolName: "t",
				Content: big, Summary120: "summary",
			})
		}

		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 4,
		})
		require.NoError(t, err)
		assert.Empty(t, report.PassesApplied)

		h.ShrinkEffectiveMaxOnRejection(25_000)
		report, err = CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 4,
			HardTruncateOnOverflow: true,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, report.PassesApplied)
	})

	t.Run("hard_truncate_on_overflow", func(t *testing.T) {
		big := strings.Repeat("y", 3_000)
		h := buildToolCallHistory(8192, big, 8)
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 4,
			HardTruncateOnOverflow: true,
		})
		require.NoError(t, err)
		assert.Contains(t, report.PassesApplied, "hard-truncate")
		assertToolPairing(t, h.Snapshot())
	})
}

func TestIsCompactionStub(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{name: "empty", content: ""},
		{name: "plain_prose", content: "200 OK with body bytes"},
		{name: "compacted_stub", content: "(compacted: tool returned ~123 tokens — summary)", want: true},
		{name: "distilled_batch", content: "(distilled batch 1: worker probed /admin and got 403)", want: true},
		{name: "error_text", content: "ERROR: invalid argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsCompactionStub(tc.content))
		})
	}
}

func TestStubToolResult(t *testing.T) {
	t.Parallel()

	t.Run("preserves_distilled", func(t *testing.T) {
		original := "(distilled batch 1: worker probed /admin, got 403)"
		m := Message{
			Role:       RoleTool,
			ToolCallID: "t1",
			ToolName:   "proxy_poll",
			Content:    original,
		}
		changed := StubToolResult(&m)
		assert.False(t, changed)
		assert.Equal(t, original, m.Content)
	})

	t.Run("preserves_existing_stub", func(t *testing.T) {
		original := "(compacted: proxy_poll returned ~50 tokens — flow ABC)"
		m := Message{Role: RoleTool, ToolCallID: "t1", ToolName: "proxy_poll", Content: original}
		changed := StubToolResult(&m)
		assert.False(t, changed)
		assert.Equal(t, original, m.Content)
	})

	t.Run("stubs_fresh_content", func(t *testing.T) {
		m := Message{
			Role: RoleTool, ToolCallID: "t1", ToolName: "proxy_poll",
			Content:    strings.Repeat("x", 500),
			Summary120: "summary",
		}
		changed := StubToolResult(&m)
		assert.True(t, changed)
		assert.True(t, strings.HasPrefix(m.Content, stubPrefix))
	})
}
