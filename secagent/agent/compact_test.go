package agent

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
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

func TestKeepWindowStart(t *testing.T) {
	t.Parallel()

	// toolTurn is one assistant-with-tool-calls message plus its paired result.
	toolTurn := func(id string) []Message {
		return []Message{
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: id, Function: ToolFunction{Name: "t"}}}},
			{Role: RoleTool, ToolCallID: id, ToolName: "t"},
		}
	}

	t.Run("counts_turns_not_messages", func(t *testing.T) {
		msgs := make([]Message, 0, 11)
		msgs = append(msgs, Message{Role: RoleSystem, Content: "sys"})
		for i := range 5 {
			msgs = append(msgs, toolTurn(strconv.Itoa(i))...)
		}
		// keep=2 protects the last two turns, not the last four messages
		assert.Equal(t, 7, KeepWindowStart(msgs, 2))
	})

	t.Run("trailing_text_part_of_turn", func(t *testing.T) {
		msgs := slices.Concat(
			[]Message{{Role: RoleSystem, Content: "sys"}},
			toolTurn("t1"),
			[]Message{{Role: RoleAssistant, Content: "done"}},
		)
		// the trailing text reply belongs to the turn, no phantom turn is counted
		assert.Equal(t, 1, KeepWindowStart(msgs, 1))
	})

	t.Run("text_reply_after_user_counts", func(t *testing.T) {
		msgs := slices.Concat(
			[]Message{{Role: RoleSystem, Content: "sys"}},
			toolTurn("t1"),
			[]Message{{Role: RoleUser, Content: "go on"}, {Role: RoleAssistant, Content: "ok"}},
		)
		assert.Equal(t, 1, KeepWindowStart(msgs, 2))
	})

	t.Run("fewer_turns_protects_all", func(t *testing.T) {
		msgs := slices.Concat(
			[]Message{{Role: RoleSystem, Content: "sys"}},
			toolTurn("t1"),
		)
		assert.Equal(t, 1, KeepWindowStart(msgs, 4))
	})

	t.Run("no_system_prompt", func(t *testing.T) {
		msgs := slices.Concat(toolTurn("t1"), toolTurn("t2"))
		assert.Equal(t, 2, KeepWindowStart(msgs, 1))
	})

	t.Run("empty_history", func(t *testing.T) {
		assert.Zero(t, KeepWindowStart(nil, 3))
	})

	t.Run("keep_floored_at_one", func(t *testing.T) {
		msgs := slices.Concat(
			[]Message{{Role: RoleSystem, Content: "sys"}},
			toolTurn("t1"), toolTurn("t2"),
		)
		assert.Equal(t, KeepWindowStart(msgs, 1), KeepWindowStart(msgs, 0))
	})

	// Regression: a window computed in messages (keep*2) lets turn-drop eat into
	// turns the user asked to protect when turns carry multiple tool results.
	t.Run("tool_heavy_window", func(t *testing.T) {
		big := strings.Repeat("x", 3_000)
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		for i := range 8 {
			calls := make([]ToolCall, 3)
			for j := range calls {
				calls[j] = ToolCall{ID: fmt.Sprintf("t%d_%d", i, j), Function: ToolFunction{Name: "t"}}
			}
			h.Append(Message{Role: RoleAssistant, Content: big, ToolCalls: calls})
			for _, tc := range calls {
				h.Append(Message{Role: RoleTool, ToolCallID: tc.ID, ToolName: "t", Content: big, Summary120: "s"})
			}
		}
		report := ForceHardTruncate(h, 1, 2)
		assert.Positive(t, report.DroppedTurns)

		snap := h.Snapshot()
		// system prompt plus the last two turns survive intact
		require.Len(t, snap, 9)
		assertToolPairing(t, snap)
		for _, m := range snap[7:] {
			if m.Role == RoleTool {
				assert.Equal(t, big, m.Content)
			}
		}
	})
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
		a := CompactionReport{StubbedResults: 1, DroppedTurns: 2, SelfPrunedCalls: 3, AuxCallsSkipped: 7}
		b := CompactionReport{StubbedResults: 4, DroppedTurns: 5, SelfPrunedCalls: 6, AuxCallsSkipped: 8}
		got := MergeReports(a, b)
		assert.Equal(t, 5, got.StubbedResults)
		assert.Equal(t, 7, got.DroppedTurns)
		assert.Equal(t, 9, got.SelfPrunedCalls)
		assert.Equal(t, 15, got.AuxCallsSkipped)
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

// Regression: ReplaceAll used to zero the token anchor mid-pass, flipping the estimate
// basis so a nearly no-op pass could appear to reach the low-watermark target.
func TestCompactRemainder_AnchorBasis(t *testing.T) {
	t.Parallel()

	t.Run("no_op_pass_does_not_hit_target", func(t *testing.T) {
		// model-scoped so SetPromptTokens cannot shift the shared calibration bucket
		// other parallel tests estimate with
		const model = "compact-anchor-basis"
		h := NewHistoryForModel(4096, model, nil)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.Append(Message{Role: RoleUser, Content: strings.Repeat("u", 400)})
		for i := range 6 {
			id := strconv.Itoa(i)
			h.Append(Message{
				Role:      RoleAssistant,
				ToolCalls: []ToolCall{{ID: id, Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: RoleTool, ToolCallID: id, ToolName: "t",
				Content: strings.Repeat("r", 300), Summary120: "result",
			})
			h.Append(Message{Role: RoleAssistant, Content: "step " + id + " done."})
		}
		// anchor well above the raw estimate, as the server-reported count does
		h.SetPromptTokens(3000)
		before := h.EstimateTokens()
		require.Greater(t, before, 1638) // above the low-watermark target

		report, err := CompactRemainder(h, CompactionOptions{HardTruncateOnOverflow: true})
		require.NoError(t, err)
		// the mechanical passes free little, so reaching the target requires the
		// turn-drop pass instead of an early basis-flip stop
		assert.Contains(t, report.PassesApplied, "turn-drop")
		assert.Less(t, report.After, before)
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
			IsError:    true,
		})
	}
	h.Append(Message{Role: RoleUser, Content: "continue"})
	h.Append(Message{Role: RoleAssistant, Content: "ok"})
	return h
}

func TestApplyCompactionDefaults(t *testing.T) {
	t.Parallel()

	t.Run("fills_zero_values", func(t *testing.T) {
		var opt CompactionOptions
		ApplyCompactionDefaults(&opt)
		assert.InDelta(t, 0.80, opt.HighWatermark, 0)
		assert.InDelta(t, 0.40, opt.LowWatermark, 0)
		assert.Equal(t, 4, opt.KeepTurns)
		assert.InDelta(t, defaultRecoveryThreshold, opt.RecoveryThreshold, 0)
	})

	t.Run("preserves_explicit_values", func(t *testing.T) {
		opt := CompactionOptions{HighWatermark: 0.9, LowWatermark: 0.3, KeepTurns: 6, RecoveryThreshold: 0.5}
		ApplyCompactionDefaults(&opt)
		assert.InDelta(t, 0.9, opt.HighWatermark, 0)
		assert.InDelta(t, 0.3, opt.LowWatermark, 0)
		assert.Equal(t, 6, opt.KeepTurns)
		assert.InDelta(t, 0.5, opt.RecoveryThreshold, 0)
	})

	t.Run("repairs_inverted_watermarks", func(t *testing.T) {
		opt := CompactionOptions{HighWatermark: 0.5, LowWatermark: 0.9}
		ApplyCompactionDefaults(&opt)
		assert.Less(t, opt.LowWatermark, opt.HighWatermark)
	})
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
		require.ErrorIs(t, err, ErrContextExhausted)
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

	t.Run("oversized_keep_turns_degrades", func(t *testing.T) {
		big := strings.Repeat("x", 6_000)
		h := buildFattyHistory(26_000, big)
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 64,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, report.PassesApplied)
	})

	t.Run("inverted_watermarks_repaired", func(t *testing.T) {
		big := strings.Repeat("x", 6_000)
		h := buildFattyHistory(8192, big)
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.90, KeepTurns: 1,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, report.PassesApplied)
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

	t.Run("think_strip_batched", func(t *testing.T) {
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
		// every think-carrying assistant outside the keep window is stripped in one pass
		assert.Equal(t, 4, report.ThinkStripped)
		assert.Less(t, report.After, report.Before)
	})

	// Regression: with the production wire shape the estimate already excludes think on
	// assistants outside the keep-think tail, so stripping stored content there destroys
	// chain-of-thought without saving any tokens.
	t.Run("wire_shape_skips_stale_strip", func(t *testing.T) {
		const model = "compact-wire-stale"
		big := strings.Repeat("x", 6_000)
		h := NewHistoryForModel(8192, model, func(msgs []Message) []Message {
			return inlineHandler{}.Replay(msgs, 1)
		})
		h.Append(Message{Role: RoleSystem, Content: "sys prompt"})
		for i := range 5 {
			id := strconv.Itoa(i)
			h.Append(Message{
				Role:      RoleAssistant,
				Content:   "< think>deliberation " + id + "< /think>step " + id + " done",
				ToolCalls: []ToolCall{{ID: id, Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: RoleTool, ToolCallID: id, ToolName: "t",
				Content: big, Summary120: Summarize120(big),
			})
		}
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		require.NoError(t, err)
		// the wire already strips these assistants, so the pass must not fire
		assert.NotContains(t, report.PassesApplied, "think-strip")
		assert.Contains(t, report.PassesApplied, "tool-stub")
		for i, m := range h.Snapshot() {
			if m.Role == RoleAssistant {
				assert.Contains(t, m.Content, "< think>", "assistant %d lost stored think", i)
			}
		}
	})

	// Assistants the wire still carries think on but that fall outside the keep window
	// (tool-heavy turns shrink the message window below the think tail) are legitimate
	// strip targets.
	t.Run("wire_shape_strips_live_think", func(t *testing.T) {
		const model = "compact-wire-live"
		think := "< think>" + strings.Repeat("r", 6_000) + "< /think>answer"
		h := NewHistoryForModel(4096, model, func(msgs []Message) []Message {
			return inlineHandler{}.Replay(msgs, 2)
		})
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		for i := range 3 {
			id := strconv.Itoa(i)
			content := "plain reply"
			if i > 0 {
				content = think
			}
			h.Append(Message{
				Role:      RoleAssistant,
				Content:   content,
				ToolCalls: []ToolCall{{ID: id, Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: RoleTool, ToolCallID: id, ToolName: "t",
				Content: "ok", Summary120: "ok",
			})
		}
		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.80, LowWatermark: 0.40, KeepTurns: 1,
		})
		require.NoError(t, err)
		// only the middle assistant is both wire-retained and outside the keep window
		assert.Equal(t, []string{"think-strip"}, report.PassesApplied)
		assert.Equal(t, 1, report.ThinkStripped)

		snap := h.Snapshot()
		assert.Contains(t, snap[1].Content, "plain reply")
		assert.NotContains(t, snap[3].Content, "< think>")
		assert.Contains(t, snap[5].Content, "< think>")
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

	// Regression: when the protected tail alone exceeds the high watermark every
	// drop pass is a no-op and the agent wedged on repeated terminal errors. The
	// last-resort tail-stub pass must stub tail tool results (pairing preserved).
	t.Run("tail_stub_rescues_protected_tail", func(t *testing.T) {
		big := strings.Repeat("x", 6_000)
		h := NewHistory(1024)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.Append(Message{
			Role:      RoleAssistant,
			Content:   "probe done",
			ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
		})
		h.Append(Message{
			Role: RoleTool, ToolCallID: "t1", ToolName: "t",
			Content: big, Summary120: "summary",
		})

		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 4,
			HardTruncateOnOverflow: true,
		})
		require.NoError(t, err)
		assert.Contains(t, report.PassesApplied, "tail-stub")
		assert.Less(t, report.After, report.Before)

		snap := h.Snapshot()
		assertToolPairing(t, snap)
		assert.Equal(t, "probe done", snap[1].Content)
		assert.True(t, IsCompactionStub(snap[2].Content))
	})

	// Regression: turn-drop only starts on assistants, so a history dominated by
	// large user directives (installed via ReplaceHistory) could never shrink.
	t.Run("user_drop_unblocks_directive_views", func(t *testing.T) {
		big := strings.Repeat("u", 8_000)
		h := NewHistory(4096)
		h.Append(Message{Role: RoleSystem, Content: "sys prompt"})
		h.Append(Message{Role: RoleUser, Content: big})
		for i := range 3 {
			id := strconv.Itoa(i)
			h.Append(Message{
				Role:      RoleAssistant,
				Content:   "step " + id + ".",
				ToolCalls: []ToolCall{{ID: id, Function: ToolFunction{Name: "t", Arguments: "{}"}}},
			})
			h.Append(Message{
				Role: RoleTool, ToolCallID: id, ToolName: "t",
				Content: "ok", Summary120: "ok",
			})
		}

		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 4,
		})
		require.NoError(t, err)
		assert.Contains(t, report.PassesApplied, "user-drop")
		assert.Positive(t, report.DroppedUsers)

		snap := h.Snapshot()
		assert.Equal(t, "sys prompt", snap[0].Content)
		for _, m := range snap[1:] {
			assert.NotEqual(t, RoleUser, m.Role)
		}
	})

	// The tail-stub rescue is part of the hard-truncate fallback family; the
	// fail-fast option must keep returning the overflow error.
	t.Run("fail_fast_skips_tail_stub", func(t *testing.T) {
		big := strings.Repeat("x", 6_000)
		h := NewHistory(1024)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.Append(Message{
			Role:      RoleAssistant,
			Content:   "probe done",
			ToolCalls: []ToolCall{{ID: "t1", Function: ToolFunction{Name: "t", Arguments: "{}"}}},
		})
		h.Append(Message{
			Role: RoleTool, ToolCallID: "t1", ToolName: "t",
			Content: big, Summary120: "summary",
		})
		_, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 4,
			HardTruncateOnOverflow: false,
		})
		require.ErrorIs(t, err, ErrContextExhausted)
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

	// Regression for the in-place compaction race: the narrator reads an agent's
	// history (Snapshot/EstimateTokens, both locked) while CompactRemainder runs
	// its in-place passes. Fails under -race if the passes mutate the live
	// backing array without the lock.
	t.Run("concurrent_readers_race", func(t *testing.T) {
		big := strings.Repeat("x", 6_000)
		h := buildFattyHistory(8192, big)

		stop := make(chan struct{})
		var readers sync.WaitGroup
		for range 4 {
			readers.Add(1)
			go func() {
				defer readers.Done()
				for {
					select {
					case <-stop:
						return
					default:
						_ = h.Snapshot()
						_ = h.EstimateTokens()
					}
				}
			}()
		}

		report, err := CompactRemainder(h, CompactionOptions{
			HighWatermark: 0.50, LowWatermark: 0.20, KeepTurns: 1,
		})
		close(stop)
		readers.Wait()

		require.NoError(t, err)
		assert.NotEmpty(t, report.PassesApplied)
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
