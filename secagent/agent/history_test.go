package agent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistory_ShrinkEffectiveMaxOnRejection(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		maxCtx    int
		rejects   []int
		wantEffMx int
	}{
		{name: "clamps_to_80_percent", maxCtx: 250_000, rejects: []int{200_000}, wantEffMx: 160_000},
		{name: "sticky_downward_only", maxCtx: 250_000, rejects: []int{200_000, 180_000, 250_000}, wantEffMx: 144_000},
		{name: "floored_to_prevent_cripple", maxCtx: 250_000, rejects: []int{1000}, wantEffMx: 4096},
		{name: "zero_or_negative_noop", maxCtx: 250_000, rejects: []int{0, -5}, wantEffMx: 250_000},
		{name: "rejection_above_max_noop", maxCtx: 100_000, rejects: []int{150_000}, wantEffMx: 100_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHistory(tc.maxCtx)
			for _, r := range tc.rejects {
				h.ShrinkEffectiveMaxOnRejection(r)
			}
			assert.Equal(t, tc.wantEffMx, h.EffectiveMaxContext())
		})
	}
}

func TestHistory_TokenTracking(t *testing.T) {
	// Serial: SetPromptTokens mutates the process-wide calibration EMA
	t.Cleanup(resetCalibrationForTest)
	h := NewHistory(4096)
	assert.Equal(t, 4096, h.MaxContext())
	h.Append(Message{Role: RoleSystem, Content: "sys"})
	h.Append(Message{Role: RoleUser, Content: "hello world hello world"})
	assert.Positive(t, h.EstimateTokens())

	h.SetPromptTokens(2048)
	assert.Equal(t, 2048, h.EstimateTokens())

	h.Append(Message{Role: RoleAssistant, Content: "ok"})
	assert.Greater(t, h.EstimateTokens(), 2048)
}

func TestHistory_Calibration(t *testing.T) {
	// Serial: each subtest mutates the process-wide calibration EMA
	t.Run("starts_at_one", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		assert.InDelta(t, 1.0, h.Calibration(), 0.001)
	})

	t.Run("under_count_raises", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		for range 10 {
			h.Append(Message{Role: RoleUser, Content: "abcdefghij"})
		}
		// raw ~69 tokens, reported 200 -> observed ratio ~2.9; EMA alpha=0.3 lands ~1.57
		h.SetPromptTokens(200)
		assert.InDelta(t, 1.57, h.Calibration(), 0.2)
	})

	t.Run("clamped_to_bounds", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		h.Append(Message{Role: RoleUser, Content: "hi"})
		h.SetPromptTokens(1_000_000)
		assert.InDelta(t, calibrationMax, h.Calibration(), 0.001)
	})

	t.Run("ema_converges", func(t *testing.T) {
		resetCalibrationForTest()
		t.Cleanup(resetCalibrationForTest)
		h := NewHistory(8192)
		h.Append(Message{Role: RoleUser, Content: strings.Repeat("x", 400)})
		// raw 104, real 208 -> ratio 2.0; EMA converges over many updates
		for range 50 {
			h.SetPromptTokens(208)
		}
		assert.InDelta(t, 2.0, h.Calibration(), 0.05)
	})
}

func TestHistory_WireShape(t *testing.T) {
	// Serial: SetPromptTokens mutates the shared calibration EMA, so each subtest
	// uses its own model bucket to stay isolated.
	t.Cleanup(resetCalibrationForTest)

	stripAll := func(msgs []Message) []Message { return FilterThinkBlocks(msgs, 0) }
	thinkContent := "<think>" + strings.Repeat("t", 400) + "</think>"

	t.Run("estimate_uses_wire_shape", func(t *testing.T) {
		h := NewHistoryForModel(8192, "wire-est", stripAll)
		h.Append(Message{Role: RoleUser, Content: strings.Repeat("a", 400)})
		h.Append(Message{Role: RoleAssistant, Content: thinkContent})
		// Stored raw is 211; the wire shape strips the think block leaving 108.
		assert.Equal(t, 108, h.EstimateTokens())
	})

	t.Run("calibration_uses_wire_estimate", func(t *testing.T) {
		h := NewHistoryForModel(8192, "wire-cal", stripAll)
		h.Append(Message{Role: RoleUser, Content: strings.Repeat("a", 400)})
		h.Append(Message{Role: RoleAssistant, Content: thinkContent})
		// real 216 over wire raw 108 -> observed ratio 2.0; stored raw would give ~1.02.
		h.RecordWireEstimate(108)
		h.SetPromptTokens(216)
		assert.InDelta(t, 1.3, h.Calibration(), 0.001)
	})

	t.Run("growth_uses_wire_shape", func(t *testing.T) {
		h := NewHistoryForModel(8192, "wire-growth", stripAll)
		h.Append(Message{Role: RoleUser, Content: strings.Repeat("a", 400)})
		h.RecordWireEstimate(104)
		h.SetPromptTokens(104)
		h.Append(Message{Role: RoleAssistant, Content: thinkContent})
		// Growth is estimated over the stripped shape, not the stored think content.
		assert.Equal(t, 108, h.EstimateTokens())
	})

	t.Run("wire_estimate_reset_on_replace", func(t *testing.T) {
		h := NewHistoryForModel(8192, "wire-reset", nil)
		h.RecordWireEstimate(100)
		h.ReplaceAll(nil)
		h.Append(Message{Role: RoleUser, Content: strings.Repeat("a", 400)})
		// Falls back to the stored-shape estimate once the wire estimate is cleared.
		h.SetPromptTokens(208)
		assert.InDelta(t, 1.3, h.Calibration(), 0.001)
	})
}

func TestHistory_ReplaceAllAnchor(t *testing.T) {
	// Serial: SetPromptTokens mutates the process-wide calibration EMA
	t.Cleanup(resetCalibrationForTest)

	t.Run("identical_replace_keeps_estimate", func(t *testing.T) {
		resetCalibrationForTest()
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.Append(Message{Role: RoleUser, Content: "hello world hello world"})
		h.SetPromptTokens(1000)
		h.Append(Message{Role: RoleUser, Content: strings.Repeat("g", 400)})
		anchored := h.EstimateTokens() // server count plus growth

		h.ReplaceAll(h.Snapshot())
		assert.Equal(t, anchored, h.EstimateTokens())
	})

	t.Run("shrink_carries_server_overhead", func(t *testing.T) {
		resetCalibrationForTest()
		sys := Message{Role: RoleSystem, Content: "sys"}
		h := NewHistory(8192)
		h.Append(sys)
		h.Append(Message{Role: RoleUser, Content: strings.Repeat("a", 400)})
		h.SetPromptTokens(1000)

		h.ReplaceAll([]Message{sys})
		// the prompt-side overhead survives the swap, keeping the estimate above
		// the raw estimate of the surviving message alone
		assert.Greater(t, h.EstimateTokens(), EstimateMessageTokens(sys))
	})
}

func TestHistory_ReplaceAllIfUnchanged(t *testing.T) {
	t.Parallel()

	t.Run("applies_when_unchanged", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: RoleUser, Content: "u1"})
		gen := h.Generation()

		ok := h.ReplaceAllIfUnchanged(gen, []Message{{Role: RoleUser, Content: "replaced"}})

		assert.True(t, ok)
		assert.Equal(t, "replaced", h.Snapshot()[0].Content)
		assert.NotEqual(t, gen, h.Generation())
	})

	t.Run("stale_generation_aborts", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: RoleUser, Content: "u1"})
		gen := h.Generation()
		h.Append(Message{Role: RoleUser, Content: "u2"})

		ok := h.ReplaceAllIfUnchanged(gen, []Message{{Role: RoleUser, Content: "replaced"}})

		assert.False(t, ok)
		assert.Len(t, h.Snapshot(), 2)
	})
}

func TestHistory_IterationBoundaryID(t *testing.T) {
	t.Parallel()

	t.Run("unset_returns_zero", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.Append(Message{Role: RoleUser, Content: "hi"})
		assert.Zero(t, h.IterationBoundaryID())
	})

	t.Run("mark_records_nextid", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.Append(Message{Role: RoleUser, Content: "before"})
		h.MarkIterationBoundary()
		watermark := h.IterationBoundaryID()
		require.Equal(t, h.Snapshot()[1].HistoryID, watermark)

		h.Append(Message{Role: RoleAssistant, Content: "iter"})
		assert.Greater(t, h.Snapshot()[2].HistoryID, watermark)
	})

	t.Run("watermark_survives_replaceall", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.Append(Message{Role: RoleUser, Content: "old1"})
		h.Append(Message{Role: RoleUser, Content: "old2"})
		h.MarkIterationBoundary()
		watermark := h.IterationBoundaryID()
		h.Append(Message{Role: RoleAssistant, Content: "iter content"})
		iterID := h.Snapshot()[3].HistoryID

		// Drop the two pre-boundary user messages, keep system + iter content.
		snap := h.Snapshot()
		h.ReplaceAll([]Message{snap[0], snap[3]})

		assert.Equal(t, watermark, h.IterationBoundaryID())
		// Iter message keeps its ID; still > watermark.
		assert.Equal(t, iterID, h.Snapshot()[1].HistoryID)
		assert.Greater(t, h.Snapshot()[1].HistoryID, h.IterationBoundaryID())
	})

	t.Run("salvages_surviving_tail_when_boundary_msg_dropped", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.MarkIterationBoundary()
		h.Append(Message{Role: RoleUser, Content: "u1"})
		h.Append(Message{Role: RoleAssistant, Content: "a1"})
		h.Append(Message{Role: RoleAssistant, Content: "a2"})
		watermark := h.IterationBoundaryID()
		survivorID := h.Snapshot()[3].HistoryID

		// Drop the first iter message but retain a later one, the watermark
		// stays valid and the survivor is still classified as iter content.
		snap := h.Snapshot()
		h.ReplaceAll([]Message{snap[0], snap[3]})

		assert.Equal(t, watermark, h.IterationBoundaryID())
		assert.Greater(t, survivorID, watermark)
	})

	t.Run("reset_clears_watermark", func(t *testing.T) {
		h := NewHistory(8192)
		h.Append(Message{Role: RoleSystem, Content: "sys"})
		h.Append(Message{Role: RoleUser, Content: "u1"})
		h.MarkIterationBoundary()
		require.NotZero(t, h.IterationBoundaryID())
		h.ResetIterationBoundary()
		assert.Zero(t, h.IterationBoundaryID())
	})
}
