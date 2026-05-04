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
