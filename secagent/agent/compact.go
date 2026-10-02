package agent

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-appsec/sectool-agents/secagent/util"
)

// CompactionOptions controls compaction thresholds.
type CompactionOptions struct {
	HighWatermark float64 // e.g. 0.80
	LowWatermark  float64 // e.g. 0.40
	KeepTurns     int     // e.g. 4
	// HardTruncateOnOverflow controls the final fallback. When true (default),
	// drops turns down to a 2-turn window. When false, returns the overflow error.
	HardTruncateOnOverflow bool
	// RecoveryThreshold is the fraction of EffectiveMaxContext that one compaction step must
	// free to skip later, more expensive ones. 0 falls back to defaultRecoveryThreshold.
	RecoveryThreshold float64
}

// TODO - tune defaultRecoveryThreshold based on history.CompactorOptions.OnCompact telemetry
const defaultRecoveryThreshold = 0.25

// CompactionReport describes the result of a Compact call.
type CompactionReport struct {
	Before           int
	After            int
	PassesApplied    []string
	StubbedResults   int
	DroppedTurns     int
	Truncated        int
	ThinkStripped    int
	RepairsProtected int // tool-result repair errors skipped from stubbing
	CollapsedErrors  int // redundant same-tool errors dropped
	SelfPrunedCalls  int // tool calls dropped by the self-prune callback
	DistilledResults int // tool results replaced with distilled prose
	AuxCallsSkipped  int // aux LLM calls denied by the per-pass aux call budget
}

// StripAssistantThink removes inline `<think>...</think>` blocks from m's Content.
// Returns true when Content changed. Non-assistant messages return false. Idempotent.
func StripAssistantThink(m *Message) bool {
	if m.Role != RoleAssistant {
		return false
	}
	before := m.Content
	after := StripThinkBlocks(before)
	if after == before {
		return false
	}
	m.Content = after
	return true
}

// Compaction-stub marker prefixes; new prefixes must also be added to IsCompactionStub.
const (
	stubPrefix    = "(compacted: "
	DistillPrefix = "(distilled batch "
)

// IsCompactionStub reports whether content carries any known compaction marker.
func IsCompactionStub(content string) bool {
	return strings.HasPrefix(content, stubPrefix) ||
		strings.HasPrefix(content, DistillPrefix)
}

// StubToolResult replaces m's Content with a compact stub and returns true when m.Content changed.
// Skips repair-error messages and content already stubbed. Idempotent.
func StubToolResult(m *Message) bool {
	if m.Role != RoleTool || m.IsRepairError {
		return false
	}
	if IsCompactionStub(m.Content) {
		return false
	}
	approxTokens := EstimateStringTokens(m.Content)
	toolName := m.ToolName
	if toolName == "" {
		toolName = "tool"
	}
	summary := m.Summary120
	if summary == "" {
		summary = util.Truncate(m.Content, 120)
	}
	stub := fmt.Sprintf(
		"%s%s returned ~%d tokens — %s)",
		stubPrefix, toolName, approxTokens, summary,
	)
	if m.Content == stub {
		return false
	}
	m.Content = stub
	return true
}

// ApplyCompactionDefaults fills zero-value fields in opt with package defaults and
// repairs incoherent settings so compaction can always make progress.
func ApplyCompactionDefaults(opt *CompactionOptions) {
	if opt.HighWatermark <= 0 {
		opt.HighWatermark = 0.80
	}
	if opt.LowWatermark <= 0 {
		opt.LowWatermark = 0.40
	}
	if opt.KeepTurns <= 0 {
		opt.KeepTurns = 4
	}
	if opt.RecoveryThreshold <= 0 {
		opt.RecoveryThreshold = defaultRecoveryThreshold
	}
	// target must sit below the trigger or the passes can never satisfy the final check
	if opt.LowWatermark >= opt.HighWatermark {
		opt.LowWatermark = opt.HighWatermark / 2
	}
}

// CompactErrorsOnly drops redundant repeated tool errors from h. Returns a report describing what changed.
func CompactErrorsOnly(h *History, opt CompactionOptions) CompactionReport {
	ApplyCompactionDefaults(&opt)
	before := h.EstimateTokens()
	report := CompactionReport{Before: before, After: before}
	maxCtx := h.EffectiveMaxContext()
	target := int(float64(maxCtx) * opt.LowWatermark)
	if before <= target {
		return report
	}
	msgs := h.Snapshot()
	if collapsed, dropped := collapseSameToolErrorStreaks(msgs); dropped > 0 {
		report.CollapsedErrors = dropped
		report.PassesApplied = append(report.PassesApplied, "error-collapse")
		h.ReplaceAll(collapsed)
	}
	report.After = h.EstimateTokens()
	return report
}

// CompactRemainder runs the post-self-prune compaction passes on h in
// place. Returns an error when h still exceeds HighWatermark.
func CompactRemainder(h *History, opt CompactionOptions) (CompactionReport, error) {
	ApplyCompactionDefaults(&opt)
	before := h.EstimateTokens()
	report := CompactionReport{Before: before, After: before}
	maxCtx := h.EffectiveMaxContext()
	target := int(float64(maxCtx) * opt.LowWatermark)
	high := int(float64(maxCtx) * opt.HighWatermark)
	if before <= target {
		return report, nil
	}

	msgs := h.Snapshot()
	// clamp so the keep window never covers the whole history
	keep := clampKeepTurns(msgs, opt.KeepTurns)

	// every pass protects the same trailing keep-turn window
	bound := KeepWindowStart(msgs, keep)

	// strip inline think from oldest assistants; trailing window keeps chain-of-thought continuity.
	// With a wire shape the wire already drops think from assistants outside the keep-think tail,
	// so only strip where the wire still carries it and the strip saves real tokens. One batched
	// write per pass keeps this O(n) instead of a clone + re-estimate per message.
	var thinkCount int
	wire := h.WireView(msgs)
	for i := 0; i < bound && i < len(wire); i++ {
		if msgs[i].Role != RoleAssistant || !HasInlineThink(wire[i].Content) {
			continue
		}
		if StripAssistantThink(&msgs[i]) {
			thinkCount++
		}
	}
	if thinkCount > 0 {
		// clone so later in-place passes never alias the live history
		h.ReplaceAll(slices.Clone(msgs))
		report.PassesApplied = append(report.PassesApplied, "think-strip")
		report.ThinkStripped = thinkCount
	}
	if h.EstimateTokens() <= target {
		report.After = h.EstimateTokens()
		return report, nil
	}

	// stub oldest tool results; repair errors carry schema guidance, skip them
	var stubbed, repairsProtected int
	for i := 0; i < bound; i++ {
		if msgs[i].Role != RoleTool {
			continue
		} else if msgs[i].IsRepairError {
			repairsProtected++
			continue
		}

		if StubToolResult(&msgs[i]) {
			stubbed++
			h.ReplaceAll(slices.Clone(msgs))
			if h.EstimateTokens() <= target {
				break
			}
		}
	}
	if stubbed > 0 {
		report.PassesApplied = append(report.PassesApplied, "tool-stub")
		report.StubbedResults = stubbed
	}
	report.RepairsProtected = repairsProtected
	if h.EstimateTokens() <= target {
		report.After = h.EstimateTokens()
		return report, nil
	}

	// Truncate older assistant content to its first sentence
	var truncCount int
	for i := 0; i < bound; i++ {
		if msgs[i].Role != RoleAssistant {
			continue
		} else if msgs[i].Content == "" {
			continue
		}

		first := msgs[i].Content
		for j, r := range msgs[i].Content {
			if r == '.' || r == '!' || r == '?' || r == '\n' {
				first = strings.TrimSpace(msgs[i].Content[:j+1])
				break
			}
		}
		if first != msgs[i].Content {
			msgs[i].Content = first
			truncCount++
			h.ReplaceAll(slices.Clone(msgs))
			if h.EstimateTokens() <= target {
				break
			}
		}
	}
	if truncCount > 0 {
		report.PassesApplied = append(report.PassesApplied, "text-trunc")
		report.Truncated = truncCount
	}
	if h.EstimateTokens() <= target {
		report.After = h.EstimateTokens()
		return report, nil
	}

	// Drop oldest full turn triples until under target or nothing left
	var droppedTurns int
	for h.EstimateTokens() > target {
		newMsgs, dropped := dropOldestTurn(msgs, keep)
		if !dropped {
			break
		}
		msgs = newMsgs
		droppedTurns++
		h.ReplaceAll(msgs)
	}
	if droppedTurns > 0 {
		report.PassesApplied = append(report.PassesApplied, "turn-drop")
		report.DroppedTurns = droppedTurns
	}

	// hard truncate: a single huge tool result can survive turn-drop;
	// shrink keep window to 2 to drop more while preserving tool pairing
	if opt.HardTruncateOnOverflow && h.EstimateTokens() > high {
		var hardDropped int
		for h.EstimateTokens() > high {
			newMsgs, dropped := dropOldestTurn(msgs, 2)
			if !dropped {
				break
			}
			msgs = newMsgs
			hardDropped++
			h.ReplaceAll(msgs)
		}
		if hardDropped > 0 {
			report.PassesApplied = append(report.PassesApplied, "hard-truncate")
			report.DroppedTurns += hardDropped
		}
	}

	after := h.EstimateTokens()
	report.After = after
	if after > high {
		return report, fmt.Errorf(
			"compaction could not reduce context below high watermark: %d > %d",
			after, high,
		)
	}
	return report, nil
}

// MergeReports concatenates PassesApplied and sums counters across a and b.
// Before is taken from a; After is b.After when non-zero, else a.After.
func MergeReports(a, b CompactionReport) CompactionReport {
	after := b.After
	if after == 0 {
		after = a.After
	}
	return CompactionReport{
		Before:           a.Before,
		After:            after,
		PassesApplied:    append(append([]string{}, a.PassesApplied...), b.PassesApplied...),
		StubbedResults:   a.StubbedResults + b.StubbedResults,
		DroppedTurns:     a.DroppedTurns + b.DroppedTurns,
		Truncated:        a.Truncated + b.Truncated,
		ThinkStripped:    a.ThinkStripped + b.ThinkStripped,
		RepairsProtected: a.RepairsProtected + b.RepairsProtected,
		CollapsedErrors:  a.CollapsedErrors + b.CollapsedErrors,
		SelfPrunedCalls:  a.SelfPrunedCalls + b.SelfPrunedCalls,
		DistilledResults: a.DistilledResults + b.DistilledResults,
		AuxCallsSkipped:  a.AuxCallsSkipped + b.AuxCallsSkipped,
	}
}

// ForceHardTruncate drops oldest turns from h until estimated tokens <= targetTokens, preserving the
// system prompt and a trailing keep-turn window (keep is floored at 2). Returns a report of what was done.
func ForceHardTruncate(h *History, targetTokens, keep int) CompactionReport {
	if keep < 2 {
		keep = 2
	}
	report := CompactionReport{Before: h.EstimateTokens()}
	msgs := h.Snapshot()
	var dropped int
	for h.EstimateTokens() > targetTokens {
		next, ok := dropOldestTurn(msgs, keep)
		if !ok {
			break
		}
		msgs = next
		dropped++
		h.ReplaceAll(msgs)
	}
	if dropped > 0 {
		report.PassesApplied = append(report.PassesApplied, "force-hard-truncate")
		report.DroppedTurns = dropped
	}
	report.After = h.EstimateTokens()
	return report
}

// dropOldestTurn removes the oldest assistant-tool-calls turn (paired tool results plus a trailing assistant text) from
// msgs, keeping the system prompt and the trailing keep-turn window. Returns the new slice and whether a turn was dropped.
func dropOldestTurn(msgs []Message, keep int) ([]Message, bool) {
	if keep < 2 {
		keep = 2
	}
	floor := systemFloor(msgs)
	ceil := KeepWindowStart(msgs, keep)
	if ceil <= floor {
		return msgs, false
	}

	for i := floor; i < ceil; i++ {
		if msgs[i].Role != RoleAssistant {
			continue
		}
		end := i + 1
		// consume paired tool results
		for end < len(msgs) && msgs[end].Role == RoleTool {
			end++
		}
		// consume a trailing assistant TEXT (no tool calls of its own) if it
		// immediately follows, it's part of this same turn's final reply.
		// Do NOT swallow the next turn's assistant-with-tool-calls; doing so
		// would orphan its tool results.
		if end < len(msgs) && msgs[end].Role == RoleAssistant && len(msgs[end].ToolCalls) == 0 {
			end++
		}
		if end > ceil {
			return msgs, false
		}
		out := make([]Message, 0, len(msgs)-(end-i))
		out = append(out, msgs[:i]...)
		out = append(out, msgs[end:]...)
		return out, true
	}
	return msgs, false
}

// clampKeepTurns caps keep so the protected window leaves at least one turn
// compactable; an oversized keep would otherwise turn every pass into a no-op.
func clampKeepTurns(msgs []Message, keep int) int {
	if n := len(turnStarts(msgs)); n > 1 {
		return min(keep, n-1)
	}
	return keep
}

// systemFloor returns the first message index after a leading system prompt.
func systemFloor(msgs []Message) int {
	if len(msgs) > 0 && msgs[0].Role == RoleSystem {
		return 1
	}
	return 0
}

// turnStarts returns the start index of every assistant-led turn in msgs,
// matching the turn-splitting in dropOldestTurn.
func turnStarts(msgs []Message) []int {
	var starts []int
	for i := systemFloor(msgs); i < len(msgs); {
		if msgs[i].Role != RoleAssistant {
			i++
			continue
		}
		starts = append(starts, i)
		i++
		for i < len(msgs) && msgs[i].Role == RoleTool {
			i++
		}
		if i < len(msgs) && msgs[i].Role == RoleAssistant && len(msgs[i].ToolCalls) == 0 {
			i++
		}
	}
	return starts
}

// KeepWindowStart returns the index of the first message in the trailing keep-turn window
// that compaction must leave untouched. A turn is an assistant message through its paired
// tool results plus an immediately following text assistant, matching the turn-splitting
// in dropOldestTurn. When fewer than keep turns exist the whole history minus the system
// prompt is protected. keep is floored at 1.
func KeepWindowStart(msgs []Message, keep int) int {
	if keep < 1 {
		keep = 1
	}
	floor := systemFloor(msgs)
	starts := turnStarts(msgs)
	if len(starts) <= keep {
		return floor
	}
	return starts[len(starts)-keep]
}
