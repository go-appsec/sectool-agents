package agent

import (
	"fmt"
	"strings"

	"github.com/go-appsec/secagent/util"
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

// ApplyCompactionDefaults fills zero-value fields in opt with package defaults.
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
	keep := opt.KeepTurns

	// strip <think> from oldest assistants; keep*2 trailing window stays for chain-of-thought continuity
	var thinkCount int
	for i := 0; i < len(msgs)-keep*2; i++ {
		if !StripAssistantThink(&msgs[i]) {
			continue
		}

		thinkCount++
		h.ReplaceAll(msgs)
		if h.EstimateTokens() <= target {
			break
		}
	}
	if thinkCount > 0 {
		report.PassesApplied = append(report.PassesApplied, "think-strip")
		report.ThinkStripped = thinkCount
	}
	if h.EstimateTokens() <= target {
		report.After = h.EstimateTokens()
		return report, nil
	}

	// stub oldest tool results; repair errors carry schema guidance, skip them
	var stubbed, repairsProtected int
	for i := 0; i < len(msgs)-keep*2; i++ {
		if msgs[i].Role != RoleTool {
			continue
		} else if msgs[i].IsRepairError {
			repairsProtected++
			continue
		}

		if StubToolResult(&msgs[i]) {
			stubbed++
			h.ReplaceAll(msgs)
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
	for i := 0; i < len(msgs)-keep*2; i++ {
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
			h.ReplaceAll(msgs)
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
	}
}

// ForceHardTruncate drops oldest turns from h until estimated tokens <= targetTokens, preserving the
// system prompt and a trailing keep*2 window (keep is floored at 2). Returns a report of what was done.
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
// msgs, keeping the system prompt and the trailing keep*2 window. Returns the new slice and whether a turn was dropped.
func dropOldestTurn(msgs []Message, keep int) ([]Message, bool) {
	if keep < 2 {
		keep = 2
	}
	var floor int
	if len(msgs) > 0 && msgs[0].Role == "system" {
		floor = 1
	}
	ceil := len(msgs) - keep*2
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
