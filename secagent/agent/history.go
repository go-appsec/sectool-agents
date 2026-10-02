package agent

import (
	"slices"
	"sync"

	"github.com/go-appsec/sectool-agents/secagent/util"
)

// Message is one entry in an agent's history.
type Message struct {
	Role    string // system | user | assistant | tool
	Content string // for assistant+tool_calls this may be empty
	// HistoryID is an internal stable identity assigned by History so boundary tracking
	// survives compaction/truncation even when multiple messages have identical role/content.
	HistoryID uint64
	// ReasoningContent holds structured reasoning from the `reasoning_content` response field.
	// Inline-think models leave this empty and embed thinking in Content as <think>...</think>.
	ReasoningContent string
	ToolCalls        []ToolCall // assistant only
	ToolCallID       string     // tool only, pairs with assistant.tool_calls[i].ID
	ToolName         string     // tool only, populated at append for compaction stubs
	Summary120       string     // tool only, first 120 chars of raw content at append
	// IsError marks a tool result whose dispatch recorded an error. Set at
	// dispatch time; the single source of truth for error classification.
	IsError bool
	// IsRepairError marks a tool-result from RepairToolArgs failure. Compaction pass 2 skips these
	// so the model doesn't repeat the malformed call after the error context is removed.
	IsRepairError bool
}

// IsErrorResult reports whether m is a tool result flagged as an error.
// Repair errors always classify as errors.
func (m Message) IsErrorResult() bool {
	if m.Role != RoleTool {
		return false
	}
	return m.IsError || m.IsRepairError
}

// History is a goroutine-safe message log for one agent.
type History struct {
	mu       sync.Mutex
	messages []Message
	// model scopes the token calibration; wireShape maps stored messages to
	// the shape sent on the wire before estimation (nil keeps stored shape).
	model     string
	wireShape func([]Message) []Message
	// wireRaw is the last recorded uncalibrated estimate of the wire shape.
	wireRaw          int
	lastPromptTokens int
	baselineMsgCount int // messages length when lastPromptTokens was recorded
	maxContext       int
	// effectiveMax is a sticky-downward ceiling applied after upstream rejects
	// a request as too large. 0 means "use maxContext". Only shrinks, never grows.
	effectiveMax int
	nextID       uint64
	// iterStartID is the HistoryID watermark recorded at iter start.
	// Iter content = messages with HistoryID > iterStartID.
	iterStartID uint64
	// version bumps on every mutation; guards compaction write-backs
	// via ReplaceAllIfUnchanged.
	version uint64
}

const (
	// effectiveMaxFloor prevents a runaway rejection from shrinking the
	// ceiling to something the agent cannot function inside.
	effectiveMaxFloor = 4096
	// rejectionShrinkRatio scales the estimate-at-rejection down so the
	// new ceiling is meaningfully below the value the model just refused.
	rejectionShrinkRatio = 0.80
)

// NewHistory returns an empty History with the given context ceiling.
func NewHistory(maxContext int) *History {
	return NewHistoryForModel(maxContext, "", nil)
}

// NewHistoryForModel returns an empty History with the given context ceiling and model-scoped
// token calibration. wireShape optionally maps stored messages to their wire shape before
// estimation; nil keeps the stored shape.
func NewHistoryForModel(maxContext int, model string, wireShape func([]Message) []Message) *History {
	if maxContext <= 0 {
		maxContext = 32768
	}
	return &History{maxContext: maxContext, model: model, wireShape: wireShape}
}

// Append adds m to history. Callers should pre-populate ToolName and Summary120 on tool messages.
func (h *History) Append(m Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.version++
	if m.HistoryID == 0 {
		h.nextID++
		m.HistoryID = h.nextID
	} else if m.HistoryID > h.nextID {
		h.nextID = m.HistoryID
	}
	h.messages = append(h.messages, m)
}

// SetPromptTokens records the server-reported prompt token count and feeds the model-scoped
// calibration EMA, comparing against the recorded wire estimate when available.
func (h *History) SetPromptTokens(n int) {
	h.mu.Lock()
	raw := h.wireRaw
	if raw <= 0 {
		raw = h.rawEstimateRangeLocked(0, len(h.messages))
	}
	h.lastPromptTokens = n
	h.baselineMsgCount = len(h.messages)
	h.mu.Unlock()
	ObservePromptTokens(h.model, n, raw)
}

// RecordWireEstimate stores the uncalibrated token estimate of the message shape actually sent on
// the wire, keeping calibration and growth estimates like-for-like. Cleared on history replacement.
func (h *History) RecordWireEstimate(raw int) {
	h.mu.Lock()
	h.wireRaw = raw
	h.mu.Unlock()
}

// MaxContext returns the configured ceiling.
func (h *History) MaxContext() int {
	return h.maxContext
}

// EffectiveMaxContext returns the smaller of the configured ceiling and
// any shrinkage learned from context-rejected errors.
func (h *History) EffectiveMaxContext() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.effectiveMax > 0 && h.effectiveMax < h.maxContext {
		return h.effectiveMax
	}
	return h.maxContext
}

// ShrinkEffectiveMaxOnRejection lowers the effective context ceiling using
// estimateAtRejection; only shrinks, never grows.
func (h *History) ShrinkEffectiveMaxOnRejection(estimateAtRejection int) {
	if estimateAtRejection <= 0 {
		return
	}
	candidate := int(float64(estimateAtRejection) * rejectionShrinkRatio)
	if candidate < effectiveMaxFloor {
		candidate = effectiveMaxFloor
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if candidate >= h.maxContext {
		return
	}
	if h.effectiveMax == 0 || candidate < h.effectiveMax {
		h.effectiveMax = candidate
	}
}

// Calibration returns the learned multiplier for the history's model.
func (h *History) Calibration() float64 {
	return Calibration(h.model)
}

// EstimateTokens returns the estimated total prompt token count for the current history.
// Anchored on the last server-reported count when available, with growth estimated over the
// wire shape so stripped content does not skew the result.
func (h *History) EstimateTokens() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.lastPromptTokens <= 0 {
		return h.estimateRangeLocked(0, len(h.messages))
	}
	var growth int
	if h.baselineMsgCount < len(h.messages) {
		growth = h.estimateRangeLocked(h.baselineMsgCount, len(h.messages))
	}
	return h.lastPromptTokens + growth
}

// estimateRangeLocked returns the calibrated token estimate for messages in [start, end).
func (h *History) estimateRangeLocked(start, end int) int {
	return int(float64(h.rawEstimateRangeLocked(start, end)) * Calibration(h.model))
}

// rawEstimateRangeLocked returns the uncalibrated token estimate for messages in [start, end).
// Messages are mapped to their wire shape first so estimates match what the server priced.
func (h *History) rawEstimateRangeLocked(start, end int) int {
	if start < 0 {
		start = 0
	}
	if end > len(h.messages) {
		end = len(h.messages)
	}
	msgs := h.messages[start:end]
	if h.wireShape != nil {
		msgs = h.wireShape(msgs)
	}
	var total int
	for i := range msgs {
		total += rawMessageTokens(msgs[i])
	}
	return total
}

// Snapshot returns a copy of the message list.
func (h *History) Snapshot() []Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.messages)
}

// WireView maps msgs to the shape sent on the wire. Returns msgs unchanged when
// no wire shape is configured.
func (h *History) WireView(msgs []Message) []Message {
	if h.wireShape == nil {
		return msgs
	}
	return h.wireShape(msgs)
}

// ReplaceAll replaces the message slice with msgs and re-bases the token anchor onto the
// replacement, so estimates stay on one accounting basis across the swap. Preserves the
// iteration watermark; use ResetIterationBoundary when the swap should also end the current
// iteration.
func (h *History) ReplaceAll(msgs []Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.replaceAllLocked(msgs)
}

// Generation returns a counter bumped on every Append and ReplaceAll. Pair
// with ReplaceAllIfUnchanged to detect writers between snapshot and apply.
func (h *History) Generation() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.version
}

// ReplaceAllIfUnchanged behaves like ReplaceAll but applies only when the
// message log is unchanged since generation was taken via Generation.
// Returns false without mutating when a writer landed in between.
func (h *History) ReplaceAllIfUnchanged(generation uint64, msgs []Message) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.version != generation {
		return false
	}
	h.replaceAllLocked(msgs)
	return true
}

func (h *History) replaceAllLocked(msgs []Message) {
	h.version++
	h.nextID = 0
	for i := range msgs {
		if msgs[i].HistoryID == 0 {
			h.nextID++
			msgs[i].HistoryID = h.nextID
			continue
		}
		if msgs[i].HistoryID > h.nextID {
			h.nextID = msgs[i].HistoryID
		}
	}
	// keep estimates comparable across the swap: carry the prompt-side overhead
	// recorded with the last server count onto the replacement messages
	var prevBase int
	if h.lastPromptTokens > 0 {
		prevBase = h.estimateRangeLocked(0, h.baselineMsgCount)
	}
	h.messages = msgs
	if h.lastPromptTokens > 0 {
		h.lastPromptTokens += h.estimateRangeLocked(0, len(msgs)) - prevBase
		h.baselineMsgCount = len(msgs)
	}
	h.wireRaw = 0
}

// IterationBoundaryID returns the HistoryID watermark for the current iter.
// Iter content = messages with HistoryID > this value.
func (h *History) IterationBoundaryID() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.iterStartID
}

// MarkIterationBoundary records the current position as the iter-start watermark.
func (h *History) MarkIterationBoundary() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.iterStartID = h.nextID
}

// ResetIterationBoundary clears the iter watermark. Intended for callers
// that swap the working memory wholesale (e.g. ReplaceHistory).
func (h *History) ResetIterationBoundary() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.iterStartID = 0
}

// Len returns the current message count.
func (h *History) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.messages)
}

// Summarize120 returns the first 120 runes of s, with an ellipsis on overflow.
func Summarize120(s string) string {
	return util.Truncate(s, 120)
}
