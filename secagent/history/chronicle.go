package history

import (
	"slices"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/sectool-agents/secagent/agent"
)

// ChronicleKeepRecentIters is the trailing iter window kept raw.
const ChronicleKeepRecentIters = 2

// Chronicle holds a worker's chat history with per-message iteration indices.
type Chronicle struct {
	messages []agent.Message
	iters    []int
}

// NewChronicle returns a Chronicle seeded with messages and iteration indices.
func NewChronicle(messages []agent.Message, iters []int) Chronicle {
	return Chronicle{messages: messages, iters: iters}
}

// Messages returns the internal message slice; callers must not mutate it.
func (c *Chronicle) Messages() []agent.Message {
	if c == nil {
		return nil
	}
	return c.messages
}

// Len returns the number of chronicle messages.
func (c *Chronicle) Len() int {
	if c == nil {
		return 0
	}
	return len(c.messages)
}

// Install replaces a's history with the chronicle and queues directive.
func (c *Chronicle) Install(a agent.Agent, directive string) {
	a.ReplaceHistory(c.messages)
	a.MarkIterationBoundary()
	a.Query(directive)
}

// SnapshotSinceBoundary returns a clone of a's history above the iter watermark, or nil.
func SnapshotSinceBoundary(a agent.Agent) []agent.Message {
	tail := snapshotSinceBoundary(a)
	if tail == nil {
		return nil
	}
	return slices.Clone(tail)
}

// snapshotSinceBoundary returns a's history above the iter watermark
// (uncloned), excluding system messages.
func snapshotSinceBoundary(a agent.Agent) []agent.Message {
	full := a.Snapshot()
	watermark := a.IterationBoundaryID()
	idx := slices.IndexFunc(full, func(m agent.Message) bool { return m.HistoryID > watermark })
	if idx < 0 {
		return nil
	}
	return bulk.SliceFilter(func(m agent.Message) bool { return m.Role != agent.RoleSystem }, full[idx:])
}

// ExtractAndAppend appends a's iter messages onto the chronicle, tagged with iter.
func (c *Chronicle) ExtractAndAppend(a agent.Agent, iter int) {
	newMsgs := snapshotSinceBoundary(a)
	if len(newMsgs) == 0 {
		return
	}
	c.messages = append(c.messages, newMsgs...)
	c.iters = append(c.iters, slices.Repeat([]int{iter}, len(newMsgs))...)
}

// Compact repairs any iters/messages desync, then strips and stubs messages
// older than keepRecentIters; returns stripped, stubbed, and repaired counts.
func (c *Chronicle) Compact(currentIter, keepRecentIters int) (stripped, stubbed, repaired int) {
	if c == nil || len(c.messages) == 0 || keepRecentIters < 1 {
		return 0, 0, 0
	}
	repaired = c.syncIters()
	cutoff := currentIter - keepRecentIters + 1
	for i := range c.messages {
		if c.iters[i] >= cutoff {
			continue
		}
		if agent.StripAssistantThink(&c.messages[i]) {
			stripped++
		}
		if agent.StubToolResult(&c.messages[i], "") {
			stubbed++
		}
	}
	return stripped, stubbed, repaired
}

// syncIters repairs iters/messages desync in place: missing entries are
// padded with 0 so the tail lands in the compacted bucket, extras are
// truncated. Returns the number of entries added or removed.
func (c *Chronicle) syncIters() int {
	delta := len(c.messages) - len(c.iters)
	if delta == 0 {
		return 0
	}
	if delta < 0 {
		c.iters = c.iters[:len(c.messages)]
		return -delta
	}
	c.iters = append(c.iters, slices.Repeat([]int{0}, delta)...)
	return delta
}

// ApplySelfPrune repairs any iters/messages desync, then drops tool-call IDs
// from the chronicle; returns dropped count.
func (c *Chronicle) ApplySelfPrune(dropIDs []string) int {
	if c == nil || len(dropIDs) == 0 || len(c.messages) == 0 {
		return 0
	}
	dropSet := buildDropSet(dropIDs)
	if len(dropSet) == 0 {
		return 0
	}
	c.syncIters()
	keptMsgs, keptIndices, dropped := PruneToolResults(c.messages, dropSet, nil)
	keptIters := make([]int, 0, len(keptIndices))
	for _, i := range keptIndices {
		keptIters = append(keptIters, c.iters[i])
	}
	c.messages = keptMsgs
	c.iters = keptIters
	return dropped
}

// buildDropSet returns a set of non-empty ids.
func buildDropSet(ids []string) map[string]struct{} {
	return bulk.SliceToSet(bulk.SliceFilter(func(s string) bool { return s != "" }, ids))
}

func (c *Chronicle) Reset() {
	if c == nil {
		return
	}
	c.messages = nil
	c.iters = nil
}

// CloneWithDirective returns a Chronicle clone with directive prepended at iter.
func (c *Chronicle) CloneWithDirective(directive string, iter int) Chronicle {
	var srcMsgs []agent.Message
	var srcIters []int
	if c != nil {
		srcMsgs = c.messages
		srcIters = c.iters
	}
	msgs := make([]agent.Message, 0, 1+len(srcMsgs))
	msgs = append(msgs, agent.Message{Role: "user", Content: directive})
	msgs = append(msgs, srcMsgs...)
	iters := make([]int, 0, 1+len(srcIters))
	iters = append(iters, iter)
	iters = append(iters, srcIters...)
	return Chronicle{messages: msgs, iters: iters}
}
