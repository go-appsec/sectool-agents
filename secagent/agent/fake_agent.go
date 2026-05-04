package agent

import (
	"context"
	"errors"
	"slices"
	"sync"
)

// FakeAgent is a scripted Agent for tests. Each Drain pops the next
// configured TurnSummary in order; Query appends the content to QueriedInputs.
type FakeAgent struct {
	mu            sync.Mutex
	Turns         []TurnSummary // scripted sequence consumed in order
	Errors        []error       // per-turn errors; len may be < len(Turns)
	QueriedInputs []string
	Tools         []ToolDef
	ContextTokens int
	ContextMax    int
	Closed        bool
	MaxRoundsSeen []int // records bounds passed to DrainBounded for assertions
	// OnDrain, when non-nil, fires just before a scripted turn is returned.
	// Tests use it to simulate side effects that a real agent would produce through its tool handlers.
	OnDrain func(turnIndex int)
	// LastReplacedHistory is the most recent slice passed to ReplaceHistory.
	// Tests assert on shape (length, roles, content) of installed history.
	LastReplacedHistory []Message
	// ReplacedHistories records every ReplaceHistory call in order so tests
	// can assert "exactly one ReplaceHistory per phase entry" semantics.
	ReplacedHistories [][]Message
	// OverflowOnDrain, when true, invokes OnContextOverflow (if non-nil) before returning the scripted turn.
	// Lets tests exercise the verifier's context-budget auto-dismiss path without a real OpenAIAgent.
	OverflowOnDrain   bool
	OnContextOverflow func()
	// BoundaryCalls counts MarkIterationBoundary invocations so tests can
	// assert "exactly one boundary mark per iter per agent" semantics.
	BoundaryCalls int
	// LastBoundaryID is the HistoryID watermark IterationBoundaryID() returns. Tests may set it directly;
	// values map 1:1 to legacy index semantics because Snapshot() assigns HistoryID = i+1 per message.
	LastBoundaryID uint64
	// SnapshotMessages, when non-nil, is what Snapshot() returns. Lets tests script a synthetic
	// chat history for chronicle-extraction assertions without driving a full Drain sequence.
	SnapshotMessages []Message
}

// Query records the content.
func (f *FakeAgent) Query(content string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.QueriedInputs = append(f.QueriedInputs, content)
}

// Drain pops the next scripted turn.
func (f *FakeAgent) Drain(ctx context.Context) (TurnSummary, error) {
	return f.DrainBounded(ctx, 0)
}

// DrainBounded records maxRounds into MaxRoundsSeen and pops the next scripted turn.
func (f *FakeAgent) DrainBounded(ctx context.Context, maxRounds int) (TurnSummary, error) {
	f.mu.Lock()
	cb := f.OnDrain
	overflow := f.OverflowOnDrain
	overflowCb := f.OnContextOverflow
	turnIdx := len(f.QueriedInputs) - 1
	if maxRounds > 0 {
		f.MaxRoundsSeen = append(f.MaxRoundsSeen, maxRounds)
	}
	if ctx.Err() != nil {
		f.mu.Unlock()
		return TurnSummary{}, ctx.Err()
	}
	if len(f.Turns) == 0 {
		f.mu.Unlock()
		return TurnSummary{}, errors.New("FakeAgent: no scripted turns")
	}
	t := f.Turns[0]
	f.Turns = f.Turns[1:]
	var err error
	if len(f.Errors) > 0 {
		err = f.Errors[0]
		f.Errors = f.Errors[1:]
	}
	f.mu.Unlock()
	if overflow && overflowCb != nil {
		overflowCb()
	}
	if cb != nil {
		cb(turnIdx)
	}
	return t, err
}

// MarkIterationBoundary records a watermark derived from LastReplacedHistory + QueriedInputs and increments BoundaryCalls.
func (f *FakeAgent) MarkIterationBoundary() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.BoundaryCalls++
	f.LastBoundaryID = uint64(len(f.LastReplacedHistory) + len(f.QueriedInputs))
}

// IterationBoundaryID returns the recorded watermark.
func (f *FakeAgent) IterationBoundaryID() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.LastBoundaryID
}

// Snapshot returns SnapshotMessages when set, otherwise a slice synthesized from
// LastReplacedHistory and QueriedInputs. Messages without HistoryID are stamped with
// positional IDs (msg[i].HistoryID = i+1) so chronicle boundary filters see watermark-comparable values.
func (f *FakeAgent) Snapshot() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []Message
	if f.SnapshotMessages != nil {
		out = slices.Clone(f.SnapshotMessages)
	} else {
		out = make([]Message, 0, len(f.LastReplacedHistory)+len(f.QueriedInputs))
		out = append(out, f.LastReplacedHistory...)
		for _, q := range f.QueriedInputs {
			out = append(out, Message{Role: "user", Content: q})
		}
	}
	for i := range out {
		if out[i].HistoryID == 0 {
			out[i].HistoryID = uint64(i + 1)
		}
	}
	return out
}

// ReplaceHistory records msgs into LastReplacedHistory and ReplacedHistories.
// Does not preserve a system prompt.
func (f *FakeAgent) ReplaceHistory(msgs []Message) {
	f.mu.Lock()
	defer f.mu.Unlock()

	cp := slices.Clone(msgs)
	f.LastReplacedHistory = cp
	f.ReplacedHistories = append(f.ReplacedHistories, cp)
}

// Interrupt is a no-op in fake.
func (f *FakeAgent) Interrupt() {}

// SetTools records tools.
func (f *FakeAgent) SetTools(defs []ToolDef) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Tools = append(f.Tools[:0], defs...)
}

// ContextUsage returns configured fake values.
func (f *FakeAgent) ContextUsage() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.ContextTokens, f.ContextMax
}

// EffectiveContextUsage returns the same values as ContextUsage; FakeAgent has no separate effective ceiling.
func (f *FakeAgent) EffectiveContextUsage() (int, int) {
	return f.ContextUsage()
}

// SnapshotSinceID returns the suffix of Snapshot() whose HistoryID > id, skipping a leading system message.
// Returns all post-system messages when id is 0 or absent.
func (f *FakeAgent) SnapshotSinceID(id uint64) []Message {
	snap := f.Snapshot()
	if len(snap) == 0 {
		return nil
	}
	var start int
	if snap[0].Role == RoleSystem {
		start = 1
	}
	if id != 0 {
		for i := start; i < len(snap); i++ {
			if snap[i].HistoryID == id {
				start = i + 1
				break
			}
		}
	}
	if start >= len(snap) {
		return nil
	}
	return snap[start:]
}

// SetOnSelfPruneApplied is a no-op; FakeAgent has no compactor.
func (f *FakeAgent) SetOnSelfPruneApplied(func(droppedIDs []string)) {}

// SummarizeStatus returns an empty line; FakeAgent has no LLM backend.
func (f *FakeAgent) SummarizeStatus(context.Context, int) (string, error) {
	return "", nil
}

// Close marks the fake closed.
func (f *FakeAgent) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Closed = true
	return nil
}
