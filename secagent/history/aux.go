package history

import (
	"context"
	"time"
)

const (
	// defaultAuxTimeout bounds each aux compaction callback (self-prune, distill).
	defaultAuxTimeout = 5 * time.Minute
	// defaultAuxCallBudget caps aux LLM calls per compaction pass.
	defaultAuxCallBudget = 8
)

// AuxBudget bounds the LLM calls aux compaction callbacks may issue during one
// pass. The nil budget is unlimited.
type AuxBudget struct {
	remaining int
	skipped   int
}

// newAuxBudget returns a budget of n calls; n <= 0 falls back to defaultAuxCallBudget.
func newAuxBudget(n int) *AuxBudget {
	if n <= 0 {
		n = defaultAuxCallBudget
	}
	return &AuxBudget{remaining: n}
}

// Allow reports whether another aux call is budgeted; otherwise it records a skip.
func (b *AuxBudget) Allow() bool {
	if b == nil {
		return true
	}
	if b.remaining <= 0 {
		b.skipped++
		return false
	}
	b.remaining--
	return true
}

// Skipped returns the number of aux calls denied so far.
func (b *AuxBudget) Skipped() int {
	if b == nil {
		return 0
	}
	return b.skipped
}

// auxContext returns ctx with the per-callback aux deadline applied.
func auxContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = defaultAuxTimeout
	}
	return context.WithTimeout(ctx, timeout)
}
