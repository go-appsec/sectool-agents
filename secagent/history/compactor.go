package history

import (
	"context"
	"sync"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/secagent/agent"
)

// CompactorOptions configures a LayeredCompactor.
type CompactorOptions struct {
	Compaction            agent.CompactionOptions
	RetireOnPressure      bool
	OnSelfPruneCandidates func(context.Context, []agent.Message) ([]string, error)
	OnDistillResults      func(context.Context, []agent.Message) ([]agent.Message, error)
	OnSelfPruneApplied    func([]string)
	// OnCallbackError logs failures from aux passes.
	OnCallbackError func(error)
	OnCompact       func(agent.CompactionReport)
}

// NewLayeredCompactor returns a LayeredCompactor with the given options.
func NewLayeredCompactor(opts CompactorOptions) *LayeredCompactor {
	return &LayeredCompactor{opts: opts}
}

// LayeredCompactor implements agent.Compactor with layered compaction passes.
type LayeredCompactor struct {
	mu   sync.Mutex
	opts CompactorOptions
}

// SetOnSelfPruneApplied swaps in a new post-apply hook; safe under concurrent use.
func (c *LayeredCompactor) SetOnSelfPruneApplied(f func([]string)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.opts.OnSelfPruneApplied = f
}

func (c *LayeredCompactor) currentOpts() CompactorOptions {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.opts
}

// MaybeCompact runs layered compaction when h crosses the high watermark.
// Returns agent.ErrRetireOnPressure when RetireOnPressure is set.
func (c *LayeredCompactor) MaybeCompact(ctx context.Context, h *agent.History) error {
	opts := c.currentOpts()
	agent.ApplyCompactionDefaults(&opts.Compaction)
	maxCtx := h.EffectiveMaxContext()
	high := int(float64(maxCtx) * opts.Compaction.HighWatermark)
	if h.EstimateTokens() < high {
		return nil
	}
	if opts.RetireOnPressure {
		return agent.ErrRetireOnPressure
	}

	recoveryGoal := int(float64(maxCtx) * opts.Compaction.RecoveryThreshold)
	startTokens := h.EstimateTokens()

	aggregate := agent.CompactionReport{Before: startTokens}
	defer func() {
		aggregate.After = h.EstimateTokens()
		if opts.OnCompact != nil && len(aggregate.PassesApplied) > 0 {
			opts.OnCompact(aggregate)
		}
	}()

	r0 := agent.CompactErrorsOnly(h, opts.Compaction)
	aggregate = agent.MergeReports(aggregate, r0)
	if h.EstimateTokens() < high {
		return nil
	}

	if startTokens-h.EstimateTokens() < recoveryGoal && opts.OnSelfPruneCandidates != nil {
		rB := c.runSelfPrune(ctx, h, opts)
		aggregate = agent.MergeReports(aggregate, rB)
		if h.EstimateTokens() < high {
			return nil
		}
	}

	if startTokens-h.EstimateTokens() < recoveryGoal && opts.OnDistillResults != nil {
		rC := runDistill(ctx, h, opts)
		aggregate = agent.MergeReports(aggregate, rC)
		if h.EstimateTokens() < high {
			return nil
		}
	}

	r1, err := agent.CompactRemainder(h, opts.Compaction)
	aggregate = agent.MergeReports(aggregate, r1)
	return err
}

// runSelfPrune applies self-prune drops; fails open on callback errors.
func (c *LayeredCompactor) runSelfPrune(ctx context.Context, h *agent.History, opts CompactorOptions) agent.CompactionReport {
	before := h.EstimateTokens()
	report := agent.CompactionReport{Before: before, After: before}
	snap := h.Snapshot()
	dropIDs, err := opts.OnSelfPruneCandidates(ctx, snap)
	if err != nil {
		if opts.OnCallbackError != nil {
			opts.OnCallbackError(err)
		}
		return report
	}
	if len(dropIDs) == 0 {
		return report
	}
	dropSet := buildDropSet(dropIDs)
	if len(dropSet) == 0 {
		return report
	}
	pruned, _, dropped := PruneToolResults(snap, dropSet, nil)
	if dropped == 0 {
		return report
	}
	h.ReplaceAll(pruned)
	report.SelfPrunedCalls = dropped
	report.PassesApplied = append(report.PassesApplied, "self-prune")
	report.After = h.EstimateTokens()
	// re-read under lock to capture dynamic SetOnSelfPruneApplied updates
	if hook := c.currentOpts().OnSelfPruneApplied; hook != nil {
		hook(bulk.MapKeysSlice(dropSet))
	}
	return report
}

// runDistill applies distill replacement; fails open on callback errors.
func runDistill(ctx context.Context, h *agent.History, opts CompactorOptions) agent.CompactionReport {
	before := h.EstimateTokens()
	report := agent.CompactionReport{Before: before, After: before}
	snap := h.Snapshot()
	replacement, err := opts.OnDistillResults(ctx, snap)
	if err != nil {
		if opts.OnCallbackError != nil {
			opts.OnCallbackError(err)
		}
		return report
	}
	if len(replacement) == 0 {
		return report
	}
	distilled := countDistilledChanges(snap, replacement)
	if distilled == 0 {
		return report
	}
	h.ReplaceAll(replacement)
	report.DistilledResults = distilled
	report.PassesApplied = append(report.PassesApplied, "distill")
	report.After = h.EstimateTokens()
	return report
}

// countDistilledChanges counts tool-result messages whose Content changed.
func countDistilledChanges(before, after []agent.Message) int {
	n := len(before)
	if len(after) < n {
		n = len(after)
	}
	var changed int
	for i := 0; i < n; i++ {
		if before[i].Role != agent.RoleTool || after[i].Role != agent.RoleTool {
			continue
		}

		if before[i].Content != after[i].Content {
			changed++
		}
	}
	return changed
}
