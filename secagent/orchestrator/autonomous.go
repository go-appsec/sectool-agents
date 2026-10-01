package orchestrator

import (
	"context"
	"slices"

	"github.com/go-appsec/sectool-agents/secagent/agent"
	"github.com/go-appsec/sectool-agents/secagent/orchestrator/prompts"
)

// workerRunResult carries the WorkerState fields one autonomous run produces.
// Run goroutines build it privately instead of mutating the shared
// WorkerState; the controller applies it at join time via
// WorkerState.ApplyRunResult, making the join the sole synchronization
// point between the two goroutines.
type workerRunResult struct {
	EscalationReason string
	AutonomousTurns  []agent.TurnSummary
	RecentToolErrors []string
	CoachedErrorSig  string
}

// newWorkerRunResult seeds a result with w's cross-run error tracking.
// Called on the controller goroutine at fire time; the run goroutine owns
// the value from then on.
func newWorkerRunResult(w *WorkerState) workerRunResult {
	return workerRunResult{
		RecentToolErrors: slices.Clone(w.RecentToolErrors),
		CoachedErrorSig:  w.CoachedErrorSig,
	}
}

// drainOne drains one turn on w and records its summary in rs, classifying
// the turn's escalation reason.
func drainOne(ctx context.Context,
	w *WorkerState, rs *workerRunResult, candidates *CandidatePool, log *Logger) (agent.TurnSummary, error) {
	before := candidates.Counter()
	summary, err := w.Agent.Drain(ctx)
	if err != nil {
		log.Log("worker", "drain error", map[string]any{
			"worker_id": w.ID, "err": err.Error(),
		})
		return summary, err
	}
	if newIDs := candidates.IDsSinceForWorker(before, w.ID); len(newIDs) > 0 &&
		summary.EscalationReason != EscalationContextExhausted {
		summary.EscalationReason = EscalationCandidate
	} else {
		summary.EscalationReason = agent.ClassifyEscalation(summary, false)
	}
	rs.AutonomousTurns = append(rs.AutonomousTurns, summary)
	updateToolErrorSignatures(rs, summary)
	log.Log("worker", "turn", map[string]any{
		"worker_id":        w.ID,
		"turn":             len(rs.AutonomousTurns),
		"escalation":       summary.EscalationReason,
		"tokens_in":        summary.TokensIn,
		"tokens_out":       summary.TokensOut,
		"tool_calls":       len(summary.ToolCalls),
		"flow_ids_touched": len(summary.FlowIDs),
	})
	return summary, nil
}

// updateToolErrorSignatures records summary's error-tool signatures into
// rs.RecentToolErrors. Error-free turns decay the window by one entry;
// rs.CoachedErrorSig latches until its signature decays out.
func updateToolErrorSignatures(rs *workerRunResult, summary agent.TurnSummary) {
	var sawError bool
	for _, tc := range summary.ToolCalls {
		if !tc.IsError {
			continue
		}

		sig := tc.ResultSummary
		if len(sig) > ErrorSignatureMaxLen {
			sig = sig[:ErrorSignatureMaxLen]
		}
		if sig == "" {
			continue
		}
		sawError = true
		rs.RecentToolErrors = append(rs.RecentToolErrors, sig)
		if len(rs.RecentToolErrors) > MaxRecentToolErrors {
			rs.RecentToolErrors = rs.RecentToolErrors[len(rs.RecentToolErrors)-MaxRecentToolErrors:]
		}
	}
	if !sawError && len(rs.RecentToolErrors) > 0 {
		rs.RecentToolErrors = rs.RecentToolErrors[1:]
	}
	if rs.CoachedErrorSig != "" && !slices.Contains(rs.RecentToolErrors, rs.CoachedErrorSig) {
		rs.CoachedErrorSig = ""
	}
}

// RunWorkerUntilEscalation drains w up to its AutonomousBudget (capped at 20) or until
// escalation, accumulating turn summaries and the escalation reason in rs.
// Caller must install the per-iter chronicle first.
func RunWorkerUntilEscalation(ctx context.Context,
	w *WorkerState, rs *workerRunResult, candidates *CandidatePool, log *Logger) ([]agent.TurnSummary, error) {
	budget := min(max(w.AutonomousBudget, 1), 20)

	for attempt := 0; attempt < budget; attempt++ {
		if attempt > 0 {
			w.Agent.Query(prompts.IntraPhaseContinue)
		}
		summary, err := drainOne(ctx, w, rs, candidates, log)
		if err != nil {
			rs.EscalationReason = EscalationError
			return rs.AutonomousTurns, err
		}
		if summary.EscalationReason != "" {
			rs.EscalationReason = summary.EscalationReason
			return rs.AutonomousTurns, nil
		}
	}
	rs.EscalationReason = EscalationBudget
	return rs.AutonomousTurns, nil
}

// runOneWorker drains w for one iteration and returns the run's result.
// One recovery attempt is made on mid-iter error. rs carries the cross-run
// error tracking seeded at fire time; the controller applies the result to
// w at join time.
func runOneWorker(ctx context.Context,
	w *WorkerState, rs workerRunResult, candidates *CandidatePool, log *Logger) workerRunResult {
	_, err := RunWorkerUntilEscalation(ctx, w, &rs, candidates, log)
	if err != nil && w.LastInstruction != "" {
		log.Log("worker", "recover", map[string]any{
			"worker_id": w.ID, "attempt": 1, "err": err.Error(),
		})
		w.Agent.Interrupt()
		w.Agent.Query(w.LastInstruction)
		summary, err2 := drainOne(ctx, w, &rs, candidates, log)
		if err2 != nil {
			rs.EscalationReason = EscalationError
		} else {
			// Outcome of the final turn; a productive recovery is not an error.
			rs.EscalationReason = summary.EscalationReason
		}
	}
	return rs
}
