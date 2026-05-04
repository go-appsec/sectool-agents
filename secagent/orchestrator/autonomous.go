package orchestrator

import (
	"context"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/orchestrator/prompts"
)

// drainOne drains one turn on w and returns its summary, also appending
// it to w.AutonomousTurns and updating the worker's escalation reason.
func drainOne(ctx context.Context,
	w *WorkerState, candidates *CandidatePool, log *Logger) (agent.TurnSummary, error) {
	before := candidates.Counter()
	summary, err := w.Agent.Drain(ctx)
	if err != nil {
		log.Log("worker", "drain error", map[string]any{
			"worker_id": w.ID, "err": err.Error(),
		})
		return summary, err
	}
	if newIDs := candidates.IDsSinceForWorker(before, w.ID); len(newIDs) > 0 {
		summary.EscalationReason = "candidate"
	} else {
		summary.EscalationReason = agent.ClassifyEscalation(summary, false)
	}
	w.AutonomousTurns = append(w.AutonomousTurns, summary)
	updateToolErrorSignatures(w, summary)
	log.Log("worker", "turn", map[string]any{
		"worker_id":        w.ID,
		"turn":             len(w.AutonomousTurns),
		"escalation":       summary.EscalationReason,
		"tokens_in":        summary.TokensIn,
		"tokens_out":       summary.TokensOut,
		"tool_calls":       len(summary.ToolCalls),
		"flow_ids_touched": len(summary.FlowIDs),
	})
	return summary, nil
}

// updateToolErrorSignatures records summary's error-tool signatures into
// w.RecentToolErrors. Any successful call clears w.CoachedErrorSig.
func updateToolErrorSignatures(w *WorkerState, summary agent.TurnSummary) {
	var sawSuccess bool
	for _, tc := range summary.ToolCalls {
		if !tc.IsError {
			sawSuccess = true
			continue
		}

		sig := tc.ResultSummary
		if len(sig) > ErrorSignatureMaxLen {
			sig = sig[:ErrorSignatureMaxLen]
		}
		if sig == "" {
			continue
		}
		w.RecentToolErrors = append(w.RecentToolErrors, sig)
		if len(w.RecentToolErrors) > MaxRecentToolErrors {
			w.RecentToolErrors = w.RecentToolErrors[len(w.RecentToolErrors)-MaxRecentToolErrors:]
		}
	}
	if sawSuccess {
		w.CoachedErrorSig = ""
	}
}

// RunWorkerUntilEscalation drains w up to its AutonomousBudget (capped at 20) or until escalation.
// Returns each turn's summary and sets w.EscalationReason. Caller must install the per-iter chronicle first.
func RunWorkerUntilEscalation(ctx context.Context,
	w *WorkerState, candidates *CandidatePool, log *Logger) ([]agent.TurnSummary, error) {
	budget := min(max(w.AutonomousBudget, 1), 20)

	var runs []agent.TurnSummary
	for attempt := 0; attempt < budget; attempt++ {
		if attempt > 0 {
			w.Agent.Query(prompts.IntraPhaseContinue)
		}
		summary, err := drainOne(ctx, w, candidates, log)
		if err != nil {
			w.EscalationReason = EscalationError
			return runs, err
		}
		runs = append(runs, summary)
		if summary.EscalationReason != "" {
			w.EscalationReason = summary.EscalationReason
			return runs, nil
		}
	}
	w.EscalationReason = EscalationBudget
	return runs, nil
}

// runOneWorker drains w for one iteration and returns the turn summaries.
// One recovery attempt is made on mid-iter error.
func runOneWorker(ctx context.Context,
	w *WorkerState, candidates *CandidatePool, log *Logger) []agent.TurnSummary {
	w.EscalationReason = ""
	w.AutonomousTurns = nil
	runs, err := RunWorkerUntilEscalation(ctx, w, candidates, log)
	if err != nil && w.LastInstruction != "" {
		log.Log("worker", "recover", map[string]any{
			"worker_id": w.ID, "attempt": 1, "err": err.Error(),
		})
		w.Agent.Interrupt()
		w.Agent.Query(w.LastInstruction)
		summary, err2 := drainOne(ctx, w, candidates, log)
		if err2 != nil {
			w.EscalationReason = EscalationError
		} else {
			runs = append(runs, summary)
			if summary.EscalationReason != "" {
				w.EscalationReason = summary.EscalationReason
			}
		}
	}
	return runs
}
