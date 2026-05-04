package orchestrator

import (
	"strings"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/secagent/agent"
)

// appendIterationHistory appends one IterationEntry per worker alive at iter start.
func appendIterationHistory(workers []*WorkerState,
	aliveAtStart map[int]bool, angleAt map[int]string, workerRuns map[int][]agent.TurnSummary,
	decisions *DecisionQueue, candidates *CandidatePool, candidatesBefore, iteration int) {
	for _, w := range workers {
		if !aliveAtStart[w.ID] {
			continue
		}

		runs := workerRuns[w.ID]
		mine := candidates.IDsSinceForWorker(candidatesBefore, w.ID)
		angle := strings.Join(strings.Fields(angleAt[w.ID]), " ")
		if len(angle) > angleMaxLen {
			const ellipsis = "…"
			angle = angle[:angleMaxLen-len(ellipsis)] + ellipsis
		}
		var toolCalls, flows int
		for _, t := range runs {
			toolCalls += len(t.ToolCalls)
			flows += len(t.FlowIDs)
		}
		w.AppendHistory(IterationEntry{
			Iteration:    iteration,
			Angle:        angle,
			Outcome:      DeriveIterationOutcome(w, decisions, candidates, mine),
			ToolCalls:    toolCalls,
			FlowsTouched: flows,
		})
	}
}

// angleMaxLen caps the Angle field so the rendered history stays compact.
const angleMaxLen = 100

// DeriveIterationOutcome returns the outcome classifying w's iteration result.
// workerCandidates are the candidate IDs reported by w this iteration.
func DeriveIterationOutcome(w *WorkerState, decisions *DecisionQueue,
	candidates *CandidatePool, workerCandidates []string) IterationOutcome {
	if !w.Alive {
		return OutcomeStopped
	}

	mine := bulk.SliceToSet(workerCandidates)

	var mineSnapshots []FindingCandidate
	for id := range mine {
		if c := candidates.ByID(id); c != nil {
			mineSnapshots = append(mineSnapshots, *c)
		}
	}

	var tierMatched bool
	for _, f := range decisions.Findings {
		for _, cid := range f.SupersedesCandidateIDs {
			if _, ok := mine[cid]; ok {
				return OutcomeFinding
			}
		}
		if !tierMatched && len(mineSnapshots) > 0 {
			ids, _ := MatchPendingCandidatesTiered(f, mineSnapshots)
			if len(ids) > 0 {
				tierMatched = true
			}
		}
	}
	if tierMatched {
		return OutcomePossibleFinding
	}

	for _, d := range decisions.Dismissals {
		if _, ok := mine[d.CandidateID]; ok {
			return OutcomeDismissed
		}
	}

	for id := range mine {
		if c := candidates.ByID(id); c != nil && c.Status == CandidateStatusPending {
			return OutcomeCandidate
		}
	}

	switch w.EscalationReason {
	case EscalationError:
		return OutcomeError
	case EscalationBudget:
		return OutcomeBudget
	}
	return OutcomeSilent
}
