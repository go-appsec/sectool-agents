package orchestrator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-appsec/secagent/agent"
)

// Worker escalation reasons. A worker's autonomous run ends by setting EscalationReason to one of these values.
const (
	EscalationSilent    = "silent"
	EscalationError     = "error"
	EscalationBudget    = "budget"
	EscalationCandidate = "candidate"
)

// UpdateStallStreaks adjusts each alive worker's ProgressNoneStreak from
// its last run outcome. Silent/error/repeated-error increment; candidate
// or new flows reset. Repeated-error workers also get a coaching nudge.
func UpdateStallStreaks(workers []*WorkerState) {
	for _, w := range workers {
		if !w.Alive {
			continue
		}

		var producedFlows bool
		for _, t := range w.AutonomousTurns {
			if len(t.FlowIDs) > 0 {
				producedFlows = true
				break
			}
		}
		repeatedSig, repeated := repeatedErrorSignature(w.RecentToolErrors)
		switch {
		case w.EscalationReason == EscalationSilent || w.EscalationReason == EscalationError:
			// Silent/error wins over flows (preserved precedence: a worker
			// that touched a flow but escalated silent is still stalling).
			w.ProgressNoneStreak++
		case w.EscalationReason == EscalationCandidate || producedFlows:
			w.ProgressNoneStreak = 0
			w.StallWarned = false
		case repeated:
			w.ProgressNoneStreak++
		}
		if repeated && w.CoachedErrorSig != repeatedSig && w.Agent != nil {
			w.Agent.Query(fmt.Sprintf(
				"Your last several tool calls returned the same error: %q. Try a different tool or approach. If you're stuck, report what you've learned via report_finding_candidate and describe the blocker.",
				repeatedSig,
			))
			w.CoachedErrorSig = repeatedSig
		}
	}
}

// repeatedErrorSignature returns (signature, true) when sigs contains at
// least RepeatedErrorThreshold identical entries.
func repeatedErrorSignature(sigs []string) (string, bool) {
	if len(sigs) < RepeatedErrorThreshold {
		return "", false
	}
	counts := map[string]int{}
	for _, s := range sigs {
		counts[s]++
		if counts[s] >= RepeatedErrorThreshold {
			return s, true
		}
	}
	return "", false
}

// hasProductiveTurn reports whether any turn issued a tool call or touched a flow ID.
func hasProductiveTurn(turns []agent.TurnSummary) bool {
	for _, t := range turns {
		if len(t.ToolCalls) > 0 || len(t.FlowIDs) > 0 {
			return true
		}
	}
	return false
}

// FormatStallWarnings returns the stall-warnings block for the director
// prompt, or "" when no worker has an un-latched warning at/above warnAfter.
func FormatStallWarnings(workers []*WorkerState, warnAfter int) string {
	ids := make([]int, 0, len(workers))
	for _, w := range workers {
		if !w.Alive {
			continue
		}

		if w.ProgressNoneStreak >= warnAfter && !w.StallWarned {
			ids = append(ids, w.ID)
		}
	}
	sort.Ints(ids)
	byID := map[int]*WorkerState{}
	for _, w := range workers {
		byID[w.ID] = w
	}
	warnings := make([]string, 0, len(ids))
	for _, id := range ids {
		w := byID[id]
		warnings = append(warnings, fmt.Sprintf(
			"- Worker %d has had %d consecutive silent autonomous runs. Expand its plan with concrete next steps or stop it.",
			w.ID, w.ProgressNoneStreak,
		))
	}
	if len(warnings) == 0 {
		return ""
	}
	return "**Stall warnings:**\n" + strings.Join(warnings, "\n")
}

// LatchStallWarnings sets StallWarned on any alive worker whose ProgressNoneStreak is at/above warnAfter.
func LatchStallWarnings(workers []*WorkerState, warnAfter int) {
	for _, w := range workers {
		if w.Alive && w.ProgressNoneStreak >= warnAfter {
			w.StallWarned = true
		}
	}
}
