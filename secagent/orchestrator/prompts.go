package orchestrator

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/util"
)

func formatToolCalls(calls []agent.ToolCallRecord, limit int) string {
	if len(calls) == 0 {
		return "  (no tool calls)"
	}
	if limit <= 0 {
		limit = 20
	}
	var lines []string
	shown := calls
	if len(shown) > limit {
		shown = shown[:limit]
	}
	for i, c := range shown {
		var status string
		if c.IsError {
			status = " [ERROR]"
		}
		line := fmt.Sprintf("  %d. %s(%s)%s", i+1, c.Name, c.InputSummary, status)
		if c.ResultSummary != "" {
			line += "\n     → " + c.ResultSummary
		}
		lines = append(lines, line)
	}
	if len(calls) > limit {
		lines = append(lines, fmt.Sprintf("  … and %d more tool call(s) omitted.", len(calls)-limit))
	}
	return strings.Join(lines, "\n")
}

func formatAutonomousRun(workerID int, turns []agent.TurnSummary, escalationReason string) string {
	if len(turns) == 0 {
		return fmt.Sprintf(
			"### Worker %d\n(No autonomous turns this iteration. escalation_reason=%s)",
			workerID, orDefault(escalationReason, "unknown"),
		)
	}
	var parts []string
	parts = append(parts, fmt.Sprintf(
		"### Worker %d — %d autonomous turn(s), escalated: %s",
		workerID, len(turns), orDefault(escalationReason, "unknown"),
	))
	for i, s := range turns {
		var names []string
		for _, c := range s.ToolCalls {
			names = append(names, c.Name)
		}
		calls := "(no tool calls)"
		if len(names) > 0 {
			calls = strings.Join(names, ", ")
		}
		flows := "(no flows)"
		if len(s.FlowIDs) > 0 {
			flows = strings.Join(s.FlowIDs, ", ")
		}
		firstLine := strings.TrimSpace(s.AssistantText)
		if i := strings.IndexByte(firstLine, '\n'); i >= 0 {
			firstLine = strings.TrimSpace(firstLine[:i])
		}
		if firstLine == "" {
			firstLine = "(no text)"
		}
		parts = append(parts, fmt.Sprintf(
			"  Turn %d: tools=[%s] flows=[%s]\n    text: %s",
			i+1, util.Truncate(calls, 200), flows, util.Truncate(firstLine, 240),
		))
	}
	last := turns[len(turns)-1]
	parts = append(parts, "")
	parts = append(parts, fmt.Sprintf("Last turn tool calls (%d):", len(last.ToolCalls)))
	parts = append(parts, formatToolCalls(last.ToolCalls, 10))
	return strings.Join(parts, "\n")
}

func formatPendingCandidates(pending []FindingCandidate) string {
	if len(pending) == 0 {
		return "No pending finding candidates."
	}
	var lines []string
	lines = append(lines, "**Pending finding candidates (awaiting verification):**")
	for _, c := range pending {
		flows := strings.Join(c.FlowIDs, ", ")
		if flows == "" {
			flows = noneSentinel
		}
		lines = append(lines, fmt.Sprintf(
			"- `%s` [%s] %s — %s\n  worker: %d\n  flows: %s\n  summary: %s\n  reproduction hint: %s",
			c.CandidateID, c.Severity, c.Title, c.Endpoint, c.WorkerID, flows,
			util.Truncate(c.Summary, 200), util.Truncate(c.ReproductionHint, 200),
		))
	}
	return strings.Join(lines, "\n")
}

func statusLine(iteration, maxIter, findings int) string {
	return fmt.Sprintf("**Status:** iteration %d/%d, findings filed: %d", iteration, maxIter, findings)
}

// BuildVerifierPrompt returns the initial verifier substep prompt.reconSummary is included as a header when non-empty.
func BuildVerifierPrompt(workers []*WorkerState, workerRuns map[int][]agent.TurnSummary,
	pending []FindingCandidate, findingsSummary, reconSummary string, iteration, maxIter, findingsCount int) string {
	var parts []string
	parts = append(parts, statusLine(iteration, maxIter, findingsCount))
	if reconSummary != "" {
		parts = append(parts, "", "## Recon summary (initial scope mapping by retired worker 1)", "", reconSummary)
	}
	parts = append(parts, "", findingsSummary, "", formatPendingCandidates(pending), "", "## Worker autonomous runs this iteration", "")
	for _, w := range workers {
		runs, ok := workerRuns[w.ID]
		if !ok {
			continue
		}
		parts = append(parts, formatAutonomousRun(w.ID, runs, w.EscalationReason), "")
	}
	parts = append(parts, "Reproduce and dispose of every pending candidate. Call `verification_done(summary)` when all are filed or dismissed.")
	return strings.Join(parts, "\n")
}

// BuildVerifierContinuePrompt returns the substep 2..N prompt with
// already-filed and dismissed entries surfaced for context.
func BuildVerifierContinuePrompt(pending []FindingCandidate, filedThisPhase []FindingFiled,
	dismissedThisPhase []CandidateDismissal, substep, maxSubsteps int) string {
	parts := []string{
		fmt.Sprintf("**Verification substep %d/%d.** Filed %d, dismissed %d so far this phase.",
			substep, maxSubsteps, len(filedThisPhase), len(dismissedThisPhase)),
	}
	if len(filedThisPhase) > 0 {
		parts = append(parts, "", "**Already filed this phase (do not re-file):**")
		for _, f := range filedThisPhase {
			parts = append(parts, "- "+f.Title)
		}
	}
	if len(dismissedThisPhase) > 0 {
		parts = append(parts, "", "**Already dismissed this phase:**")
		for _, d := range dismissedThisPhase {
			parts = append(parts, "- "+d.CandidateID)
		}
	}
	parts = append(parts, "", formatPendingCandidates(pending))
	return strings.Join(parts, "\n")
}

// FormatFollowUpHints returns the verifier follow-up hints block for
// the synthesis prompt, or "" when no hints are present.
func FormatFollowUpHints(findings []FindingFiled, dismissals []CandidateDismissal) string {
	var lines []string
	for _, f := range findings {
		h := strings.TrimSpace(f.FollowUpHint)
		if h == "" {
			continue
		}

		lines = append(lines, fmt.Sprintf("- (filed: %s) %s", util.Truncate(f.Title, 80), h))
	}
	for _, d := range dismissals {
		h := strings.TrimSpace(d.FollowUpHint)
		if h == "" {
			continue
		}

		lines = append(lines, fmt.Sprintf("- (dismissed: %s) %s", d.CandidateID, h))
	}
	if len(lines) == 0 {
		return ""
	}
	return "**Verifier follow-up hints (advisory — you decide whether to act):**\n" + strings.Join(lines, "\n")
}

// BuildPerWorkerDecisionPrompt returns the user message for one per-worker decide_worker decision call.
func BuildPerWorkerDecisionPrompt(workerID int, w *WorkerState,
	turns []agent.TurnSummary, peerSummary, iterationStatus string, takenIDs map[int]bool) string {
	idStr := strconv.Itoa(workerID)
	var parts []string
	parts = append(parts, iterationStatus)
	parts = append(parts, "", fmt.Sprintf(
		"**Single tool call: `decide_worker(worker_id=%s, ...)`.** Only `decide_worker` is registered for this prompt — every other tool errors out. Output exactly one call.",
		idStr,
	))
	parts = append(parts, "", fmt.Sprintf(
		"## Worker %s activity (escalation: %s, %d autonomous turn(s))",
		idStr, orDefault(w.EscalationReason, "unknown"), len(turns),
	), "", formatAutonomousRun(workerID, turns, w.EscalationReason))
	if peerSummary != "" {
		parts = append(parts, "", "## Other alive workers (current angles, for coordination — do not duplicate)", "", peerSummary)
	}
	if hist := formatSingleWorkerHistory(w); hist != "" {
		parts = append(parts, "", hist)
	}
	parts = append(parts, "", "## decide_worker(worker_id="+idStr+", ...)",
		"- `action=\"continue\"`: keep the worker on its current angle. Provide `instruction` (next-iter directive).",
		"- `action=\"expand\"`: pivot to a new angle. Provide `instruction` (new directive).",
		"- `action=\"stop\"`: retire the worker. Provide `reason` (informs the recap).",
		"- Optional `fork={new_worker_id, instruction}`: spawn a child that inherits this worker's chronicle. `new_worker_id` must NOT be in the taken set.",
	)
	if len(takenIDs) > 0 {
		parts = append(parts, "",
			"Taken worker IDs (alive + completed — never reuse): ["+formatTakenIDs(takenIDs)+"].")
	}
	return strings.Join(parts, "\n")
}

// formatSingleWorkerHistory returns the recent-iter outcome rows for w, or "" when none are recorded.
func formatSingleWorkerHistory(w *WorkerState) string {
	entries := w.RecentHistory()
	if len(entries) == 0 {
		return ""
	}
	lines := []string{fmt.Sprintf("**Worker %d recent iter history (up to %d):**", w.ID, WorkerHistoryRing)}
	for _, e := range entries {
		angle := e.Angle
		if angle == "" {
			angle = "(no instruction)"
		}
		lines = append(lines, fmt.Sprintf(
			"- iter %d [%s] %q — %d tools, %d flows",
			e.Iteration, e.Outcome, angle, e.ToolCalls, e.FlowsTouched,
		))
	}
	return strings.Join(lines, "\n")
}

// FormatPeerSummary returns one line per alive worker other than exceptID summarizing their current angle.
func FormatPeerSummary(workers []*WorkerState, exceptID int) string {
	var lines []string
	for _, w := range workers {
		if !w.Alive || w.ID == exceptID {
			continue
		}
		angle := w.LastInstruction
		if angle == "" {
			angle = "(no instruction)"
		}
		lines = append(lines, fmt.Sprintf("- Worker %d: %s", w.ID, util.Truncate(angle, 200)))
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

// BuildSynthesisPrompt returns the user message for the synthesis call.
func BuildSynthesisPrompt(workers []*WorkerState, completed []CompletedWorker,
	verificationSummary, findingsSummary, stallWarnings, followUpHints string,
	iterationStatus string, maxWorkers int) string {
	parts := make([]string, 0, 16)
	parts = append(parts, iterationStatus)
	parts = append(parts, "",
		"**Synthesis call.** Registered tools: `plan_workers` (optional), `direction_done` (close this iteration), `end_run` (close the entire run, rarely). `decide_worker` is NOT registered — per-worker decisions are already recorded above.",
	)
	parts = append(parts, "", findingsSummary, "", "**Verification:** "+verificationSummary)
	if stallWarnings != "" {
		parts = append(parts, "", stallWarnings)
	}
	if followUpHints != "" {
		parts = append(parts, "", followUpHints)
	}
	if block := formatCompletedRoster(completed); block != "" {
		parts = append(parts, "", block)
	}
	var aliveCount int
	aliveIDs := make([]string, 0, len(workers))
	for _, w := range workers {
		if !w.Alive {
			continue
		}
		aliveCount++
		aliveIDs = append(aliveIDs, strconv.Itoa(w.ID))
	}
	aliveStr := noneSentinel
	if len(aliveIDs) > 0 {
		aliveStr = strings.Join(aliveIDs, ", ")
	}
	parts = append(parts, "", fmt.Sprintf("**Alive workers (after this iter's per-worker decisions):** [%s]  **Parallelism:** %d/%d.", aliveStr, aliveCount, maxWorkers))
	parts = append(parts, "", "## Action",
		"- `plan_workers`: spawn fresh workers and/or retarget alive ones. Use when uncovered surface remains.",
		"- `direction_done(summary)`: close this iteration. Use for almost every iteration.",
		"- `end_run(summary)`: close the entire run. Only after many iterations when the assignment is exhausted and findings have been filed.",
	)
	return strings.Join(parts, "\n")
}

// formatCompletedRoster returns the retired-workers reference block,
// capped at completedWorkersRenderCap most-recent entries.
func formatCompletedRoster(completed []CompletedWorker) string {
	if len(completed) == 0 {
		return ""
	}
	lines := []string{
		"**Workers completed earlier this run** (reference context — these IDs are gone, do NOT plan or fork against them):",
	}
	var start int
	if len(completed) > completedWorkersRenderCap {
		omitted := len(completed) - completedWorkersRenderCap
		start = omitted
		lines = append(lines, fmt.Sprintf("(%d earlier completed worker(s) omitted)", omitted))
	}
	for _, c := range completed[start:] {
		reason := c.Reason
		if reason == "" {
			reason = "(no reason given)"
		}
		summary := util.Truncate(c.Summary, completedSummaryRenderCap)
		if summary == "" {
			summary = "(summary unavailable)"
		}
		lines = append(lines, fmt.Sprintf(
			"- Worker %d (stopped iter %d, reason: %s):\n  %s",
			c.ID, c.StoppedAt, util.Truncate(reason, 200), summary,
		))
	}
	return strings.Join(lines, "\n")
}

// completedSummaryRenderCap caps each rendered per-worker summary length.
const completedSummaryRenderCap = 8000

// completedWorkersRenderCap caps the number of completed workers rendered per synthesis prompt.
const completedWorkersRenderCap = 10

// BuildIter1ReconReviewPrompt returns the iter-1 review user message (free-form response, no tool calls).
func BuildIter1ReconReviewPrompt(iterationStatus string, maxWorkers int) string {
	parts := make([]string, 0, 16)
	parts = append(parts, iterationStatus)
	parts = append(parts, "",
		"**Step 1 of 2: text response, NO tool calls.** No tools are registered for this call — every tool errors out. Plan in plain text; the next prompt will ask you to formalize via `plan_workers`.",
		"",
		"## Recon iteration complete",
		"",
		"The recon worker (worker 1) has finished its scope-mapping pass — pure exploration, no planning, no proposals. The recon record above is a factual map of what exists, not a testing plan. Planning is your job now.",
		"",
		"## Your response",
		"",
		"1. Describe the target's scope, attack surface, technology stack, and authentication boundaries as you now understand them.",
		fmt.Sprintf("2. Propose **at least 2 and up to %d** concrete, mutually-exclusive worker assignments for iteration 2. A single worker is not enough — parallelism across distinct angles is the whole point of the loop. Each assignment names a specific endpoint, technique, or attack vector. Number them starting from 2 (worker 1 is retired).", maxWorkers),
	)
	return strings.Join(parts, "\n")
}

// BuildIter1ReconPlanPrompt returns the iter-1 plan user message
// asking for plan_workers + direction_done.
func BuildIter1ReconPlanPrompt(iterationStatus string, maxWorkers int) string {
	parts := make([]string, 0, 16)
	parts = append(parts, iterationStatus)
	parts = append(parts, "",
		"**Step 2 of 2: formalize the iter-2 roster.** Registered tools: `plan_workers`, `direction_done`. `decide_worker` and `end_run` are NOT registered — worker 1 is already retired and the run is just starting.",
		"",
		fmt.Sprintf("1. Call `plan_workers` once with the assignments you proposed above. Include **at least 2 entries and up to %d**. Pick fresh integer worker_ids starting from 2.", maxWorkers),
		"2. Call `direction_done(summary)` to close this iteration. The summary briefly recaps the recon findings and the iter-2 plan.",
	)
	return strings.Join(parts, "\n")
}

// BuildIter1ReconPlanRetryPrompt returns the retry message when the iter-1 plan call did not invoke plan_workers.
func BuildIter1ReconPlanRetryPrompt() string {
	return "**You did NOT call `plan_workers` in your last response.** A worker roster is required to continue. Call `plan_workers` now with **at least 2** `{worker_id, assignment}` entries on distinct angles (worker_ids starting from 2; each assignment names a specific endpoint or technique). Then call `direction_done(summary)` to close. This is your last chance — without a `plan_workers` call the run ends."
}
