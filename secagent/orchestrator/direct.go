package orchestrator

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/history"
	"github.com/go-appsec/secagent/util"
)

// FireWorkerFunc starts one worker's iter+1 autonomous run and returns a
// join function that blocks for the resulting TurnSummaries.
type FireWorkerFunc func(ctx context.Context, w *WorkerState) (joinFn func() []agent.TurnSummary)

// SpawnChildFunc returns a forked child worker provisioned with id and the initial instruction.
type SpawnChildFunc func(ctx context.Context, id int, instruction string) (*WorkerState, error)

// DecisionPhaseInput bundles the inputs to RunDecisionPhase.
type DecisionPhaseInput struct {
	Director        agent.Agent
	DirChat         *DirectorChat
	Decisions       *DecisionQueue
	Workers         []*WorkerState // current alive set + dead (for completed-roster context)
	WorkerRuns      map[int][]agent.TurnSummary
	IterationStatus string
	Iter            int
	MaxWorkers      int
	TakenIDs        func() map[int]bool
	Fire            FireWorkerFunc
	SpawnChild      SpawnChildFunc
	Retire          func(w *WorkerState, reason string, iter int)
}

// DecisionPhaseResult carries the join handles for worker runs fired
// during RunDecisionPhase. Call Wait at iter boundary to collect them.
type DecisionPhaseResult struct {
	mu    sync.Mutex
	joins map[int]func() []agent.TurnSummary
}

// Wait blocks on every fired worker run and returns the per-worker turn-summary map.
func (r *DecisionPhaseResult) Wait() map[int][]agent.TurnSummary {
	if r == nil {
		return nil
	}
	out := map[int][]agent.TurnSummary{}
	r.mu.Lock()
	joins := r.joins
	r.mu.Unlock()
	for id, j := range joins {
		out[id] = j()
	}
	return out
}

// RunDecisionPhase records one decide_worker decision per alive worker and
// returns the join handles for any iter+1 runs fired by those decisions.
func RunDecisionPhase(
	ctx context.Context,
	in DecisionPhaseInput,
	log *Logger,
) *DecisionPhaseResult {
	in.Decisions.BeginPhase(agent.PhaseDirection)
	res := &DecisionPhaseResult{joins: map[int]func() []agent.TurnSummary{}}

	// Sort alive workers by ID for deterministic order.
	alive := bulk.SliceFilter(func(w *WorkerState) bool { return w.Alive }, in.Workers)
	slices.SortFunc(alive, func(a, b *WorkerState) int { return cmp.Compare(a.ID, b.ID) })

	for _, w := range alive {
		// shutdown short-circuit: don't spawn doomed runs on canceled ctx
		if ctx.Err() != nil {
			log.Log("decision", "phase aborted", map[string]any{"err": ctx.Err().Error()})
			break
		}

		// drain buffered self-prunes before appending fresh activity
		if drops := w.DrainSelfPrunes(); len(drops) > 0 {
			in.DirChat.ApplyWorkerSelfPrune(w.ID, drops)
			w.Chronicle.ApplySelfPrune(drops)
		}
		activity := snapshotWorkerIterActivity(w)
		in.DirChat.AppendWorkerActivity(w.ID, in.Iter, activity)

		decisionsBefore := len(in.Decisions.WorkerDecisions)
		askWorker(ctx, in, w, log)
		if len(in.Decisions.WorkerDecisions) == decisionsBefore {
			if ctx.Err() != nil {
				log.Log("decision", "phase aborted", map[string]any{"err": ctx.Err().Error()})
				break
			}
			// no decision recorded; default-continue so the directive isn't lost
			log.Log("decision", "no-decision-defaulting-to-continue", map[string]any{
				"worker_id": w.ID,
			})
			in.Decisions.AddDecision(WorkerDecision{
				Kind:        "continue",
				WorkerID:    w.ID,
				Instruction: w.LastInstruction,
			})
		}

		d := in.Decisions.WorkerDecisions[len(in.Decisions.WorkerDecisions)-1]
		appendDecisionToChat(in.DirChat, w.ID, in.Iter, d)

		applyDecisionAndFire(ctx, in, w, d, res, log)
	}
	in.Decisions.BeginPerWorkerDecision(0) // clear the asked-worker hint
	return res
}

// askWorker drives one per-worker decision call: installs the rendered
// view + prompt on the director and runs a bounded drain.
func askWorker(ctx context.Context, in DecisionPhaseInput, w *WorkerState, log *Logger) {
	view := in.DirChat.RenderForWorker(w.ID)
	peer := FormatPeerSummary(in.Workers, w.ID)
	taken := map[int]bool{}
	if in.TakenIDs != nil {
		taken = in.TakenIDs()
	}
	prompt := BuildPerWorkerDecisionPrompt(
		w.ID, w, in.WorkerRuns[w.ID], peer, in.IterationStatus, taken,
	)
	in.Director.ReplaceHistory(view)
	in.Director.Query(prompt)
	in.Decisions.BeginPerWorkerDecision(w.ID)
	if _, err := in.Director.DrainBounded(ctx, decisionDrainMaxRounds); err != nil {
		log.Log("decision", "drain error", map[string]any{
			"worker_id": w.ID, "err": err.Error(),
		})
	}
}

// applyDecisionAndFire applies d to w (continue/expand fires the next run, stop enqueues retire,
// fork spawns + fires a child) and records any fired-run joins on res.
func applyDecisionAndFire(ctx context.Context,
	in DecisionPhaseInput, w *WorkerState, d WorkerDecision, res *DecisionPhaseResult, log *Logger) {
	switch d.Kind {
	case decideActionStop:
		log.Log("decision", decideActionStop, map[string]any{"worker_id": w.ID, "reason": d.Reason})
		if in.Retire != nil {
			in.Retire(w, d.Reason, in.Iter)
		} else {
			w.Alive = false
			_ = w.Agent.Close()
		}
	case decideActionContinue, decideActionExpand:
		budget := d.AutonomousBudget
		if budget <= 0 {
			budget = defaultAutonomousBudget
		}
		if budget > 20 {
			budget = 20
		}
		w.AutonomousBudget = budget
		w.LastInstruction = d.Instruction
		if in.Fire != nil {
			w.Chronicle.Install(w.Agent, w.LastInstruction)
			join := in.Fire(ctx, w)
			res.mu.Lock()
			res.joins[w.ID] = join
			res.mu.Unlock()
		}
		log.Log("decision", d.Kind, map[string]any{
			"worker_id": w.ID, "autonomous_budget": budget,
		})
	}
	// stop+fork is meaningless (child of a retired worker), so skip
	if d.Fork != nil && d.Kind != "stop" && in.SpawnChild != nil {
		nw, err := in.SpawnChild(ctx, d.Fork.NewWorkerID, d.Fork.Instruction)
		if err != nil {
			log.Log("fork", "spawn failed", map[string]any{
				"parent": w.ID, "new": d.Fork.NewWorkerID, "err": err.Error(),
			})
			return
		}
		header := "[Inherited investigative history from worker " + strconv.Itoa(w.ID) +
			" at iter " + strconv.Itoa(in.Iter) +
			". The remainder of this chronicle records that worker's prior turns; you are now worker " +
			strconv.Itoa(nw.ID) + ", picking up the thread under a new directive.]"
		nw.Chronicle = w.Chronicle.CloneWithDirective(header, in.Iter)
		if in.Fire != nil {
			nw.Chronicle.Install(nw.Agent, nw.LastInstruction)
			join := in.Fire(ctx, nw)
			res.mu.Lock()
			res.joins[nw.ID] = join
			res.mu.Unlock()
		}
		log.Log("fork", "spawn", map[string]any{
			"parent": w.ID, "new": nw.ID,
			"inherited_msgs": nw.Chronicle.Len(),
		})
	}
}

// snapshotWorkerIterActivity returns the worker agent's history from the
// iteration boundary onward, or nil when the agent doesn't expose a
// boundary. Empty content on user/system/tool messages is normalized.
func snapshotWorkerIterActivity(w *WorkerState) []agent.Message {
	out := history.SnapshotSinceBoundary(w.Agent)
	if out == nil {
		return nil
	}
	NormalizeEmptyContent(out)
	return out
}

// appendDecisionToChat appends a tagged user-role summary of d to c.
func appendDecisionToChat(c *DirectorChat, workerID, iter int, d WorkerDecision) {
	body := "[director decision recorded for worker " + strconv.Itoa(workerID) + ": " +
		d.Kind
	switch d.Kind {
	case "continue", "expand":
		body += " — " + util.Truncate(d.Instruction, 400)
		if d.AutonomousBudget > 0 {
			body += " (budget=" + strconv.Itoa(d.AutonomousBudget) + ")"
		}
	case "stop":
		body += " — " + util.Truncate(d.Reason, 400)
	}
	if d.Fork != nil {
		body += " | fork worker " + strconv.Itoa(d.Fork.NewWorkerID) + ": " +
			util.Truncate(d.Fork.Instruction, 400)
	}
	body += "]"
	c.Append(agent.Message{Role: "user", Content: body}, workerID, iter)
}

// SynthesisPhaseInput bundles the inputs to RunSynthesisPhase.
type SynthesisPhaseInput struct {
	Director        agent.Agent
	DirChat         *DirectorChat
	Decisions       *DecisionQueue
	Workers         []*WorkerState
	Completed       []CompletedWorker
	VerifierSummary string
	FindingsSummary string
	StallWarnings   string
	FollowUpHints   string
	IterationStatus string
	MaxWorkers      int
}

// RunSynthesisPhase runs the post-decision synthesis call. If the director
// didn't close the phase explicitly, direction_done is auto-recorded.
func RunSynthesisPhase(ctx context.Context, in SynthesisPhaseInput, log *Logger) bool {
	in.Decisions.BeginPhase(agent.PhaseDirection)
	view := in.DirChat.RenderForSynthesis()
	prompt := BuildSynthesisPrompt(
		in.Workers, in.Completed,
		in.VerifierSummary, in.FindingsSummary, in.StallWarnings, in.FollowUpHints,
		in.IterationStatus, in.MaxWorkers,
	)
	in.Director.ReplaceHistory(view)
	in.Director.Query(prompt)
	if _, err := in.Director.Drain(ctx); err != nil {
		log.Log("synthesis", "drain error", map[string]any{"err": err.Error()})
	}
	closed := in.Decisions.HasDirectionDone || in.Decisions.HasEndRun
	if !closed {
		if ctx.Err() != nil {
			// Shutdown was requested mid-drain.
			// Don't auto-close; the controller is exiting and the next-iter loop check will break anyway
			log.Log("synthesis", "phase aborted", map[string]any{"err": ctx.Err().Error()})
			return false
		}
		// The synthesis call didn't close the phase
		// Auto-close so the controller doesn't wedge; director_done is the safe default
		in.Decisions.SetDirectionDone("auto: synthesis did not call direction_done")
		log.Log("synthesis", "auto-direction-done", nil)
	}
	return true
}

// RunIter1ReconReviewCall runs the iter-1 recon review (first of two synthesis calls). The director's
// free-form response is appended to dirChat. Caller must clear director tools before invoking.
func RunIter1ReconReviewCall(ctx context.Context,
	director agent.Agent, dirChat *DirectorChat,
	iterationStatus string, iter, maxWorkers int, log *Logger) {
	view := dirChat.RenderForSynthesis()
	prompt := BuildIter1ReconReviewPrompt(iterationStatus, maxWorkers)
	director.ReplaceHistory(view)
	director.Query(prompt)
	turn, err := director.Drain(ctx)
	if err != nil {
		log.Log("synthesis", "iter1-review drain error", map[string]any{"err": err.Error()})
	}
	text := strings.TrimSpace(agent.StripThinkBlocks(turn.AssistantText))
	if text == "" {
		log.Log("synthesis", "iter1-review empty response", nil)
		return
	}
	dirChat.Append(agent.Message{
		Role:    "assistant",
		Content: text,
	}, 0, iter)
	log.Log("synthesis", "iter1-review captured", map[string]any{
		"chars":   len(text),
		"preview": util.Truncate(text, 600),
	})
}

// RunIter1ReconPlanCall runs the iter-1 recon plan call (second of two synthesis calls).
// Records plan_workers / direction_done into decisions, retrying once if plan_workers was missing.
// Caller must register the synthesis tools on director before invoking.
func RunIter1ReconPlanCall(ctx context.Context, director agent.Agent, dirChat *DirectorChat, decisions *DecisionQueue,
	iterationStatus string, maxWorkers int, log *Logger) {
	decisions.BeginPhase(agent.PhaseDirection)
	view := dirChat.RenderForSynthesis()
	director.ReplaceHistory(view)
	director.Query(BuildIter1ReconPlanPrompt(iterationStatus, maxWorkers))
	if _, err := director.Drain(ctx); err != nil {
		log.Log("synthesis", "iter1-plan drain error", map[string]any{"err": err.Error()})
	}
	// Mandatory retry: if plan_workers wasn't called, re-prompt once
	if !decisions.HasPlan {
		log.Log("synthesis", "iter1-plan missing-retry", nil)
		director.Query(BuildIter1ReconPlanRetryPrompt())
		if _, err := director.Drain(ctx); err != nil {
			log.Log("synthesis", "iter1-plan retry drain error", map[string]any{"err": err.Error()})
		}
	}
	if !decisions.HasDirectionDone && !decisions.HasEndRun {
		decisions.SetDirectionDone("auto: iter-1 plan call did not call direction_done")
		log.Log("synthesis", "iter1-plan auto-direction-done", nil)
	}
	log.Log("synthesis", "iter1-plan result", map[string]any{
		"has_plan":    decisions.HasPlan,
		"plan_count":  len(decisions.Plan),
		"closed_done": decisions.HasDirectionDone,
	})
}
