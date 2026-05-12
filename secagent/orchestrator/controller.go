package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-analyze/bulk"
	"golang.org/x/sync/errgroup"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/config"
	"github.com/go-appsec/secagent/history"
	"github.com/go-appsec/secagent/mcp"
	"github.com/go-appsec/secagent/orchestrator/prompts"
	"github.com/go-appsec/secagent/util"
)

// AgentFactory builds Agent instances per role. NewReconWorker omits
// report_finding_candidate so recon cannot file findings.
type AgentFactory interface {
	NewWorker(id, numWorkers int) (agent.Agent, error)
	NewReconWorker(reconMission string) (agent.Agent, error)
	NewVerifier(onContextOverflow func()) (agent.Agent, error)
	NewDecisionDirector() (agent.Agent, error)
	NewSynthesisDirector() (agent.Agent, error)
	Close() error
}

// OpenAIFactory builds OpenAIAgent instances against the shared pool.
type OpenAIFactory struct {
	Cfg       *config.Config
	Pool      *agent.ClientPool
	Malformed *MalformedCounter
	Log       *Logger
	// Reasoning handler; nil falls back to inline.
	Reasoning agent.ReasoningHandler
	// Summarizer enables worker compaction callbacks; nil disables.
	Summarizer *history.Summarizer
	// ReconSummary is prepended to non-recon worker system prompts.
	ReconSummary string
}

// slowToolThreshold is the time threshold for tool calls to be logged as slow.
const slowToolThreshold = 10 * time.Second

func (f *OpenAIFactory) malformedCallback(model string) func(name string, err error) {
	if f.Malformed == nil {
		return nil
	}
	return func(name string, err error) { f.Malformed.Observe(model, name, err) }
}

// requestCallbacks returns start/end hooks that log each chat-completion call tagged with role.
func (f *OpenAIFactory) requestCallbacks(role string) (func(int), func(int, time.Duration, int, int, error)) {
	start := func(attempt int) {
		fields := map[string]any{"role": role}
		if attempt > 0 {
			fields["attempt"] = attempt
		}
		f.Log.Log("agent", "request", fields)
	}
	end := func(attempt int, elapsed time.Duration, tokensIn, tokensOut int, err error) {
		fields := map[string]any{
			"role":       role,
			"elapsed":    elapsed.Round(time.Millisecond).String(),
			"tokens_in":  tokensIn,
			"tokens_out": tokensOut,
		}
		if attempt > 0 {
			fields["attempt"] = attempt
		}
		msg := "response"
		if err != nil {
			fields["err"] = err.Error()
			switch {
			case errors.Is(err, context.Canceled):
				msg = "response cancelled"
			case errors.Is(err, context.DeadlineExceeded):
				msg = "response timeout"
			default:
				msg = "response error"
			}
		}
		f.Log.Log("agent", msg, fields)
	}
	return start, end
}

// toolCallbacks returns start/end hooks for tool dispatches tagged with role.
func (f *OpenAIFactory) toolCallbacks(role string) (func(string, json.RawMessage), func(string, json.RawMessage, time.Duration, bool, bool, string)) {
	start := func(name string, _ json.RawMessage) {
		f.Log.Log("tool", "start", map[string]any{"role": role, "name": name})
	}
	end := func(name string, _ json.RawMessage, elapsed time.Duration, isErr, timedOut bool, errText string) {
		fields := map[string]any{
			"role":    role,
			"name":    name,
			"elapsed": elapsed.Round(time.Millisecond).String(),
			"error":   isErr,
		}
		if errText != "" {
			fields["error_text"] = errText
		}
		msg := toolMsgDone
		switch {
		case timedOut:
			msg = toolMsgTimeout
		case elapsed >= slowToolThreshold && !isErr:
			msg = toolMsgSlow
		}
		f.Log.Log("tool", msg, fields)
	}
	return start, end
}

// fuzzyToolMatchCallback returns a hook that logs fuzzy tool-name matches.
func (f *OpenAIFactory) fuzzyToolMatchCallback(role string) func(received, resolved string) {
	return func(received, resolved string) {
		f.Log.Log("tool", "fuzzy-name-match", map[string]any{
			"role":     role,
			"received": received,
			"resolved": resolved,
		})
	}
}

// callbackErrorCallback returns a hook that logs aux compaction-pass failures.
func (f *OpenAIFactory) callbackErrorCallback(role string) func(error) {
	return func(err error) {
		f.Log.Log("agent", "compact-callback-error", map[string]any{
			"role": role,
			"err":  err.Error(),
		})
	}
}

// compactCallback returns a hook that logs compaction events for role.
func (f *OpenAIFactory) compactCallback(role string) func(agent.CompactionReport) {
	return func(r agent.CompactionReport) {
		fields := map[string]any{
			"role":   role,
			"before": r.Before,
			"after":  r.After,
		}
		if n := len(r.PassesApplied); n > 0 {
			fields["phase"] = r.PassesApplied[n-1]
		}
		f.Log.Log("agent", "compact", fields)
	}
}

// buildAgent assembles an OpenAIAgent for the given role.
func (f *OpenAIFactory) buildAgent(
	role, model, systemPrompt string,
	pool *agent.ClientPool,
	maxContext int,
	reasoning agent.ReasoningHandler,
	setFlowExtractor bool,
	onContextOverflow func(),
	retireOnPressure bool,
	wireCompactionAssist bool,
) agent.Agent {
	onReqStart, onReqEnd := f.requestCallbacks(role)
	onToolStart, onToolEnd := f.toolCallbacks(role)
	compactionOpts := agent.CompactionOptions{
		HighWatermark:          f.Cfg.HighWatermark,
		LowWatermark:           f.Cfg.LowWatermark,
		KeepTurns:              f.Cfg.KeepTurns,
		HardTruncateOnOverflow: true,
	}
	compactorOpts := history.CompactorOptions{
		Compaction:       compactionOpts,
		RetireOnPressure: retireOnPressure,
		OnCallbackError:  f.callbackErrorCallback(role),
		OnCompact:        f.compactCallback(role),
	}
	if wireCompactionAssist && f.Summarizer != nil {
		compactorOpts.OnSelfPruneCandidates = history.SelfPruneCallback(f.Summarizer)
		compactorOpts.OnDistillResults = history.DistillCallback(f.Summarizer)
	}
	cfg := agent.OpenAIAgentConfig{
		Model:             model,
		SystemPrompt:      systemPrompt,
		Pool:              pool,
		MaxContext:        maxContext,
		TurnTimeout:       f.Cfg.TurnTimeout,
		PerToolTimeout:    f.Cfg.PerToolTimeout,
		MaxParallelTools:  f.Cfg.MaxParallelTools,
		MaxTurnsPerAgent:  f.Cfg.MaxTurnsPerAgent,
		KeepThinkTurns:    f.Cfg.EffectiveKeepThinkTurns(maxContext),
		Reasoning:         reasoning,
		OnMalformedCall:   f.malformedCallback(model),
		OnRequestStart:    onReqStart,
		OnRequestEnd:      onReqEnd,
		OnToolStart:       onToolStart,
		OnToolEnd:         onToolEnd,
		OnFuzzyToolMatch:  f.fuzzyToolMatchCallback(role),
		OnContextOverflow: onContextOverflow,
		OnHardTruncate:    f.compactCallback(role),
		Compactor:         history.NewLayeredCompactor(compactorOpts),
	}
	if setFlowExtractor {
		cfg.FlowIDExtractor = ExtractFlowIDs
	}
	return agent.NewOpenAIAgent(cfg)
}

// withMission appends cfg.Prompt and ReconSummary (when non-empty) to systemPrompt as anchored sections.
func (f *OpenAIFactory) withMission(systemPrompt string) string {
	mission := strings.TrimSpace(f.Cfg.Prompt)
	out := systemPrompt
	if mission != "" {
		out += "\n\n## Mission (original assignment for this run — do not lose sight of this)\n\n" + mission
	}
	recon := strings.TrimSpace(f.ReconSummary)
	if recon != "" {
		out += "\n\n## Recon (iter-1 scope mapping by retired worker 1 — anchored context for every subsequent worker)\n\n" + recon
	}
	return out
}

// withRecon appends reconMission to systemPrompt as an anchored section.
func (f *OpenAIFactory) withRecon(systemPrompt, reconMission string) string {
	out := systemPrompt + "\n\n## Recon goal (this run's surface-mapping objective — observation only)"
	if recon := strings.TrimSpace(reconMission); recon != "" {
		out += "\n\n" + recon
	}
	return out
}

// NewWorker returns a worker agent with the given id out of numWorkers.
func (f *OpenAIFactory) NewWorker(id, numWorkers int) (agent.Agent, error) {
	return f.buildAgent(
		fmt.Sprintf("worker-%d", id),
		f.Cfg.Model,
		f.withMission(prompts.BuildWorkerSystemPrompt(id, numWorkers)),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		true,
		nil,
		false,
		true, // wire model-driven compaction assist (workers only)
	), nil
}

// NewReconWorker returns the iter-1 recon worker agent anchored to reconMission.
// The agent retires at the high watermark instead of compacting (preserving the full chronicle).
func (f *OpenAIFactory) NewReconWorker(reconMission string) (agent.Agent, error) {
	return f.buildAgent(
		"worker-1-recon",
		f.Cfg.Model,
		f.withRecon(prompts.BuildReconWorkerSystemPrompt(), reconMission),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		true,
		nil,
		true,  // RetireOnPressure: recon stops cleanly at high watermark
		false, // RetireOnPressure short-circuits maybeCompact, so callbacks are unreachable; skip wiring
	), nil
}

// NewVerifier returns a verifier agent. onContextOverflow fires when a chat-completion call is rejected as over-context.
func (f *OpenAIFactory) NewVerifier(onContextOverflow func()) (agent.Agent, error) {
	return f.buildAgent(
		"verifier",
		f.Cfg.Model,
		f.withMission(prompts.BuildVerifierSystemPrompt()),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		true,
		onContextOverflow,
		false,
		true, // wire model-driven compaction assist (parity with workers)
	), nil
}

// NewDecisionDirector returns the per-worker decision director agent.
func (f *OpenAIFactory) NewDecisionDirector() (agent.Agent, error) {
	return f.buildAgent(
		"director-review",
		f.Cfg.Model,
		f.withMission(prompts.BuildDirectorDecisionSystemPrompt(f.Cfg.MaxWorkers)),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		false,
		nil,
		false,
		false, // director compaction stays mechanical
	), nil
}

// NewSynthesisDirector returns the iteration-end synthesis director agent.
func (f *OpenAIFactory) NewSynthesisDirector() (agent.Agent, error) {
	return f.buildAgent(
		"director-plan",
		f.Cfg.Model,
		f.withMission(prompts.BuildDirectorSynthesisSystemPrompt(f.Cfg.MaxWorkers)),
		f.Pool,
		f.Cfg.MaxContext,
		f.Reasoning,
		false,
		nil,
		false,
		false, // director compaction stays mechanical
	), nil
}

func (f *OpenAIFactory) Close() error { return nil }

// buildClientPool returns a bounded-concurrency ClientPool of n distinct ChatClient instances against baseURL.
// httpTimeout caps each HTTP call; 0 disables it.
func buildClientPool(baseURL, apiKey string, n int, httpTimeout time.Duration) *agent.ClientPool {
	if n < 1 {
		n = 1
	}
	clients := make([]agent.ChatClient, 0, n)
	for i := 0; i < n; i++ {
		clients = append(clients, agent.NewOpenAIChatClient(baseURL, apiKey, httpTimeout))
	}
	return agent.NewClientPoolWithClients(clients)
}

// resolveFormat returns the reasoning format for (baseURL, model) via cache, probing through client on cache miss.
func resolveFormat(ctx context.Context, cache *agent.ReasoningFormatCache, pool *agent.ClientPool,
	role, baseURL, model string, log *Logger) agent.ReasoningFormat {
	client, err := pool.Acquire(ctx)
	if err != nil {
		log.Log("server", "reasoning-format probe aborted", map[string]any{
			"role": role, "model": model, "err": err.Error(),
		})
		return agent.ReasoningFormatUnknown
	}
	defer pool.Release(client)
	return cache.Resolve(ctx, client, baseURL, model,
		func(f agent.ReasoningFormat, elapsed time.Duration, err error) {
			fields := map[string]any{
				"role":     role,
				"model":    model,
				"base_url": baseURL,
				"format":   f.String(),
				"elapsed":  elapsed.Round(time.Millisecond).String(),
			}
			if err != nil {
				fields["err"] = err.Error()
			}
			log.Log("server", "reasoning-format", fields)
		},
	)
}

// workerSpawnFunc returns a ready-to-run worker provisioned with id,
// numWorkers and the assignment as its initial LastInstruction.
type workerSpawnFunc func(ctx context.Context, id, numWorkers int, assignment string) (*WorkerState, error)

// newWorkerSpawner returns a workerSpawnFunc that provisions workers against the MCP endpoint at mcpURL.
func newWorkerSpawner(mcpURL string, toolResultMaxBytes int,
	factory AgentFactory, candidates *CandidatePool, writer *FindingWriter,
	candidateDedup CandidateDedupReviewer, merger MergeSubmitter, autonomousBudget int) workerSpawnFunc {
	return func(ctx context.Context, id, numWorkers int, assignment string) (*WorkerState, error) {
		m, err := mcp.Connect(ctx, mcpURL)
		if err != nil {
			return nil, fmt.Errorf("mcp connect (worker %d): %w", id, err)
		}
		defs, err := m.BuildToolDefs(ctx, "mcp__sectool__", toolResultMaxBytes)
		if err != nil {
			_ = m.Close()
			return nil, fmt.Errorf("list sectool tools (worker %d): %w", id, err)
		}
		a, err := factory.NewWorker(id, numWorkers)
		if err != nil {
			_ = m.Close()
			return nil, fmt.Errorf("new worker %d: %w", id, err)
		}
		tools := append(slices.Clone(defs), WorkerToolDefs(candidates, writer, id, candidateDedup, merger)...)
		a.SetTools(tools)
		ws := &WorkerState{
			ID:               id,
			Agent:            a,
			MCP:              m,
			Alive:            true,
			LastInstruction:  assignment,
			AutonomousBudget: autonomousBudget,
		}
		// Buffer self-prune drops so RunDecisionPhase can mirror them onto DirectorChat and the chronicle
		a.SetOnSelfPruneApplied(ws.BufferSelfPrunes)
		return ws, nil
	}
}

// Run starts sectool and drives the iteration loop until cfg.MaxIterations is reached or the director ends the run.
// attached signals that an MCP server is already reachable at cfg.MCPPort; when true no child sectool is launched.
func Run(ctx context.Context, cfg *config.Config, attached bool, log *Logger, sd *Shutdown) error {
	srv, err := StartSectool(ctx, cfg.ProxyPort, cfg.MCPPort, cfg.SectoolBinary, attached, log)
	if err != nil {
		return fmt.Errorf("sectool start: %w", err)
	}
	defer srv.Terminate()

	mcpURL := srv.URL

	log.Log("server", "models", map[string]any{
		"model":     cfg.Model,
		"log_model": cfg.LogModel,
	})

	// 2m headroom keeps context cancellation as the normal termination path
	httpTimeout := cfg.TurnTimeout + 2*time.Minute
	pool := buildClientPool(cfg.BaseURL, cfg.APIKey, cfg.AgentPoolSize, httpTimeout)
	// dedicated log pool isolates narrator from main-pool contention
	logPool := buildClientPool(cfg.BaseURL, cfg.APIKey, cfg.LogPoolSize(), httpTimeout)
	mainReasoning, logReasoning := probeReasoningHandlers(ctx, cfg, pool, logPool, log)

	malformed := NewMalformedCounter(log)
	defer malformed.Flush()
	factory := &OpenAIFactory{
		Cfg: cfg, Pool: pool,
		Malformed: malformed, Log: log,
		Reasoning: mainReasoning,
	}

	candidates := NewCandidatePool()
	decisions := NewDecisionQueue()
	writer := NewFindingWriter(cfg.FindingsDir)
	// shared between worker hot path, verifier dedup, and async merger; main
	// model only; the log model produced too many false-merge verdicts
	dedupReviewer := &OpenAIDedupReviewer{
		Pool:  pool,
		Model: cfg.Model,
		Log:   log,
	}
	// load-bearing summaries (worker recall, director planning compaction); main model
	summarizer := &history.Summarizer{
		Pool:  pool,
		Model: cfg.Model,
		Log:   log,
	}
	factory.Summarizer = summarizer
	// cap=4 so a candidate flurry can't saturate the shared pool; Wait at
	// shutdown so the user doesn't lose work mid-merge
	asyncMerger := newAsyncMerger(ctx, dedupReviewer, writer, log, 4)
	defer asyncMerger.Wait()

	// retired-worker registry; mutated on the main goroutine
	var completed []CompletedWorker
	retireQueue := newRetireQueue(ctx, summarizer, cfg.Prompt, log, 4)
	defer retireQueue.Wait()

	// goroutine join (Drain return) is the read/write synchronizing event
	var verifierOverflowed bool
	verifier, err := factory.NewVerifier(func() {
		verifierOverflowed = true
	})
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	defer func() { _ = verifier.Close() }()
	// two phase-scoped director agents share DirectorChat; split prompts
	// stop the model from hallucinating wrong-phase tools
	decisionDirector, err := factory.NewDecisionDirector()
	if err != nil {
		return fmt.Errorf("new decision director: %w", err)
	}
	defer func() { _ = decisionDirector.Close() }()
	synthesisDirector, err := factory.NewSynthesisDirector()
	if err != nil {
		return fmt.Errorf("new synthesis director: %w", err)
	}
	defer func() { _ = synthesisDirector.Close() }()

	verifierMCP, err := mcp.Connect(ctx, mcpURL)
	if err != nil {
		return fmt.Errorf("mcp connect (verifier): %w", err)
	}
	defer func() { _ = verifierMCP.Close() }()

	verifierSectoolDefs, err := verifierMCP.BuildToolDefs(ctx, "mcp__sectool__", cfg.ToolResultMaxBytes)
	if err != nil {
		return fmt.Errorf("list verifier sectool tools: %w", err)
	}

	// Directors get full sectool access to spot-check worker claims rather than hallucinate tool calls
	// Each director gets its own MCP client to keep tool dispatch state scoped per agent
	decisionDirectorMCP, err := mcp.Connect(ctx, mcpURL)
	if err != nil {
		return fmt.Errorf("mcp connect (decision director): %w", err)
	}
	defer func() { _ = decisionDirectorMCP.Close() }()
	decisionDirectorSectoolDefs, err := decisionDirectorMCP.BuildToolDefs(ctx, "mcp__sectool__", cfg.ToolResultMaxBytes)
	if err != nil {
		return fmt.Errorf("list decision director sectool tools: %w", err)
	}
	synthesisDirectorMCP, err := mcp.Connect(ctx, mcpURL)
	if err != nil {
		return fmt.Errorf("mcp connect (synthesis director): %w", err)
	}
	defer func() { _ = synthesisDirectorMCP.Close() }()
	synthesisDirectorSectoolDefs, err := synthesisDirectorMCP.BuildToolDefs(ctx, "mcp__sectool__", cfg.ToolResultMaxBytes)
	if err != nil {
		return fmt.Errorf("list synthesis director sectool tools: %w", err)
	}

	verifierTools := append(slices.Clone(verifierSectoolDefs), VerifierToolDefs(decisions)...)
	verifier.SetTools(verifierTools)

	spawn := newWorkerSpawner(mcpURL, cfg.ToolResultMaxBytes, factory, candidates, writer, dedupReviewer, asyncMerger, cfg.AutonomousBudget)

	workers := make([]*WorkerState, 0, cfg.MaxWorkers)
	defer func() {
		for _, w := range workers {
			w.Close()
		}
	}()
	var w1 *WorkerState
	if cfg.SkipRecon {
		log.Log("server", "recon", map[string]any{"enabled": false, "reason": "--skip-recon"})
		w1, err = spawn(ctx, 1, 1, cfg.Prompt)
		if err != nil {
			return err
		}
		log.Log("worker", "seeded testing worker (skip-recon)", map[string]any{"id": 1})
	} else {
		reconMission, rerr := summarizer.SummarizeReconMission(ctx, cfg.Prompt)
		if rerr != nil || reconMission == "" {
			// fail-soft: degrade to verbatim cfg.Prompt
			fields := map[string]any{"fallback": "cfg.Prompt verbatim"}
			if rerr != nil {
				fields["err"] = rerr.Error()
			}
			log.Log("recon", "mission-summary failed", fields)
			reconMission = cfg.Prompt
		}
		log.Log("recon", "start", map[string]any{
			"mission_chars":   len(reconMission),
			"mission_preview": util.Truncate(reconMission, 240),
		})
		m, err := mcp.Connect(ctx, mcpURL)
		if err != nil {
			return fmt.Errorf("mcp connect (recon worker): %w", err)
		}
		defs, err := m.BuildToolDefs(ctx, "mcp__sectool__", cfg.ToolResultMaxBytes)
		if err != nil {
			_ = m.Close()
			return fmt.Errorf("list sectool tools (recon worker): %w", err)
		}
		a, err := factory.NewReconWorker(reconMission)
		if err != nil {
			_ = m.Close()
			return fmt.Errorf("new recon worker: %w", err)
		}
		a.SetTools(defs)
		w1 = &WorkerState{
			ID:               1,
			Agent:            a,
			MCP:              m,
			Alive:            true,
			LastInstruction:  prompts.ReconDirective,
			AutonomousBudget: cfg.AutonomousBudget,
		}
		log.Log("worker", "seeded recon", map[string]any{"id": 1})
	}
	workers = append(workers, w1)

	// canonical long-lived chat; each director call installs a compacted view via ReplaceHistory
	dirChat := NewDirectorChat()

	// captured by closures so end_run / takenIDs see live state
	var guardIteration int
	guardStateFn := func() (int, int) { return guardIteration, writer.RunCount }
	takenIDsFn := func() map[int]bool {
		out := map[int]bool{}
		for _, w := range workers {
			out[w.ID] = true
		}
		for _, c := range completed {
			out[c.ID] = true
		}
		return out
	}
	completedIDsFn := func() map[int]bool {
		out := map[int]bool{}
		for _, c := range completed {
			out[c.ID] = true
		}
		// retired workers whose summary is still in flight
		for _, w := range workers {
			if !w.Alive {
				out[w.ID] = true
			}
		}
		return out
	}
	aliveWorkerIDsFn := func() []int {
		var out []int
		for _, w := range workers {
			if w.Alive {
				out = append(out, w.ID)
			}
		}
		return out
	}

	// pushed to the narrator via SetActiveAgents; narrator never dereferences controller-owned state directly
	currentPhase := "idle"

	computeActiveAgents := func() []NamedAgent {
		switch currentPhase {
		case "autonomous":
			var out []NamedAgent
			for _, w := range workers {
				if !w.Alive {
					continue
				}
				out = append(out, NamedAgent{
					Name:  fmt.Sprintf("worker-%d", w.ID),
					Agent: w.Agent,
				})
			}
			return out
		case "verification":
			return []NamedAgent{{Name: "verifier", Agent: verifier}}
		case "direction":
			return []NamedAgent{
				{Name: "director-review", Agent: decisionDirector},
				{Name: "director-plan", Agent: synthesisDirector},
			}
		}
		return nil
	}

	// Narration runs through its own logPool so worker traffic on the main pool can't starve operator-facing summaries
	// Pool capacity itself is the only cap on concurrent narration calls
	narrator := NewNarrator(NarratorConfig{
		Interval:   cfg.NarrateInterval,
		Model:      cfg.LogModel,
		Pool:       logPool,
		CallBudget: cfg.NarrateTimeout(),
		Summarizer: logReasoning,
		// Parent ctx so ctrl+c propagates to in-flight narration HTTP calls so shutdown doesn't
		// wait on narration that the operator doesn't care about anymore
		Parent: ctx,
	}, log)
	log.AttachNarrator(narrator)
	defer func() {
		log.AttachNarrator(nil)
		narrator.Close()
	}()
	fields := map[string]any{}
	if narrator == nil {
		fields["enabled"] = false
		fields["reason"] = "disabled by config"
	} else {
		fields["enabled"] = true
		fields["interval"] = cfg.NarrateInterval.String()
		fields["timeout"] = cfg.NarrateTimeout().String()
		fields["pool_size"] = logPool.Size()
	}
	log.Log("server", "narrator", fields)

	// force-fires a narrator summary so the operator gets a fresh sentence at every phase boundary
	phaseTransition := func(from, to string) {
		currentPhase = to
		narrator.SetActiveAgents(computeActiveAgents())
		log.Log("controller", "transition phase "+from+" to "+to, nil)
		narrator.TriggerNow()
	}

	// fires one worker's iter run as a goroutine; the returned func blocks for the result
	fire := func(fctx context.Context, w *WorkerState) func() []agent.TurnSummary {
		resultCh := make(chan []agent.TurnSummary, 1)
		go func() {
			resultCh <- runOneWorker(fctx, w, candidates, log)
		}()
		return func() []agent.TurnSummary { return <-resultCh }
	}

	// provisions a forked child; chronicle inheritance happens in direct.go
	spawnChild := func(sctx context.Context, id int, instruction string) (*WorkerState, error) {
		var alive int
		for _, w := range workers {
			if w.Alive {
				alive++
			}
		}
		nw, err := spawn(sctx, id, alive+1, instruction)
		if err != nil {
			return nil, err
		}
		workers = append(workers, nw)
		return nw, nil
	}

	retire := func(w *WorkerState, reason string, iter int) {
		retireQueue.Submit(w, reason, iter)
	}

	// drains completed retire results into dirChat + completed; idempotent
	applyRetiredSummaries := func() {
		for _, r := range retireQueue.DrainCompleted() {
			if r.Summary != "" {
				dirChat.ReplaceWorkerWithSummary(r.WorkerID, r.Summary, r.Iter)
			}
			completed = append(completed, CompletedWorker{
				ID: r.WorkerID, StoppedAt: r.Iter, Reason: r.Reason, Summary: r.Summary,
			})
			if r.Summary != "" {
				log.Log("retire", "summary-applied", map[string]any{
					"worker_id": r.WorkerID, "iter": r.Iter, "summary_chars": len(r.Summary),
				})
			} else {
				log.Log("retire", "empty summary — keeping raw worker activity in dirChat", map[string]any{
					"worker_id": r.WorkerID, "iter": r.Iter,
				})
			}
		}
	}

	w1.Chronicle.Install(w1.Agent, w1.LastInstruction)
	inflight := map[int]func() []agent.TurnSummary{}
	inflight[1] = fire(sd.WorkersCtx, w1)

	var iteration int
	for iteration = 1; iteration <= cfg.MaxIterations; iteration++ {
		guardIteration = iteration

		phaseTransition("idle", "autonomous")
		narrator.Tick()
		workerRuns := harvestInflight(inflight)
		inflight = map[int]func() []agent.TurnSummary{}

		// cancel-check AFTER harvest so prior-iter in-flight workers are reaped first
		if err := ctx.Err(); err != nil {
			log.Log("controller", "cancelled", map[string]any{"iter": iteration, "err": err.Error()})
			break
		}
		if sd.Phase() >= ShutdownPhaseVerifyOnly {
			log.Log("controller", "shutdown — exiting iteration loop", map[string]any{
				"iter": iteration, "phase": sd.Phase(),
			})
			break
		}

		alive := bulk.SliceFilter(func(w *WorkerState) bool { return w.Alive }, workers)
		if len(alive) == 0 {
			log.Log("controller", "no alive workers, stopping", map[string]any{"iter": iteration})
			break
		}

		log.Log("controller", "iteration start", map[string]any{
			"iter":          iteration,
			"alive_workers": len(alive),
		})

		candidatesBefore := candidates.Counter()
		angleAt, aliveAtStart := snapshotIterationStart(alive)

		UpdateStallStreaks(alive)
		extractWorkerChroniclesAtIterEnd(alive, iteration, log)

		enforceStallStopsAsync(workers, cfg.StallStopAfter, retire, iteration, log)

		// dead-iteration short-circuit: skip verify/direction, refire alive workers
		if isDeadIteration(workerRuns, candidatesBefore, candidates.Counter()) {
			log.Log("controller", "dead-iteration", map[string]any{"iter": iteration})
			appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
			refireAlive(sd.WorkersCtx, workers, fire, inflight, log)
			narrator.TriggerNow()
			continue
		}

		decisions.Reset()

		verifierOverflowed = false
		verifierDirective := BuildVerifierPrompt(
			workers, workerRuns, candidates.Pending(),
			writer.SummaryForOrchestrator(), factory.ReconSummary,
			iteration, cfg.MaxIterations, writer.RunCount,
		)
		verifier.ReplaceHistory([]agent.Message{{Role: "user", Content: verifierDirective}})
		log.Log("compose", "installed", map[string]any{"role": "verifier", "iter": iteration})
		phaseTransition("autonomous", "verification")
		verificationSummary := RunVerificationPhase(
			sd.VerifierCtx, verifier, decisions, candidates, writer, dedupReviewer, log,
		)
		if verifierOverflowed && !decisions.HasVerificationDone && len(candidates.Pending()) > 0 {
			AutoDismissOnContextOverflow(candidates, decisions, log)
		}

		applyRetiredSummaries()

		phaseTransition("verification", "direction")
		stallWarnings := FormatStallWarnings(workers, cfg.StallWarnAfter)
		followUpHints := FormatFollowUpHints(decisions.Findings, decisions.Dismissals)
		iterStatus := statusLine(iteration, cfg.MaxIterations, writer.RunCount)

		if iteration == 1 && !cfg.SkipRecon {
			// iter-1 recon: retire w1, review, plan; fallback to single-worker
			// plan if synthesis didn't commit (avoids iter-2 alive-check kill).
			dirChat.AppendWorkerActivity(w1.ID, iteration, snapshotWorkerIterActivity(w1))
			retire(w1, "recon complete", iteration)
			if r, ok := retireQueue.WaitOne(ctx); ok {
				if r.Summary != "" {
					dirChat.ReplaceWorkerWithSummary(r.WorkerID, r.Summary, r.Iter)
					factory.ReconSummary = r.Summary
				} else {
					log.Log("recon", "empty summary — keeping raw worker activity in dirChat", map[string]any{
						"worker_id": r.WorkerID,
					})
				}
				completed = append(completed, CompletedWorker{
					ID: r.WorkerID, StoppedAt: r.Iter, Reason: r.Reason, Summary: r.Summary,
				})
				// summary_tokens_est: recurring per-call cost the recon
				// summary imposes on every subsequent system prompt
				log.Log("recon", "end", map[string]any{
					"worker_id":          r.WorkerID,
					"summary_chars":      len(r.Summary),
					"summary_tokens_est": agent.EstimateStringTokens(r.Summary),
				})
				// canonical summary is in factory.ReconSummary; release backing storage
				w1.Chronicle.Reset()
			}
			LatchStallWarnings(workers, cfg.StallWarnAfter)

			synthesisDirector.SetTools(nil)
			RunIter1ReconReviewCall(sd.WorkersCtx, synthesisDirector, dirChat, iterStatus, iteration, cfg.MaxWorkers, log)

			synthesisDirector.SetTools(append(slices.Clone(synthesisDirectorSectoolDefs),
				SynthesisToolDefs(decisions, guardStateFn, takenIDsFn, completedIDsFn, aliveWorkerIDsFn)...))
			RunIter1ReconPlanCall(sd.WorkersCtx, synthesisDirector, dirChat, decisions, iterStatus, cfg.MaxWorkers, log)

			if decisions.HasEndRun {
				log.Log("controller", "end_run", map[string]any{"summary": decisions.EndRunSummary})
				appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
				break
			}
			if !decisions.HasPlan {
				// synthesis failed to plan even after retry; inject a default so iter 2 has work
				fallback := []PlanEntry{{WorkerID: 2, Assignment: cfg.Prompt}}
				decisions.SetPlan(fallback)
				log.Log("recon", "synthesis produced no plan — injecting fallback worker 2", map[string]any{
					"hint":            "director did not call plan_workers after retry; iter 2 spawns one worker with the original mission",
					"fallback_worker": 2,
					"fallback_assign": util.Truncate(cfg.Prompt, 200),
					"recon_summary":   util.Truncate(factory.ReconSummary, 200),
				})
			}
			applyPlanAndFire(sd.WorkersCtx, decisions.Plan, &workers, spawn, cfg.MaxWorkers, fire, inflight, log)
			appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
			narrator.TriggerNow()
			continue
		}

		// directors get sectool tools so they can spot-check rather than hallucinate
		decisionDirector.SetTools(append(slices.Clone(decisionDirectorSectoolDefs),
			DecisionToolDefs(decisions, takenIDsFn, log)...))
		decRes := RunDecisionPhase(sd.WorkersCtx, DecisionPhaseInput{
			Director: decisionDirector, DirChat: dirChat, Decisions: decisions,
			Workers: workers, WorkerRuns: workerRuns,
			IterationStatus: iterStatus, Iter: iteration, MaxWorkers: cfg.MaxWorkers,
			TakenIDs:   takenIDsFn,
			Fire:       fire,
			SpawnChild: spawnChild,
			Retire:     retire,
		}, log)
		LatchStallWarnings(workers, cfg.StallWarnAfter)
		applyRetiredSummaries()

		synthesisDirector.SetTools(append(slices.Clone(synthesisDirectorSectoolDefs),
			SynthesisToolDefs(decisions, guardStateFn, takenIDsFn, completedIDsFn, aliveWorkerIDsFn)...))
		RunSynthesisPhase(sd.WorkersCtx, SynthesisPhaseInput{
			Director: synthesisDirector, DirChat: dirChat, Decisions: decisions,
			Workers: workers, Completed: completed,
			VerifierSummary: verificationSummary, FindingsSummary: writer.SummaryForOrchestrator(),
			StallWarnings: stallWarnings, FollowUpHints: followUpHints,
			IterationStatus: iterStatus, MaxWorkers: cfg.MaxWorkers,
		}, log)

		if decisions.HasEndRun {
			log.Log("controller", "end_run", map[string]any{"summary": decisions.EndRunSummary})
			appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
			break
		}

		// publish per-worker decision joins BEFORE plan apply so retargets
		// cancel/replace the in-flight run instead of double-Draining
		for id, j := range decRes.joins {
			inflight[id] = j
		}
		if decisions.HasPlan {
			applyPlanAndFire(sd.WorkersCtx, decisions.Plan, &workers, spawn, cfg.MaxWorkers, fire, inflight, log)
		}

		appendIterationHistory(workers, aliveAtStart, angleAt, workerRuns, decisions, candidates, candidatesBefore, iteration)
		narrator.TriggerNow()
	}

	// drain in-flight runs the loop fired but never harvested (end_run break)
	for _, j := range inflight {
		_ = j()
	}

	// graceful-shutdown finalization: stage 1 verify pending, stage 2 dump unvalidated
	if sd.Phase() >= ShutdownPhaseVerifyOnly {
		if sd.Phase() == ShutdownPhaseVerifyOnly && len(candidates.Pending()) > 0 {
			verifierOverflowed = false
			finalDirective := BuildVerifierPrompt(
				workers, map[int][]agent.TurnSummary{}, candidates.Pending(),
				writer.SummaryForOrchestrator(), factory.ReconSummary,
				iteration, cfg.MaxIterations, writer.RunCount,
			)
			verifier.ReplaceHistory([]agent.Message{{Role: "user", Content: finalDirective}})
			log.Log("shutdown", "final-verification start", map[string]any{
				"pending": len(candidates.Pending()),
			})
			RunVerificationPhase(
				sd.VerifierCtx, verifier, decisions, candidates, writer, dedupReviewer, log,
			)
			if verifierOverflowed && len(candidates.Pending()) > 0 {
				AutoDismissOnContextOverflow(candidates, decisions, log)
			}
		}
		if sd.Phase() >= ShutdownPhaseDumpUnvalidated {
			DumpUnvalidatedCandidates(candidates.Pending(), writer, log)
		}
	}

	retireQueue.Wait()
	applyRetiredSummaries()

	log.Log("summary", "run complete", map[string]any{
		"iterations":     iteration,
		"findings_count": writer.RunCount,
		"workers":        len(workers),
	})
	for _, p := range writer.Paths {
		log.Log("summary", "finding", map[string]any{"path": filepath.Clean(p)})
	}
	return nil
}

// isDeadIteration reports whether the autonomous phase produced no tool calls across any worker and no new candidates.
func isDeadIteration(workerRuns map[int][]agent.TurnSummary, candidatesBefore, candidatesAfter int) bool {
	if candidatesAfter != candidatesBefore {
		return false
	}
	for _, runs := range workerRuns {
		for _, r := range runs {
			if len(r.ToolCalls) > 0 {
				return false
			}
		}
	}
	return true
}

// applyPlanAndFire applies a plan_workers list (spawn fresh / retarget alive) and fires each
// affected worker's iter+1 run via fire, recording the join in inflight.
// Entries that exceed maxWorkers or collide with retired IDs are skipped with a log entry.
func applyPlanAndFire(ctx context.Context, plan []PlanEntry, workers *[]*WorkerState, spawn workerSpawnFunc,
	maxWorkers int, fire func(context.Context, *WorkerState) func() []agent.TurnSummary,
	inflight map[int]func() []agent.TurnSummary, log *Logger) {
	byID := map[int]*WorkerState{}
	var existing int
	planned := map[int]bool{}
	for _, w := range *workers {
		byID[w.ID] = w
		if w.Alive {
			existing++
		}
	}
	for _, p := range plan {
		if planned[p.WorkerID] {
			log.Log("plan", "duplicate entry skipped", map[string]any{"worker_id": p.WorkerID})
			continue
		}
		planned[p.WorkerID] = true
		if w, ok := byID[p.WorkerID]; ok && w.Alive {
			stopInflightWorkerRun(w, inflight, log)
			w.LastInstruction = p.Assignment
			if hasProductiveTurn(w.AutonomousTurns) {
				w.ProgressNoneStreak = 0
				w.StallWarned = false
			}
			log.Log("plan", "retarget", map[string]any{"worker_id": p.WorkerID})
			w.Chronicle.Install(w.Agent, w.LastInstruction)
			inflight[w.ID] = fire(ctx, w)
			continue
		}
		// retired worker (Alive=false), never shadow the dead entry
		if w, ok := byID[p.WorkerID]; ok && !w.Alive {
			log.Log("plan", "spawn skipped: id taken by retired worker", map[string]any{"worker_id": p.WorkerID})
			continue
		} else if existing >= maxWorkers {
			log.Log("plan", "spawn skipped: max_workers", map[string]any{"worker_id": p.WorkerID})
			continue
		}
		nw, err := spawn(ctx, p.WorkerID, existing+1, p.Assignment)
		if err != nil {
			log.Log("plan", "spawn failed", map[string]any{"worker_id": p.WorkerID, "err": err.Error()})
			continue
		}
		*workers = append(*workers, nw)
		byID[nw.ID] = nw
		existing++
		nw.Chronicle.Install(nw.Agent, nw.LastInstruction)
		inflight[nw.ID] = fire(ctx, nw)
		log.Log("plan", "spawn", map[string]any{"worker_id": p.WorkerID})
	}
}

func stopInflightWorkerRun(w *WorkerState, inflight map[int]func() []agent.TurnSummary, log *Logger) {
	if w == nil || inflight == nil {
		return
	}
	join, exists := inflight[w.ID]
	if !exists {
		return
	}
	if w.Agent != nil {
		w.Agent.Interrupt()
	}
	_ = join()
	delete(inflight, w.ID)
	log.Log("plan", "replaced in-flight run", map[string]any{"worker_id": w.ID})
}

// refireAlive fires an iter+1 run for every alive worker that doesn't already have a join in inflight.
func refireAlive(ctx context.Context, workers []*WorkerState,
	fire func(context.Context, *WorkerState) func() []agent.TurnSummary,
	inflight map[int]func() []agent.TurnSummary, log *Logger) {
	for _, w := range workers {
		if !w.Alive {
			continue
		} else if _, exists := inflight[w.ID]; exists {
			continue
		}
		w.Chronicle.Install(w.Agent, w.LastInstruction)
		inflight[w.ID] = fire(ctx, w)
		log.Log("refire", "alive worker", map[string]any{"worker_id": w.ID})
	}
}

// harvestInflight blocks on every join in inflight and returns the per-worker turn-summary map.
func harvestInflight(inflight map[int]func() []agent.TurnSummary) map[int][]agent.TurnSummary {
	out := map[int][]agent.TurnSummary{}
	for id, j := range inflight {
		out[id] = j()
	}
	return out
}

// probeReasoningHandlers returns reasoning handlers for cfg.Model and cfg.LogModel. The main probe goes through pool;
// the log probe through logPool so the two probes don't contend on a single shared slot.
func probeReasoningHandlers(ctx context.Context, cfg *config.Config,
	pool, logPool *agent.ClientPool, log *Logger) (mainR, logR agent.ReasoningHandler) {
	cache := agent.NewReasoningFormatCache()
	if cfg.LogModel == cfg.Model {
		f := resolveFormat(ctx, cache, pool, "main", cfg.BaseURL, cfg.Model, log)
		h := agent.NewReasoningHandler(f)
		return h, h
	}
	var mainFmt, logFmt agent.ReasoningFormat
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		mainFmt = resolveFormat(gctx, cache, pool, "main", cfg.BaseURL, cfg.Model, log)
		return nil
	})
	g.Go(func() error {
		logFmt = resolveFormat(gctx, cache, logPool, "log", cfg.BaseURL, cfg.LogModel, log)
		return nil
	})
	_ = g.Wait()
	return agent.NewReasoningHandler(mainFmt), agent.NewReasoningHandler(logFmt)
}

// snapshotIterationStart returns each alive worker's current LastInstruction
// (angleAt) and an alive-set keyed by worker ID.
func snapshotIterationStart(alive []*WorkerState) (angleAt map[int]string, aliveAtStart map[int]bool) {
	angleAt = map[int]string{}
	aliveAtStart = map[int]bool{}
	for _, w := range alive {
		angleAt[w.ID] = w.LastInstruction
		aliveAtStart[w.ID] = true
	}
	return
}

// extractWorkerChroniclesAtIterEnd appends each alive worker's iter
// content to its chronicle and runs in-place compaction.
func extractWorkerChroniclesAtIterEnd(alive []*WorkerState, iteration int, log *Logger) {
	for _, w := range alive {
		w.Chronicle.ExtractAndAppend(w.Agent, iteration)
		stripped, stubbed := w.Chronicle.Compact(iteration, history.ChronicleKeepRecentIters)
		log.Log("chronicle", "extract", map[string]any{
			"worker_id":      w.ID,
			"iter":           iteration,
			"chronicle_msgs": w.Chronicle.Len(),
			"think_stripped": stripped,
			"tool_stubbed":   stubbed,
		})
	}
}

// enforceStallStopsAsync calls retire for every alive worker whose ProgressNoneStreak has reached stopAfter.
func enforceStallStopsAsync(workers []*WorkerState, stopAfter int, retire func(*WorkerState, string, int), iter int, log *Logger) {
	for _, w := range workers {
		if w.Alive && w.ProgressNoneStreak >= stopAfter {
			log.Log("controller", "stall-force-stop", map[string]any{
				"worker_id": w.ID, "streak": w.ProgressNoneStreak,
			})
			retire(w, "stall-force-stop", iter)
		}
	}
}
