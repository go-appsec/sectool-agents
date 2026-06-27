package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-appsec/secagent/util"
)

// OpenAIAgentConfig configures a single agent instance.
type OpenAIAgentConfig struct {
	Model             string
	SystemPrompt      string
	Pool              *ClientPool
	MaxContext        int
	TurnTimeout       time.Duration
	PerToolTimeout    time.Duration // per-tool-call timeout; 0 disables.
	MaxParallelTools  int           // bound on concurrent tool dispatch; <=1 runs serial.
	DrainRetryMax     int
	DrainRetryBackoff time.Duration
	MaxTurnsPerAgent  int // hard cap on tool-dispatch rounds per Drain
	// KeepThinkTurns is the count of recent assistant messages that retain
	// <think> blocks on replay. 0 strips all. Inline handler only.
	KeepThinkTurns int
	// Reasoning is the format-specific reasoning handler. Nil defaults to
	// the inline handler.
	Reasoning ReasoningHandler
	// OnHardTruncate fires once after sendWithRetry hard-truncates to
	// recover from a context-overflow rejection (optional).
	OnHardTruncate func(CompactionReport)
	// OnContextOverflow fires once per sendWithRetry call when the model
	// rejected the request as over-context (optional).
	OnContextOverflow func()
	// OnToolStart fires before a tool handler runs (optional).
	OnToolStart func(name string, args json.RawMessage)
	// OnToolEnd fires after a tool handler returns (optional). timedOut is true when PerToolTimeout fired.
	// errText is truncated result text when isError is true, else empty.
	OnToolEnd func(name string, args json.RawMessage, elapsed time.Duration, isError, timedOut bool, errText string)
	// OnMalformedCall is called when tool arg repair fails (optional).
	OnMalformedCall func(name string, err error)
	// OnFuzzyToolMatch fires when a tool-name lookup miss was recovered via fuzzy fallback.
	// received is the model-emitted name; resolved is the registered name that ran.
	OnFuzzyToolMatch func(received, resolved string)
	// OnRequestStart fires before each chat-completion HTTP call (optional).
	OnRequestStart func(attempt int)
	// OnRequestEnd fires after each chat-completion HTTP call (optional).
	OnRequestEnd func(attempt int, elapsed time.Duration, tokensIn, tokensOut int, err error)
	// FlowIDExtractor (optional) extracts flow IDs from inputs/results/text.
	FlowIDExtractor func(sources ...any) []string
	// Rand is the randomness source used by retry backoff jitter. nil uses the package default.
	Rand *rand.Rand
	// Compactor manages context compaction. Nil disables compaction.
	// Returning ErrRetireOnPressure short-circuits Drain so the controller can retire and summarize.
	Compactor Compactor
}

// OpenAIAgent implements Agent over an OpenAI-compatible endpoint.
type OpenAIAgent struct {
	cfg      OpenAIAgentConfig
	history  *History
	toolDefs []ToolDef
	tools    []ChatTool
	handlers map[string]ToolHandler
	// canonHandlers/canonNames provide fallback lookup when a model emits a
	// near-miss tool name (e.g. `mcp_sectool__proxy_poll` instead of
	// `mcp__sectool__proxy_poll`). Keyed by canonicalToolName.
	canonHandlers map[string]ToolHandler
	canonNames    map[string]string
	mu            sync.Mutex
	cancelCtx     func()
}

// NewOpenAIAgent constructs an agent and seeds history with system prompt.
func NewOpenAIAgent(cfg OpenAIAgentConfig) *OpenAIAgent {
	if cfg.MaxContext <= 0 {
		cfg.MaxContext = 32768
	}
	if cfg.TurnTimeout == 0 {
		cfg.TurnTimeout = 300 * time.Second
	}
	if cfg.DrainRetryMax <= 0 {
		cfg.DrainRetryMax = 2
	}
	if cfg.DrainRetryBackoff == 0 {
		cfg.DrainRetryBackoff = 2 * time.Second
	}
	if cfg.MaxTurnsPerAgent <= 0 {
		cfg.MaxTurnsPerAgent = 100
	}
	if cfg.PerToolTimeout <= 0 {
		cfg.PerToolTimeout = 120 * time.Second
	}
	if cfg.MaxParallelTools <= 0 {
		cfg.MaxParallelTools = 4
	}
	if cfg.Reasoning == nil {
		cfg.Reasoning = NewReasoningHandler(ReasoningFormatInline)
	}
	a := &OpenAIAgent{
		cfg:      cfg,
		history:  NewHistory(cfg.MaxContext),
		handlers: map[string]ToolHandler{},
	}
	if cfg.SystemPrompt != "" {
		a.history.Append(Message{Role: "system", Content: cfg.SystemPrompt})
	}
	return a
}

// SetTools replaces the tool registry (active on next Drain).
func (a *OpenAIAgent) SetTools(defs []ToolDef) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.toolDefs = append(a.toolDefs[:0], defs...)
	a.tools = make([]ChatTool, 0, len(defs))
	a.handlers = make(map[string]ToolHandler, len(defs))
	a.canonHandlers = make(map[string]ToolHandler, len(defs))
	a.canonNames = make(map[string]string, len(defs))
	for _, d := range defs {
		a.tools = append(a.tools, ChatTool{
			Type: "function",
			Function: ChatToolSchema{
				Name:        d.Name,
				Description: d.Description,
				Parameters:  d.Schema,
			},
		})
		if d.Handler != nil {
			a.handlers[d.Name] = d.Handler
			c := canonicalToolName(d.Name)
			// First-write wins on canonical collisions: if two registered names canonicalize the same way,
			// only the first is reachable via fuzzy fallback. Exact lookups still distinguish them.
			if _, exists := a.canonHandlers[c]; !exists {
				a.canonHandlers[c] = d.Handler
				a.canonNames[c] = d.Name
			}
		}
	}
}

// Query appends a user message to history. Does not send.
func (a *OpenAIAgent) Query(content string) {
	a.history.Append(Message{Role: "user", Content: content})
}

// Interrupt cancels any in-flight Drain.
func (a *OpenAIAgent) Interrupt() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cancelCtx != nil {
		a.cancelCtx()
	}
}

// Close is a no-op for OpenAIAgent.
func (a *OpenAIAgent) Close() error { return nil }

// ContextUsage returns (tokens, max).
func (a *OpenAIAgent) ContextUsage() (int, int) {
	return a.history.EstimateTokens(), a.history.MaxContext()
}

// EffectiveContextUsage is like ContextUsage but reports the effective context ceiling.
func (a *OpenAIAgent) EffectiveContextUsage() (tokens, max int) {
	return a.history.EstimateTokens(), a.history.EffectiveMaxContext()
}

// History returns the agent's underlying history.
func (a *OpenAIAgent) History() *History { return a.history }

// Snapshot returns a shallow copy of the agent's message history.
func (a *OpenAIAgent) Snapshot() []Message { return a.history.Snapshot() }

// LastHistoryID returns the HistoryID of the last non-system message, or 0
// when only the system message (or nothing) is present.
func (a *OpenAIAgent) LastHistoryID() uint64 {
	snap := a.history.Snapshot()
	if len(snap) == 0 {
		return 0
	}
	last := snap[len(snap)-1]
	if last.Role == RoleSystem {
		return 0
	}
	return last.HistoryID
}

// SnapshotSinceID returns post-system messages whose HistoryID > id, normalized for summary use.
// Returns all post-system messages when id is 0 or has been compacted away.
func (a *OpenAIAgent) SnapshotSinceID(id uint64) []Message {
	snap := a.history.Snapshot()
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
	tail := snap[start:]
	return a.cfg.Reasoning.ForSummary(tail)
}

// ReplaceHistory replaces the agent's working memory with msgs. If msgs[0]
// is not a system message and the agent was constructed with a SystemPrompt,
// the system message is re-prepended. Cancels any in-flight Drain and resets
// iteration-boundary state. Tools and handlers are untouched.
func (a *OpenAIAgent) ReplaceHistory(msgs []Message) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancelCtx != nil {
		a.cancelCtx()
		a.cancelCtx = nil
	}
	if len(msgs) == 0 || msgs[0].Role != "system" {
		if sys := a.cfg.SystemPrompt; sys != "" {
			msgs = append([]Message{{Role: "system", Content: sys}}, msgs...)
		}
	}
	a.history.ReplaceAll(msgs)
	a.history.ResetIterationBoundary()
}

// MarkIterationBoundary records the current HistoryID watermark as the start of the active iter's content.
func (a *OpenAIAgent) MarkIterationBoundary() {
	a.history.MarkIterationBoundary()
}

// IterationBoundaryID returns the current iter watermark.
func (a *OpenAIAgent) IterationBoundaryID() uint64 {
	return a.history.IterationBoundaryID()
}

// SetOnSelfPruneApplied forwards a new post-apply hook to the wired Compactor. No-op when no compactor is set.
func (a *OpenAIAgent) SetOnSelfPruneApplied(f func(droppedIDs []string)) {
	a.mu.Lock()
	c := a.cfg.Compactor
	a.mu.Unlock()
	if c != nil {
		c.SetOnSelfPruneApplied(f)
	}
}

// Drain runs the dispatch loop and returns one TurnSummary.
func (a *OpenAIAgent) Drain(ctx context.Context) (TurnSummary, error) {
	return a.DrainBounded(ctx, a.cfg.MaxTurnsPerAgent)
}

// DrainBounded runs the dispatch loop, capping tool-dispatch rounds at
// maxRounds. A value <= 0 falls back to the configured MaxTurnsPerAgent.
func (a *OpenAIAgent) DrainBounded(ctx context.Context, maxRounds int) (TurnSummary, error) {
	if maxRounds <= 0 {
		maxRounds = a.cfg.MaxTurnsPerAgent
	}
	inner, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.cancelCtx = cancel
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.cancelCtx = nil
		a.mu.Unlock()
		cancel()
	}()

	summary := TurnSummary{}
	extractFlow := a.cfg.FlowIDExtractor

	for round := 0; ; round++ {
		if round >= maxRounds {
			// hard cap on runaway tool_calls loop, report silent to penalize it
			a.synthesizePendingToolStubs()
			summary.TimedOut = true
			summary.EscalationReason = escalationSilent
			return summary, nil
		}
		if c := a.cfg.Compactor; c != nil {
			if err := c.MaybeCompact(inner, a.history); err != nil {
				if errors.Is(err, ErrRetireOnPressure) {
					// RetireOnPressure agents (currently: recon worker) hit the high-watermark and
					// stop cleanly so the controller can retire and summarize the full chronicle.
					// This is a successful end-of-work signal, not a failure. Return nil error so
					// the autonomous loop treats it like any other turn boundary.
					summary.EscalationReason = escalationContextExhausted
					return summary, nil
				}
				summary.EscalationReason = escalationSilent
				return summary, err
			}
		}

		resp, err := a.sendWithRetry(inner)
		if errors.Is(err, context.DeadlineExceeded) {
			a.synthesizePendingToolStubs()
			summary.TimedOut = true
			summary.EscalationReason = escalationSilent
			return summary, nil
		} else if errors.Is(err, context.Canceled) {
			a.synthesizePendingToolStubs()
			return summary, ctx.Err()
		} else if err != nil {
			summary.EscalationReason = escalationError
			return summary, err
		}

		if resp.Usage.PromptTokens > 0 {
			a.history.SetPromptTokens(resp.Usage.PromptTokens)
			summary.TokensIn = resp.Usage.PromptTokens
		}
		summary.TokensOut += resp.Usage.CompletionTokens

		// reasoning handler decides storage shape (inline keeps <think> in
		// Content; structured splits via ReasoningContent). observability uses stripped Content
		storeContent, storeReasoning := a.cfg.Reasoning.Ingest(resp)
		stripped := StripThinkBlocks(storeContent)
		if len(resp.ToolCalls) == 0 {
			a.history.Append(Message{
				Role:             RoleAssistant,
				Content:          storeContent,
				ReasoningContent: storeReasoning,
			})
			summary.AssistantText += stripped
			if extractFlow != nil {
				for _, f := range extractFlow(stripped) {
					summary.FlowIDs = appendUnique(summary.FlowIDs, f)
				}
			}
			return summary, nil
		}

		a.history.Append(Message{
			Role:             RoleAssistant,
			Content:          storeContent,
			ReasoningContent: storeReasoning,
			ToolCalls:        resp.ToolCalls,
		})
		if stripped != "" {
			summary.AssistantText += stripped
		}
		if extractFlow != nil {
			for _, f := range extractFlow(stripped) {
				summary.FlowIDs = appendUnique(summary.FlowIDs, f)
			}
		}

		a.dispatchToolCalls(inner, resp.ToolCalls, &summary, extractFlow)
	}
}

// toolOutcome holds the result of a single tool dispatch so the collector
// loop can append history + summary in the original tool_calls order.
type toolOutcome struct {
	rec     ToolCallRecord
	histMsg Message
	flowIDs []string
}

// dispatchToolCalls runs handlers for calls and folds each outcome into history and summary in original order.
func (a *OpenAIAgent) dispatchToolCalls(
	inner context.Context,
	calls []ToolCall,
	summary *TurnSummary,
	extractFlow func(...any) []string,
) {
	outcomes := make([]toolOutcome, len(calls))

	// Phase 1: synchronous pre-flight (repair + flow-id extraction). Single-threaded so malformed
	// outcomes land in slot order regardless of handler scheduling.
	parsed := make([]json.RawMessage, len(calls))
	ok := make([]bool, len(calls))
	for i, tc := range calls {
		args, repairErr := RepairToolArgs(tc.Function.Arguments)
		if repairErr != nil {
			if a.cfg.OnMalformedCall != nil {
				a.cfg.OnMalformedCall(tc.Function.Name, repairErr)
			}
			rec := ToolCallRecord{Name: tc.Function.Name, IsError: true}
			rec.InputSummary = util.Truncate(tc.Function.Arguments, 240)
			errText := a.formatRepairError(tc.Function.Name, repairErr)
			rec.ResultSummary = util.Truncate(errText, 300)
			outcomes[i] = toolOutcome{
				rec: rec,
				histMsg: Message{
					Role:          RoleTool,
					Content:       errText,
					ToolCallID:    tc.ID,
					ToolName:      tc.Function.Name,
					Summary120:    Summarize120(errText),
					IsRepairError: true,
				},
			}
			continue
		}
		parsed[i] = args
		ok[i] = true
		if extractFlow != nil {
			var anyArgs any
			_ = json.Unmarshal(args, &anyArgs)
			outcomes[i].flowIDs = extractFlow(anyArgs)
		}
	}

	// Phase 2: concurrent handler execution, bounded
	concurrency := a.cfg.MaxParallelTools
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, tc := range calls {
		if !ok[i] {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tc ToolCall, args json.RawMessage) {
			defer wg.Done()
			defer func() { <-sem }()
			outcomes[i] = a.runSingleTool(inner, tc, args, outcomes[i].flowIDs, extractFlow)
		}(i, tc, parsed[i])
	}
	wg.Wait()

	// Phase 3: serial fold, append to history and summary in tool_calls order
	for _, o := range outcomes {
		summary.ToolCalls = append(summary.ToolCalls, o.rec)
		for _, f := range o.flowIDs {
			summary.FlowIDs = appendUnique(summary.FlowIDs, f)
		}
		a.history.Append(o.histMsg)
	}
}

// runSingleTool invokes one handler with the per-tool timeout and
// start/end callbacks, returning a self-contained outcome.
func (a *OpenAIAgent) runSingleTool(inner context.Context, tc ToolCall,
	args json.RawMessage, flowIDs []string, extractFlow func(...any) []string) toolOutcome {
	rec := ToolCallRecord{Name: tc.Function.Name, RawInput: args}
	rec.InputSummary = util.Truncate(string(args), 240)

	if a.cfg.OnToolStart != nil {
		a.cfg.OnToolStart(tc.Function.Name, args)
	}

	handler, known := a.handlers[tc.Function.Name]
	if !known {
		// Fuzzy-fallback: lower + collapse runs of '_' so the most common model typos still route to the real handler.
		// We do NOT rewrite tc.Function.Name in history: the assistant message records what the model emitted.
		// TODO - is this correct or will this result in agents being more likely to repeat failures
		c := canonicalToolName(tc.Function.Name)
		if h, ok := a.canonHandlers[c]; ok {
			handler = h
			known = true
			if a.cfg.OnFuzzyToolMatch != nil {
				a.cfg.OnFuzzyToolMatch(tc.Function.Name, a.canonNames[c])
			}
		} else if matched := fuzzyContainsToolMatch(c, a.canonNames); matched != "" {
			// Word-bounded contains-match resolves prefix-overgeneralization . Only fires when exactly one
			// registered name is a unique word-bounded substring; ambiguous cases fall through to "unknown tool".
			handler = a.canonHandlers[matched]
			known = true
			if a.cfg.OnFuzzyToolMatch != nil {
				a.cfg.OnFuzzyToolMatch(tc.Function.Name, a.canonNames[matched])
			}
		}
	}
	var result ToolResult
	var timedOut bool
	start := time.Now()
	if !known {
		result = ToolResult{
			Text:    fmt.Sprintf("ERROR: unknown tool %q", tc.Function.Name),
			IsError: true,
		}
	} else {
		tctx, cancel := context.WithTimeout(inner, a.cfg.PerToolTimeout)
		result = handler(tctx, args)
		cancel()
		if errors.Is(tctx.Err(), context.DeadlineExceeded) && inner.Err() == nil {
			// Tool exceeded its own budget; rewrite result so the model sees a
			// structured error rather than whatever partial output it produced.
			timedOut = true
			result = ToolResult{
				Text: fmt.Sprintf(
					"ERROR: tool %q timed out after %s",
					tc.Function.Name, a.cfg.PerToolTimeout,
				),
				IsError: true,
			}
		}
	}
	elapsed := time.Since(start)

	rec.IsError = result.IsError
	rec.ResultSummary = util.Truncate(result.Text, 300)
	if a.cfg.OnToolEnd != nil {
		var errText string
		if result.IsError {
			errText = util.Truncate(result.Text, 240)
		}
		a.cfg.OnToolEnd(tc.Function.Name, args, elapsed, result.IsError, timedOut, errText)
	}
	if extractFlow != nil {
		flowIDs = append(flowIDs, extractFlow(result.Text)...)
	}
	content := result.Text
	if result.IsError && !strings.HasPrefix(result.Text, "ERROR:") {
		content = "ERROR: " + result.Text
	}
	return toolOutcome{
		rec: rec,
		histMsg: Message{
			Role:       RoleTool,
			Content:    content,
			ToolCallID: tc.ID,
			ToolName:   tc.Function.Name,
			Summary120: Summarize120(result.Text),
		},
		flowIDs: flowIDs,
	}
}

// maxRepairSchemaBytes caps the tool schema embedded in repair errors.
const maxRepairSchemaBytes = 500

// formatRepairError renders the error sent to the model when its tool_call
// arguments fail to parse. The tool schema is embedded when known.
func (a *OpenAIAgent) formatRepairError(toolName string, repairErr error) string {
	a.mu.Lock()
	var schemaJSON []byte
	for _, d := range a.toolDefs {
		if d.Name == toolName && d.Schema != nil {
			schemaJSON, _ = json.Marshal(d.Schema)
			break
		}
	}
	a.mu.Unlock()
	if len(schemaJSON) == 0 {
		return fmt.Sprintf(
			"ERROR: your arguments did not parse: %s. Call again with valid JSON matching the schema.",
			repairErr.Error(),
		)
	}
	if len(schemaJSON) > maxRepairSchemaBytes {
		schemaJSON = append(schemaJSON[:maxRepairSchemaBytes], []byte("…")...)
	}
	return fmt.Sprintf(
		"ERROR: your arguments did not parse: %s. Call again with valid JSON matching %s.",
		repairErr.Error(), string(schemaJSON),
	)
}

// sendWithRetry dispatches one chat-completion request and applies the retry policy from Classify and BackoffFor.
func (a *OpenAIAgent) sendWithRetry(ctx context.Context) (ChatResponse, error) {
	a.mu.Lock()
	tools := a.tools
	a.mu.Unlock()

	msgs := a.buildChatMessages()
	var hardTruncated bool
	var retries int

	for attempt := 0; ; attempt++ {
		resp, err := a.dispatchChatRequest(ctx, attempt, msgs, tools)
		if err == nil {
			return resp, nil
		}
		cat, retryAfter := Classify(err)
		switch cat {
		case ErrDeadline, ErrOther, ErrModelError:
			return ChatResponse{}, err

		case ErrContextOverflow:
			// once-per-call fast-path: shrink ceiling, force-truncate, retry without debiting the retry budget
			if hardTruncated {
				return ChatResponse{}, err
			}
			hardTruncated = true
			a.history.ShrinkEffectiveMaxOnRejection(a.history.EstimateTokens())
			if a.cfg.OnContextOverflow != nil {
				a.cfg.OnContextOverflow()
			}
			target := a.history.EffectiveMaxContext() / 2
			report := ForceHardTruncate(a.history, target, 2)
			if a.cfg.OnHardTruncate != nil {
				a.cfg.OnHardTruncate(report)
			}
			if report.DroppedTurns == 0 {
				return ChatResponse{}, err
			}
			msgs = a.buildChatMessages()
			continue

		case ErrRateLimit, ErrTransientNet:
			if retries >= a.cfg.DrainRetryMax {
				return ChatResponse{}, err
			}
			wait := BackoffFor(cat, retries, retryAfter, a.cfg.DrainRetryBackoff, a.cfg.Rand)
			if err := sleepCtx(ctx, wait); err != nil {
				return ChatResponse{}, err
			}
			retries++
			continue
		}
	}
}

// sleepCtx sleeps for d, returning ctx.Err() if ctx cancels first. d <= 0 is a no-op.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// dispatchChatRequest sends one chat completion using a pooled client.
func (a *OpenAIAgent) dispatchChatRequest(ctx context.Context, attempt int,
	msgs []ChatMessage, tools []ChatTool) (ChatResponse, error) {
	client, err := a.cfg.Pool.Acquire(ctx)
	if err != nil {
		return ChatResponse{}, err
	}
	defer a.cfg.Pool.Release(client)

	callCtx, cancel := context.WithTimeout(ctx, a.cfg.TurnTimeout)
	defer cancel()

	if a.cfg.OnRequestStart != nil {
		a.cfg.OnRequestStart(attempt)
	}
	start := time.Now()
	resp, err := client.CreateChatCompletion(callCtx, ChatRequest{
		Model:    a.cfg.Model,
		Messages: msgs,
		Tools:    tools,
	})
	if a.cfg.OnRequestEnd != nil {
		a.cfg.OnRequestEnd(attempt, time.Since(start), resp.Usage.PromptTokens, resp.Usage.CompletionTokens, err)
	}
	return resp, err
}

// buildChatMessages returns the next request's chat messages.
func (a *OpenAIAgent) buildChatMessages() []ChatMessage {
	snap := a.cfg.Reasoning.Replay(a.history.Snapshot(), a.cfg.KeepThinkTurns)
	out := make([]ChatMessage, 0, len(snap))
	for _, m := range snap {
		out = append(out, ChatMessage{
			Role:             m.Role,
			Content:          m.Content,
			ReasoningContent: m.ReasoningContent,
			ToolCalls:        m.ToolCalls,
			ToolCallID:       m.ToolCallID,
		})
	}
	return out
}

// synthesizePendingToolStubs appends placeholder tool-result messages for
// any assistant.tool_calls missing a paired result at the tail of history.
func (a *OpenAIAgent) synthesizePendingToolStubs() {
	msgs := a.history.Snapshot()
	if len(msgs) == 0 {
		return
	}
	// Find the last assistant.tool_calls and count paired tool results
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role != RoleAssistant || len(msgs[i].ToolCalls) == 0 {
			continue
		}
		paired := map[string]bool{}
		for j := i + 1; j < len(msgs); j++ {
			if msgs[j].Role == RoleTool {
				paired[msgs[j].ToolCallID] = true
			}
		}
		var stubs int
		for _, tc := range msgs[i].ToolCalls {
			if !paired[tc.ID] {
				msgs = append(msgs, Message{
					Role:       RoleTool,
					Content:    "(interrupted before tool could run)",
					ToolCallID: tc.ID,
					ToolName:   tc.Function.Name,
					Summary120: "(interrupted before tool could run)",
				})
				stubs++
			}
		}
		if stubs > 0 {
			a.history.ReplaceAll(msgs)
		}
		return
	}
}

func appendUnique(slice []string, v string) []string {
	if v == "" || slices.Contains(slice, v) {
		return slice
	}
	return append(slice, v)
}
