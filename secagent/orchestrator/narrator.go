package orchestrator

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/history"
)

// narratorSystemPrompt avoids word-count constraints; reasoning models echo them in output.
const narratorSystemPrompt = `You narrate autonomous security-testing agent activity to a human operator.
Provide a single concise and clearly worded sentence as a description of the activity shown here.`

// agentNarratorSystemPrompt drives per-agent narration. The user message
// carries any prior summaries for continuity plus a transcript window of
// the agent's tool calls and assistant messages since the last firing.
const agentNarratorSystemPrompt = `You narrate one specific autonomous security-testing agent's recent activity to a human operator.
The user message lists any prior summaries (for continuity, do NOT restate them) followed by a transcript of the agent's tool calls, results, and assistant messages since the last summary.
Produce a single concise and clearly worded sentence focused on what is happening now and what the agent is likely to do next.`

// agentSummaryHistoryCap is the max number of prior agent summaries re-sent for continuity.
const agentSummaryHistoryCap = 2

// narratorMinEvents is the minimum buffered events required to fire.
// Below the threshold the buffer is preserved so events combine with later activity on the next firing.
const narratorMinEvents = 4

// narratorTranscriptBudget caps the rendered transcript window sent to
// the per-agent narrator. Tail-truncated when exceeded.
const narratorTranscriptBudget = 4000

// narratorMaxTokens is kept high so reasoning models aren't truncated before emitting content.
const narratorMaxTokens = 20000

// NarratorConfig tunes when and how the Narrator fires.
type NarratorConfig struct {
	Interval   time.Duration // minimum time between fires; 0 disables.
	Model      string        // log model ID.
	Pool       *agent.ClientPool
	CallBudget time.Duration          // per-summary call timeout; 0 defaults to 5m.
	Summarizer agent.ReasoningHandler // nil defaults to the inline handler.
	// Parent context for in-flight summary calls; nil defaults to Background.
	Parent context.Context
}

// NamedAgent pairs an agent with its narration label.
type NamedAgent struct {
	Name  string
	Agent agent.Agent
}

// Narrator buffers events and periodically dispatches summaries to a model.
type Narrator struct {
	cfg NarratorConfig
	log *Logger

	mu           sync.Mutex
	buf          []narratorEvent
	lastFireAt   time.Time
	activeAgents []NamedAgent
	// lastSummaries holds up to agentSummaryHistoryCap prior per-agent summary lines, most recent first.
	lastSummaries map[string][]string
	// lastNarrationHistoryID is the per-agent cursor at the last message
	// included in a successful narration; 0 means none yet.
	lastNarrationHistoryID map[string]uint64

	wg sync.WaitGroup
	// armed gates firing until a substantive event arrives (sticky).
	armed bool

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	tickerStop chan struct{}
	closed     bool
}

type narratorEvent struct {
	ts     time.Time
	tag    string
	msg    string
	fields map[string]any
}

// NewNarrator returns a Narrator running a background ticker, or nil
// when cfg.Interval <= 0 / cfg.Pool nil / cfg.Model "".
func NewNarrator(cfg NarratorConfig, log *Logger) *Narrator {
	if cfg.Interval <= 0 || cfg.Pool == nil || cfg.Model == "" {
		return nil
	}
	if cfg.CallBudget <= 0 {
		cfg.CallBudget = 300 * time.Second
	}
	if cfg.Summarizer == nil {
		cfg.Summarizer = agent.NewReasoningHandler(agent.ReasoningFormatInline)
	}
	parent := cfg.Parent
	if parent == nil {
		parent = context.Background()
	}
	shutdownCtx, shutdownCancel := context.WithCancel(parent)
	n := &Narrator{
		cfg:                    cfg,
		log:                    log,
		shutdownCtx:            shutdownCtx,
		shutdownCancel:         shutdownCancel,
		tickerStop:             make(chan struct{}),
		lastSummaries:          map[string][]string{},
		lastNarrationHistoryID: map[string]uint64{},
	}
	n.wg.Add(1)
	go n.runTicker()
	return n
}

// runSummaryCall invokes fn with a pool-acquired ChatClient.
func (n *Narrator) runSummaryCall(ctx context.Context, fn func(agent.ChatClient) error) error {
	client, err := n.cfg.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer n.cfg.Pool.Release(client)
	return fn(client)
}

func (n *Narrator) runTicker() {
	defer n.wg.Done()
	t := time.NewTicker(n.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-n.tickerStop:
			return
		case <-t.C:
			n.Tick()
		}
	}
}

// isUsableNarration reports whether s looks like a natural-language sentence.
func isUsableNarration(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	return strings.ContainsAny(s, " \n")
}

// SetActiveAgents publishes the agents the next firing should summarize.
func (n *Narrator) SetActiveAgents(agents []NamedAgent) {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.activeAgents = append(n.activeAgents[:0], agents...)
	n.mu.Unlock()
}

// Record buffers one event. A substantive (tag, msg) also arms the
// narrator so future Ticks may fire.
func (n *Narrator) Record(tag, msg string, fields map[string]any) {
	if n == nil {
		return
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.buf = append(n.buf, narratorEvent{
		ts: time.Now(), tag: tag, msg: msg, fields: fields,
	})
	if !n.armed && isSubstantiveNarrationEvent(tag, msg) {
		n.armed = true
	}
	n.mu.Unlock()
}

// isSubstantiveNarrationEvent reports whether the (tag, msg) pair represents real agent activity worth narrating.
func isSubstantiveNarrationEvent(tag, msg string) bool {
	switch tag {
	case "worker":
		return msg == "turn"
	case "tool":
		return msg == toolMsgDone || msg == toolMsgSlow || msg == toolMsgTimeout
	case tagFinding:
		return msg == "written"
	case tagDecision:
		return true
	}
	return false
}

// Tick fires a summary when armed, the buffer has narratorMinEvents, and Interval has elapsed since the last fire.
func (n *Narrator) Tick() {
	if n == nil {
		return
	}
	n.mu.Lock()
	now := time.Now()
	shouldFire := n.armed && len(n.buf) >= narratorMinEvents && now.Sub(n.lastFireAt) >= n.cfg.Interval
	n.mu.Unlock()
	if shouldFire {
		n.fireAsync()
	}
}

// TriggerNow forces a firing regardless of cadence. No-op when not yet
// armed or when fewer than narratorMinEvents are buffered.
func (n *Narrator) TriggerNow() {
	if n == nil {
		return
	}
	n.mu.Lock()
	skip := !n.armed || len(n.buf) < narratorMinEvents
	n.mu.Unlock()
	if skip {
		return
	}
	n.fireAsync()
}

// fireAsync spawns a firing goroutine. Concurrent callers either win the n.mu-guarded buffer snapshot (and proceed)
// or see an empty buffer (and return); the log pool is the only cap on concurrent in-flight calls.
func (n *Narrator) fireAsync() {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.mu.Lock()
		if len(n.buf) == 0 {
			n.mu.Unlock()
			return
		}
		snapshot := n.buf
		n.buf = nil
		n.lastFireAt = time.Now()
		n.mu.Unlock()

		n.runSummary(snapshot)
	}()
}

// runSummary concurrently dispatches one orchestrator-level summary and one per-active-agent summary
// under a shared timeout. Pool capacity gates real concurrency; surplus calls queue at Acquire.
func (n *Narrator) runSummary(events []narratorEvent) {
	// shutdownCtx parent so Close aborts in-flight HTTP calls
	ctx, cancel := context.WithTimeout(n.shutdownCtx, n.cfg.CallBudget)
	defer cancel()

	if ctx.Err() != nil {
		return
	}

	n.mu.Lock()
	agents := slices.Clone(n.activeAgents)
	n.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n.runOrchestratorSummary(ctx, events)
	}()
	for _, na := range agents {
		if na.Agent == nil || na.Name == "" {
			continue
		}
		wg.Add(1)
		go func(na NamedAgent) {
			defer wg.Done()
			n.runAgentSummary(ctx, na)
		}(na)
	}
	wg.Wait()
}

func (n *Narrator) runOrchestratorSummary(ctx context.Context, events []narratorEvent) {
	body := buildNarratorPrompt(events)
	var resp agent.ChatResponse
	err := n.runSummaryCall(ctx, func(client agent.ChatClient) error {
		var e error
		resp, e = client.CreateChatCompletion(ctx, agent.ChatRequest{
			Model: n.cfg.Model,
			Messages: []agent.ChatMessage{
				{Role: "system", Content: narratorSystemPrompt},
				{Role: "user", Content: body},
			},
			MaxTokens:       narratorMaxTokens,
			ReasoningEffort: agent.SummaryReasoningEffort,
		})
		return e
	})
	if err != nil {
		n.log.Log("narrate", "orchestrator: error", map[string]any{
			"err": err.Error(),
		})
		return
	}
	if line := n.cfg.Summarizer.Extract(resp); isUsableNarration(line) {
		n.log.Log("narrate", "orchestrator: "+line, map[string]any{
			"events": len(events),
		})
		return
	}
	if tail := n.cfg.Summarizer.Tail(resp); tail != "" {
		n.log.Log("narrate", "orchestrator: …thinking: "+tail, map[string]any{
			"events":          len(events),
			"truncated_think": true,
		})
		return
	}
	n.log.Log("narrate", "orchestrator: empty", map[string]any{
		"events":     len(events),
		"tokens_out": resp.Usage.CompletionTokens,
	})
}

// runAgentSummary dispatches one per-agent narration call and advances the per-agent cursor on success.
func (n *Narrator) runAgentSummary(ctx context.Context, na NamedAgent) {
	n.mu.Lock()
	since := n.lastNarrationHistoryID[na.Name]
	prev := slices.Clone(n.lastSummaries[na.Name])
	n.mu.Unlock()

	slice := na.Agent.SnapshotSinceID(since)
	filtered := agent.FilterErrorMessages(slice)
	if !agent.HasSubstantiveMessages(filtered) {
		return
	}
	tailID := slice[len(slice)-1].HistoryID

	transcript, truncated := renderAgentTranscript(filtered, narratorTranscriptBudget)
	body := buildAgentNarrationPrompt(prev, transcript, truncated)

	var resp agent.ChatResponse
	err := n.runSummaryCall(ctx, func(client agent.ChatClient) error {
		var e error
		resp, e = client.CreateChatCompletion(ctx, agent.ChatRequest{
			Model: n.cfg.Model,
			Messages: []agent.ChatMessage{
				{Role: "system", Content: agentNarratorSystemPrompt},
				{Role: "user", Content: body},
			},
			MaxTokens:       narratorMaxTokens,
			ReasoningEffort: agent.SummaryReasoningEffort,
		})
		return e
	})

	tokens, max := na.Agent.EffectiveContextUsage()
	ctxField := map[string]any{
		"context_usage":   formatContextPercent(tokens, max),
		"context_tokens":  tokens,
		"window_messages": len(filtered),
	}
	mergeFields := func(extra map[string]any) map[string]any {
		out := make(map[string]any, len(ctxField)+len(extra))
		for k, v := range ctxField {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	prefix := na.Name + ": "
	if err != nil {
		n.log.Log("narrate", prefix+"error", mergeFields(map[string]any{"err": err.Error()}))
		return
	}
	if line := n.cfg.Summarizer.Extract(resp); isUsableNarration(line) {
		n.recordAgentSummary(na.Name, line)
		n.advanceNarrationCursor(na.Name, tailID)
		n.log.Log("narrate", prefix+line, mergeFields(nil))
		return
	}
	if tail := n.cfg.Summarizer.Tail(resp); tail != "" {
		n.log.Log("narrate", prefix+"…thinking: "+tail, mergeFields(map[string]any{"truncated_think": true}))
		return
	}
	n.log.Log("narrate", prefix+"empty", mergeFields(map[string]any{
		"tokens_out": resp.Usage.CompletionTokens,
	}))
}

// advanceNarrationCursor records id as the last-narrated HistoryID for name.
func (n *Narrator) advanceNarrationCursor(name string, id uint64) {
	if id == 0 {
		return
	}
	n.mu.Lock()
	n.lastNarrationHistoryID[name] = id
	n.mu.Unlock()
}

// recordAgentSummary prepends line to the agent's prior-summary ring, capped at agentSummaryHistoryCap.
func (n *Narrator) recordAgentSummary(name, line string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	prior := n.lastSummaries[name]
	next := make([]string, 0, agentSummaryHistoryCap)
	next = append(next, line)
	for i := 0; i < len(prior) && len(next) < agentSummaryHistoryCap; i++ {
		next = append(next, prior[i])
	}
	n.lastSummaries[name] = next
}

// buildAgentNarrationPrompt returns the user message for a per-agent narration call.
func buildAgentNarrationPrompt(prevSummaries []string, transcript string, truncated bool) string {
	var b strings.Builder
	if len(prevSummaries) > 0 {
		b.WriteString("Prior summaries (most recent first; do not restate verbatim):\n")
		for i, s := range prevSummaries {
			_, _ = fmt.Fprintf(&b, "%d. %s\n", i+1, s)
		}
		b.WriteByte('\n')
	}
	b.WriteString("Activity since the last summary:\n")
	if truncated {
		b.WriteString("(earlier activity omitted)\n")
	}
	b.WriteString(transcript)
	return b.String()
}

// renderAgentTranscript returns msgs rendered as a transcript fitting
// budget tokens, and whether older messages were dropped to fit.
func renderAgentTranscript(msgs []agent.Message, budget int) (rendered string, truncated bool) {
	rendered = history.RenderSnapshotForSummary(msgs)
	if agent.EstimateStringTokens(rendered) <= budget {
		return rendered, false
	}
	for start := 1; start < len(msgs); start++ {
		candidate := history.RenderSnapshotForSummary(msgs[start:])
		if agent.EstimateStringTokens(candidate) <= budget {
			return candidate, true
		}
	}
	if len(msgs) == 0 {
		return rendered, false
	}
	return history.RenderSnapshotForSummary(msgs[len(msgs)-1:]), true
}

// formatContextPercent returns tokens/max as "NN%", capped at 99%, or "?" when max is non-positive.
func formatContextPercent(tokens, max int) string {
	if max <= 0 {
		return "?"
	}
	pct := float64(tokens) * 100 / float64(max)
	if pct < 0 {
		pct = 0
	}
	rounded := int(pct + 0.5)
	// clamp at 99% so floating-point overshoot doesn't muddy the "hit wall" signal
	if rounded >= 100 {
		rounded = 99
	}
	return fmt.Sprintf("%d%%", rounded)
}

// Close stops the ticker, cancels in-flight summaries, and waits for pending firings to return.
func (n *Narrator) Close() {
	if n == nil {
		return
	}
	n.mu.Lock()
	alreadyClosed := n.closed
	n.closed = true
	n.mu.Unlock()
	if !alreadyClosed {
		close(n.tickerStop)
	}
	n.shutdownCancel()
	n.wg.Wait()
}

// buildNarratorPrompt returns the user message rendering events for the orchestrator narration call.
func buildNarratorPrompt(events []narratorEvent) string {
	var b strings.Builder
	b.WriteString("Events since last narration:\n")
	writeEventsBlock(&b, events)
	return b.String()
}

// writeEventsBlock writes one line per event into b with stable field order (role, worker_id, then alphabetic).
func writeEventsBlock(b *strings.Builder, events []narratorEvent) {
	for _, e := range events {
		b.WriteString(e.ts.Format("15:04:05"))
		b.WriteString(" [")
		b.WriteString(e.tag)
		b.WriteString("] ")
		b.WriteString(e.msg)
		if v, ok := e.fields["role"]; ok {
			_, _ = fmt.Fprintf(b, " role=%s", formatPrettyValue(v))
		}
		if v, ok := e.fields["worker_id"]; ok {
			_, _ = fmt.Fprintf(b, " worker_id=%s", formatPrettyValue(v))
		}
		keys := make([]string, 0, len(e.fields))
		for k := range e.fields {
			if k == "role" || k == "worker_id" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, _ = fmt.Fprintf(b, " %s=%s", k, formatPrettyValue(e.fields[k]))
		}
		b.WriteByte('\n')
	}
}
