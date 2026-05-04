package agent

import (
	"context"
)

const statusSummaryRequest = "Provide a single concise and clearly worded sentence summarizing what you are currently investigating and what you will try next."

// statusTokenBudget is the input-side token cap for the history window in a
// status-summary request; separate from the output cap passed as MaxTokens.
const statusTokenBudget = 2000

// toolResultPlaceholder replaces role=tool content in the summary prompt. The message is kept so
// assistant.tool_calls stay paired (strict servers reject orphaned tool_calls), but the bytes are
// dropped since they are almost always the bulk of the history and rarely useful for a one-sentence status.
const toolResultPlaceholder = "(tool result omitted for summary)"

// SummarizeStatus returns a one-sentence status summary for a, or "" when
// no usable line or think-tail fallback could be produced.
func (a *OpenAIAgent) SummarizeStatus(ctx context.Context, maxTokens int) (string, error) {
	line, tail, err := SummarizeStatusVia(ctx, a, nil, "", maxTokens)
	if err != nil {
		return "", err
	} else if line != "" {
		return line, nil
	}
	return tail, nil
}

// SummarizeStatusVia returns a one-sentence status summary for a using client (a.cfg.Pool when nil) and
// model (a.cfg.Model when ""). thinkTail holds a truncated-think-tail fallback when no confident line was produced.
func SummarizeStatusVia(ctx context.Context, a *OpenAIAgent, client ChatClient,
	model string, maxTokens int) (line, thinkTail string, err error) {
	if client == nil {
		client, err = a.cfg.Pool.Acquire(ctx)
		if err != nil {
			return "", "", err
		}
		defer a.cfg.Pool.Release(client)
	}
	return summarizeStatusVia(ctx, a, client, model, maxTokens)
}

func summarizeStatusVia(ctx context.Context, a *OpenAIAgent, client ChatClient,
	model string, maxTokens int) (line, thinkTail string, err error) {
	if maxTokens <= 0 {
		// Reasoning models use ~1-5k tokens before emitting content
		// too low of cap truncates mid-reasoning and produces empty output
		maxTokens = 20000
	}
	a.mu.Lock()
	before := a.history.Len()
	agentModel := a.cfg.Model
	a.mu.Unlock()
	if model == "" {
		model = agentModel
	}

	// Normalize to inline-think shape so the summary model sees a consistent
	// format regardless of the underlying agent's reasoning format.
	normalized := a.cfg.Reasoning.ForSummary(a.history.Snapshot())
	// Strip tool-error noise; skip the LLM call if nothing substantive remains
	filtered := FilterErrorMessages(normalized)
	if !HasSubstantiveMessages(filtered) {
		return "", "", nil
	}
	msgs := buildStatusMessages(filtered, statusTokenBudget, a.cfg.KeepThinkTurns)
	msgs = append(msgs, ChatMessage{Role: "user", Content: statusSummaryRequest})

	resp, err := client.CreateChatCompletion(ctx, ChatRequest{
		Model:           model,
		Messages:        msgs,
		MaxTokens:       maxTokens,
		ReasoningEffort: SummaryReasoningEffort,
	})
	if err != nil {
		return "", "", err
	}

	snap := a.history.Snapshot()
	if len(snap) > before {
		a.history.ReplaceAll(snap[:before])
	}

	// Tail is a fallback for fragments when no confident line was produced
	line = a.cfg.Reasoning.Extract(resp)
	if line == "" {
		thinkTail = a.cfg.Reasoning.Tail(resp)
	}
	return line, thinkTail, nil
}

// buildStatusMessages returns the chat-message slice for a status summary over hist, fit within budget tokens.
func buildStatusMessages(hist []Message, budget, keepThinkTurns int) []ChatMessage {
	if len(hist) == 0 {
		return nil
	}
	hist = FilterThinkBlocks(hist, keepThinkTurns)
	var anchor []Message
	var tailStart int
	if hist[0].Role == RoleSystem {
		anchor = append(anchor, hist[0])
		tailStart = 1
	}
	if tailStart < len(hist) && hist[tailStart].Role != RoleTool {
		anchor = append(anchor, hist[tailStart])
		tailStart++
	}

	filtered := make([]Message, 0, len(hist)-tailStart)
	for i := tailStart; i < len(hist); i++ {
		m := hist[i]
		if m.Role == RoleTool {
			m.Content = toolResultPlaceholder
		}
		filtered = append(filtered, m)
	}

	var anchorCost int
	for _, m := range anchor {
		anchorCost += EstimateMessageTokens(m)
	}
	remaining := budget - anchorCost
	if remaining < 0 {
		remaining = 0
	}
	tail := pickTail(filtered, remaining)

	out := make([]ChatMessage, 0, len(anchor)+len(tail))
	for _, m := range anchor {
		out = append(out, ChatMessage{
			Role: m.Role, Content: m.Content, ToolCalls: m.ToolCalls, ToolCallID: m.ToolCallID,
		})
	}
	for _, m := range tail {
		out = append(out, ChatMessage{
			Role: m.Role, Content: m.Content, ToolCalls: m.ToolCalls, ToolCallID: m.ToolCallID,
		})
	}
	return out
}

// pickTail returns the trailing slice of msgs whose estimated token sum fits within budget.
func pickTail(msgs []Message, budget int) []Message {
	if budget <= 0 || len(msgs) == 0 {
		return nil
	}
	var cost int
	start := len(msgs)
	for i := len(msgs) - 1; i >= 0; i-- {
		c := EstimateMessageTokens(msgs[i])
		if cost+c > budget && start < len(msgs) {
			break
		}
		cost += c
		start = i
	}
	for start < len(msgs) && msgs[start].Role == RoleTool {
		start++
	}
	return msgs[start:]
}
