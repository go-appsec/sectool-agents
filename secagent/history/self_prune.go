package history

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/util"
)

const (
	selfPruneMaxTokens = 8000
	selfPruneMinEvents = 6
)

const selfPruneSystemPrompt = `You are reviewing a security-testing agent's history of tool calls and helping it free context space without losing load-bearing evidence. Respond with JSON only — no prose, no markdown fences.`

// selfPruneRetryTemperature is the retry temp; slightly above default to encourage variance.
const selfPruneRetryTemperature float32 = 1.2

// ErrEmptyResponse signals an empty model response (drives one retry).
var ErrEmptyResponse = errors.New("empty response")

// SelfPruneCallback returns an OnSelfPruneCandidates callback; nil if s is unconfigured.
func SelfPruneCallback(s *Summarizer) func(ctx context.Context, snapshot []agent.Message) ([]string, error) {
	return func(ctx context.Context, snapshot []agent.Message) ([]string, error) {
		if s == nil || s.Pool == nil || s.Model == "" {
			return nil, nil
		}

		events := buildToolEvents(snapshot)
		if len(events) < selfPruneMinEvents {
			return nil, nil
		}
		listing := renderToolEventListing(events)
		selPrompt := buildSelfPruneSelectionPrompt(listing)

		selected, err := runSelfPruneSelection(ctx, s, selPrompt, len(events))
		if err != nil {
			return nil, err
		}
		if len(selected) == 0 {
			return nil, nil
		}

		ids := make([]string, 0, len(selected))
		for _, idx := range selected {
			if idx < 0 || idx >= len(events) {
				continue
			}
			if id := events[idx].ToolCallID; id != "" {
				ids = append(ids, id)
			}
		}
		s.Log.Log("compact", "self-prune apply", map[string]any{
			"events_total": len(events),
			"selected":     len(selected),
			"dropped":      len(ids),
		})
		return ids, nil
	}
}

// runSelfPruneSelection runs one selection call, retrying once on ErrEmptyResponse; returns nil/nil on a second blank.
func runSelfPruneSelection(ctx context.Context, s *Summarizer, prompt string, total int) ([]int, error) {
	selected, raw, err := selfPruneRunOnce(ctx, s, prompt, total, nil)
	if err == nil {
		return selected, nil
	}
	if !errors.Is(err, ErrEmptyResponse) {
		s.logSelectError(err, raw)
		return nil, err
	}
	s.Log.Log("compact", "self-prune empty response, retrying", nil)
	retryTemp := selfPruneRetryTemperature
	selected, raw, err = selfPruneRunOnce(ctx, s, prompt, total, &retryTemp)
	if err == nil {
		return selected, nil
	}
	if errors.Is(err, ErrEmptyResponse) {
		s.Log.Log("compact", "self-prune empty after retry — treating as no selections", nil)
		return nil, nil
	}
	s.logSelectError(err, raw)
	return nil, err
}

// selfPruneRunOnce returns parsed indices, raw body, and the call/parse error.
func selfPruneRunOnce(ctx context.Context, s *Summarizer,
	prompt string, total int, temp *float32) ([]int, string, error) {
	raw, err := RunOneShot(ctx, s.Pool, s.Model, selfPruneSystemPrompt, prompt,
		selfPruneMaxTokens, agent.CompressionReasoningEffort, temp)
	if err != nil {
		s.Log.Log("compact", "self-prune select error", map[string]any{"err": err.Error()})
		return nil, raw, err
	}
	selected, parseErr := parseEventIndexList(raw, total)
	return selected, raw, parseErr
}

func (s *Summarizer) logSelectError(err error, raw string) {
	s.Log.Log("compact", "self-prune select parse error", map[string]any{
		"err": err.Error(), "raw": util.Truncate(raw, 240),
	})
}

type toolEvent struct {
	Index      int
	ToolCallID string
	ToolName   string
	ArgsPrev   string
	ResultPrev string
	IsError    bool
}

// buildToolEvents returns one toolEvent per tool_call paired with its result.
func buildToolEvents(msgs []agent.Message) []toolEvent {
	resultByID := map[string]agent.Message{}
	for _, m := range msgs {
		if m.Role == agent.RoleTool && m.ToolCallID != "" {
			resultByID[m.ToolCallID] = m
		}
	}
	var events []toolEvent
	for _, m := range msgs {
		if m.Role != agent.RoleAssistant || len(m.ToolCalls) == 0 {
			continue
		}

		for _, tc := range m.ToolCalls {
			ev := toolEvent{
				Index:      len(events),
				ToolCallID: tc.ID,
				ToolName:   tc.Function.Name,
				ArgsPrev:   util.Truncate(tc.Function.Arguments, 200),
			}
			if r, ok := resultByID[tc.ID]; ok {
				ev.ResultPrev = util.Truncate(r.Content, 200)
				ev.IsError = r.IsRepairError || strings.HasPrefix(r.Content, "ERROR:")
			}
			events = append(events, ev)
		}
	}
	return events
}

// renderToolEventListing returns events as a 1-based numbered list.
func renderToolEventListing(events []toolEvent) string {
	var b strings.Builder
	for _, ev := range events {
		_, _ = fmt.Fprintf(&b, "[#%d] %s(%s)", ev.Index+1, fallbackName(ev.ToolName), fallbackArgs(ev.ArgsPrev))
		if ev.IsError {
			b.WriteString(" → ERROR")
		}
		if ev.ResultPrev != "" {
			_, _ = fmt.Fprintf(&b, " → %s", ev.ResultPrev)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// buildSelfPruneSelectionPrompt returns the user message asking the model
// to pick removal-eligible event indices.
func buildSelfPruneSelectionPrompt(listing string) string {
	var b strings.Builder
	b.WriteString("Below is the ordered list of tool events the agent has executed so far. Each entry shows the tool name, a truncated argument preview, and a truncated result preview.\n\n")
	b.WriteString("Select ranges of tool events that are noise, or summary or state checking that is not necessary based off the context of future interactions on specific selections. Prefer contiguous early ranges over scattered single events. Keep events whose results were cited or built upon by later calls.\n\n")
	b.WriteString("## Tool events\n\n")
	b.WriteString(listing)
	b.WriteString(`
## Response

Return a single JSON object of the form:

  {"remove": [1, 2, 5, 6, 7]}

The "remove" array lists the 1-based event indices to drop from history. Empty array if nothing should be removed. JSON only — no prose.
`)
	return b.String()
}

// parseEventIndexList returns deduped sorted 0-based indices in [0, total).
func parseEventIndexList(raw string, total int) ([]int, error) {
	body := util.ExtractJSONObject(raw)
	if body == "" {
		return nil, ErrEmptyResponse
	}
	var v struct {
		Remove []int `json:"remove"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return nil, fmt.Errorf("parse index list: %w (raw: %q)", err, raw)
	}
	out := make([]int, 0, len(v.Remove))
	for _, idx := range v.Remove {
		zero := idx - 1
		if zero >= 0 && zero < total {
			out = append(out, zero)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
