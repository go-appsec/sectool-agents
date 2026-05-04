package history

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/util"
)

const distillMaxTokens = 4000

const distillSystemPrompt = `You compress one or more tool-call results from a security-testing agent's history into 1-3 sentences of plain prose. Capture status codes, key fields, observed behavior, and cross-call patterns — anything the agent might need to reference later. Drop boilerplate, byte-level minutiae, and anything already obvious from the tool name. Return prose only — no preamble, no markdown headings or fences.`

// TODO - tune distill batch sizing once OnCompact telemetry is available
const (
	distillMinBatchEvents = 3
	distillMaxBatchEvents = 6
	distillMinBatchBytes  = 2048
)

// DistillCallback returns an OnDistillResults callback; nil if s is unconfigured.
func DistillCallback(s *Summarizer) func(ctx context.Context, snapshot []agent.Message) ([]agent.Message, error) {
	return func(ctx context.Context, snapshot []agent.Message) ([]agent.Message, error) {
		if s == nil || s.Pool == nil || s.Model == "" {
			return nil, nil
		}
		batches := buildDistillBatches(snapshot)
		if len(batches) == 0 {
			return nil, nil
		}
		out := slices.Clone(snapshot)
		var distilledBatches, distilledMsgs int
		for batchIdx, b := range batches {
			prose, err := runDistillBatch(ctx, s, b)
			if err != nil {
				s.Log.Log("compact", "distill batch error", map[string]any{
					"batch_idx": batchIdx, "events": len(b.indices),
					"err": err.Error(),
				})
				continue // fail-open: leave this batch alone
			}
			if strings.TrimSpace(prose) == "" {
				continue
			}
			content := fmt.Sprintf("%s%d: %s)", agent.DistillPrefix, batchIdx+1, strings.TrimSpace(prose))
			for _, idx := range b.indices {
				out[idx].Content = content
				distilledMsgs++
			}
			distilledBatches++
		}
		if distilledBatches == 0 {
			return nil, nil
		}
		s.Log.Log("compact", "distill apply", map[string]any{
			"batches":  distilledBatches,
			"messages": distilledMsgs,
		})
		return out, nil
	}
}

// distillBatch is one summarization batch.
type distillBatch struct {
	indices []int
	calls   []distillCall
}

type distillCall struct {
	Name    string
	Args    string
	Content string
	IsError bool
}

// buildDistillBatches groups eligible old tool-result messages into batches.
func buildDistillBatches(snapshot []agent.Message) []distillBatch {
	const keepWindow = 8 // mirrors KeepTurns*2 trailing window
	cutoff := len(snapshot) - keepWindow
	if cutoff <= 1 {
		return nil
	}

	parentCall := make(map[string]agent.ToolCall)
	for _, m := range snapshot {
		if m.Role == agent.RoleAssistant {
			for _, tc := range m.ToolCalls {
				parentCall[tc.ID] = tc
			}
		}
	}

	var batches []distillBatch
	var current distillBatch
	flush := func() {
		var total int
		for _, c := range current.calls {
			total += len(c.Content)
		}
		if len(current.indices) >= distillMinBatchEvents && total >= distillMinBatchBytes {
			batches = append(batches, current)
		}
		current = distillBatch{}
	}
	for i := 0; i < cutoff; i++ {
		m := snapshot[i]
		if m.Role == "user" {
			// User messages can mark a directive boundary, don't merge across them
			flush()
			continue
		} else if m.Role != agent.RoleTool {
			continue
		} else if !isDistillEligible(m) {
			flush()
			continue
		}

		tc := parentCall[m.ToolCallID]
		current.indices = append(current.indices, i)
		current.calls = append(current.calls, distillCall{
			Name:    tc.Function.Name,
			Args:    util.Truncate(tc.Function.Arguments, 240),
			Content: m.Content,
			IsError: m.IsRepairError || strings.HasPrefix(m.Content, "ERROR:"),
		})
		if len(current.indices) >= distillMaxBatchEvents {
			flush()
		}
	}
	flush()
	return batches
}

func isDistillEligible(m agent.Message) bool {
	if m.Role != agent.RoleTool {
		return false
	} else if m.IsRepairError {
		return false
	} else if agent.IsCompactionStub(m.Content) {
		return false
	}
	return true
}

// runDistillBatch returns the prose summary for batch b.
func runDistillBatch(ctx context.Context, s *Summarizer, b distillBatch) (string, error) {
	prompt := buildDistillPrompt(b)
	raw, err := RunOneShot(ctx, s.Pool, s.Model, distillSystemPrompt, prompt,
		distillMaxTokens, agent.CompressionReasoningEffort, nil)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(agent.StripThinkBlocks(raw)), nil
}

func buildDistillPrompt(b distillBatch) string {
	var sb strings.Builder
	sb.WriteString("Summarize the following ")
	_, _ = fmt.Fprintf(&sb, "%d tool-call results", len(b.calls))
	sb.WriteString(" into 1-3 sentences of prose. Preserve status codes, key field values, observed behavior, and cross-call patterns; drop boilerplate. Plain prose only — no headings, no fences, no preamble.\n\n")
	for i, c := range b.calls {
		_, _ = fmt.Fprintf(&sb, "## Call %d: %s(%s)\n", i+1, fallbackName(c.Name), fallbackArgs(c.Args))
		if c.IsError {
			sb.WriteString("(error result)\n")
		}
		sb.WriteString(util.Truncate(c.Content, 4000))
		sb.WriteString("\n\n")
	}
	return sb.String()
}
