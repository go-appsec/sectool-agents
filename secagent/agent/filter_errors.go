package agent

import (
	"slices"
	"strings"

	"github.com/go-analyze/bulk"
)

// FilterErrorMessages returns a copy of msgs with tool-error noise stripped:
// "ERROR:"-prefixed tool results and IsRepairError messages are dropped
// along with their matching ToolCall entries on preceding assistant
// messages, and assistants left empty are dropped too.
func FilterErrorMessages(msgs []Message) []Message {
	if len(msgs) == 0 {
		return msgs
	}
	dropIDs := make(map[string]bool)
	for _, m := range msgs {
		if isErrorToolResult(m) && m.ToolCallID != "" {
			dropIDs[m.ToolCallID] = true
		}
	}
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case RoleTool:
			if isErrorToolResult(m) {
				continue
			}
			out = append(out, m)
		case RoleAssistant:
			if len(m.ToolCalls) == 0 {
				out = append(out, m)
				continue
			}
			kept := m
			kept.ToolCalls = filterToolCalls(m.ToolCalls, dropIDs)
			if len(kept.ToolCalls) == 0 && strings.TrimSpace(kept.Content) == "" {
				continue
			}
			out = append(out, kept)
		default:
			out = append(out, m)
		}
	}
	return out
}

// HasSubstantiveMessages reports whether msgs contains anything worth summarizing.
// An assistant message with text or tool_calls, or any tool-result message.
func HasSubstantiveMessages(msgs []Message) bool {
	return slices.ContainsFunc(msgs, func(m Message) bool {
		switch m.Role {
		case RoleAssistant:
			if strings.TrimSpace(m.Content) != "" || len(m.ToolCalls) > 0 {
				return true
			}
		case RoleTool:
			return true
		}
		return false
	})
}

func isErrorToolResult(m Message) bool {
	if m.Role != RoleTool {
		return false
	} else if m.IsRepairError {
		return true
	}
	return strings.HasPrefix(m.Content, "ERROR:")
}

func filterToolCalls(tcs []ToolCall, drop map[string]bool) []ToolCall {
	return bulk.SliceFilter(func(tc ToolCall) bool { return !drop[tc.ID] }, tcs)
}

// collapseSameToolErrorStreaks drops earlier tool-error messages whose next tool-result is also
// an error from the same tool name. Strips matching ToolCall entries from preceding assistants
// and drops assistants left empty. Returns the modified slice and the count of error messages dropped.
func collapseSameToolErrorStreaks(msgs []Message) ([]Message, int) {
	drop := make(map[string]bool)
	for i, m := range msgs {
		if !isErrorToolResult(m) || m.ToolCallID == "" {
			continue
		}
		for j := i + 1; j < len(msgs); j++ {
			if msgs[j].Role != RoleTool {
				continue
			}
			if isErrorToolResult(msgs[j]) && msgs[j].ToolName == m.ToolName {
				drop[m.ToolCallID] = true
			}
			break
		}
	}
	if len(drop) == 0 {
		return msgs, 0
	}
	out := make([]Message, 0, len(msgs))
	var dropped int
	for _, m := range msgs {
		switch m.Role {
		case RoleTool:
			if drop[m.ToolCallID] {
				dropped++
				continue
			}
			out = append(out, m)
		case RoleAssistant:
			if len(m.ToolCalls) == 0 {
				out = append(out, m)
				continue
			}
			kept := m
			kept.ToolCalls = filterToolCalls(m.ToolCalls, drop)
			if len(kept.ToolCalls) == 0 && strings.TrimSpace(kept.Content) == "" {
				continue
			}
			out = append(out, kept)
		default:
			out = append(out, m)
		}
	}
	return out, dropped
}
