package history

import (
	"strings"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/secagent/agent"
)

// PruneToolResults drops tool-results in dropSet, strips matching tool calls from preceding
// assistants, and removes assistants left empty.
// inScope decides per-index eligibility (nil = all eligible). keptIndices reports surviving
// original indices for parallel-array rebuild.
func PruneToolResults(msgs []agent.Message,
	dropSet map[string]struct{}, inScope func(int) bool) (kept []agent.Message, keptIndices []int, droppedToolResults int) {
	kept = make([]agent.Message, 0, len(msgs))
	keptIndices = make([]int, 0, len(msgs))
	for i, m := range msgs {
		if inScope != nil && !inScope(i) {
			kept = append(kept, m)
			keptIndices = append(keptIndices, i)
			continue
		}
		switch m.Role {
		case agent.RoleTool:
			if _, drop := dropSet[m.ToolCallID]; drop {
				droppedToolResults++
				continue
			}
			kept = append(kept, m)
			keptIndices = append(keptIndices, i)
		case agent.RoleAssistant:
			if len(m.ToolCalls) == 0 {
				kept = append(kept, m)
				keptIndices = append(keptIndices, i)
				continue
			}
			out := m
			out.ToolCalls = bulk.SliceFilter(func(tc agent.ToolCall) bool {
				_, drop := dropSet[tc.ID]
				return !drop
			}, m.ToolCalls)
			if len(out.ToolCalls) == 0 && strings.TrimSpace(out.Content) == "" {
				continue
			}
			kept = append(kept, out)
			keptIndices = append(keptIndices, i)
		default:
			kept = append(kept, m)
			keptIndices = append(keptIndices, i)
		}
	}
	return kept, keptIndices, droppedToolResults
}
