package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyEscalation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		summary        TurnSummary
		candidateFound bool
		want           string
	}{
		{name: "timeout_silent", summary: TurnSummary{TimedOut: true}, want: escalationSilent},
		{name: "candidate_found", summary: TurnSummary{ToolCalls: []ToolCallRecord{{Name: "x"}}}, candidateFound: true, want: escalationCandidate},
		{name: "silent_no_activity", summary: TurnSummary{AssistantText: "done"}, want: escalationSilent},
		{name: "productive_with_tools", summary: TurnSummary{ToolCalls: []ToolCallRecord{{Name: "x"}}}},
		{name: "productive_with_flows", summary: TurnSummary{FlowIDs: []string{"abc123"}}},
		{name: "context_exhausted_preserved", summary: TurnSummary{EscalationReason: escalationContextExhausted, TimedOut: true}, want: escalationContextExhausted},
		{name: "timeout_beats_candidate", summary: TurnSummary{TimedOut: true}, candidateFound: true, want: escalationSilent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyEscalation(tc.summary, tc.candidateFound)
			assert.Equal(t, tc.want, got)
		})
	}
}
