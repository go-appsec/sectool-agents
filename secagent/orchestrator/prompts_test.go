package orchestrator

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestFormatToolCalls(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		assert.Contains(t, formatToolCalls(nil, 0), "no tool calls")
	})

	t.Run("with_calls", func(t *testing.T) {
		out := formatToolCalls([]agent.ToolCallRecord{
			{Name: "a", InputSummary: `{"x":1}`, ResultSummary: "ok"},
			{Name: "b", InputSummary: "{}", IsError: true},
		}, 20)
		assert.Contains(t, out, "1. a")
		assert.Contains(t, out, "2. b")
		assert.Contains(t, out, "[ERROR]")
		assert.Contains(t, out, "→ ok")
	})

	t.Run("truncated_reports_remainder", func(t *testing.T) {
		many := make([]agent.ToolCallRecord, 30)
		for i := range many {
			many[i] = agent.ToolCallRecord{Name: "t"}
		}
		assert.Contains(t, formatToolCalls(many, 5), "and 25 more")
	})
}

func TestFormatAutonomousRun(t *testing.T) {
	t.Parallel()

	t.Run("empty_turns", func(t *testing.T) {
		out := formatAutonomousRun(1, nil, "silent")
		assert.Contains(t, out, "No autonomous turns")
		assert.Contains(t, out, "silent")
	})

	t.Run("renders_tools_and_flows", func(t *testing.T) {
		turns := []agent.TurnSummary{{
			AssistantText: "looking into it\nmore detail",
			ToolCalls:     []agent.ToolCallRecord{{Name: "flow_get"}, {Name: "replay_send"}},
			FlowIDs:       []string{"abc12345"},
		}}
		out := formatAutonomousRun(2, turns, "candidate")
		assert.Contains(t, out, "Worker 2")
		assert.Contains(t, out, "candidate")
		assert.Contains(t, out, "flow_get, replay_send")
		assert.Contains(t, out, "abc12345")
		assert.Contains(t, out, "looking into it")
	})
}

func TestFormatCompletedRoster(t *testing.T) {
	t.Parallel()

	build := func(n, startID int) []CompletedWorker {
		out := make([]CompletedWorker, n)
		for i := range out {
			out[i] = CompletedWorker{
				ID:        startID + i,
				StoppedAt: i + 1,
				Reason:    "done",
				Summary:   fmt.Sprintf("worker %d summary", startID+i),
			}
		}
		return out
	}

	t.Run("at_cap_renders_all_no_omission_line", func(t *testing.T) {
		out := formatCompletedRoster(build(completedWorkersRenderCap, 1))
		assert.NotContains(t, out, "omitted")
		for i := 1; i <= completedWorkersRenderCap; i++ {
			assert.Contains(t, out, fmt.Sprintf("Worker %d", i))
		}
	})

	t.Run("over_cap_truncates_with_omission_count", func(t *testing.T) {
		extra := 3
		out := formatCompletedRoster(build(completedWorkersRenderCap+extra, 1))
		assert.Contains(t, out, fmt.Sprintf("(%d earlier completed worker(s) omitted)", extra))
		// First `extra` entries dropped, last completedWorkersRenderCap kept.
		for i := 1; i <= extra; i++ {
			assert.NotContains(t, out, fmt.Sprintf("Worker %d ", i),
				"earliest workers must be truncated")
		}
		for i := extra + 1; i <= extra+completedWorkersRenderCap; i++ {
			assert.Containsf(t, out, fmt.Sprintf("Worker %d ", i),
				"recent worker %d must be rendered", i)
		}
	})
}

func TestFormatPendingCandidates(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "No pending finding candidates.", formatPendingCandidates(nil))
	})

	t.Run("renders_candidate_fields", func(t *testing.T) {
		out := formatPendingCandidates([]FindingCandidate{{
			CandidateID: "c1", Title: "xss", Severity: "high",
			Endpoint: "/x", WorkerID: 2, FlowIDs: []string{"abc12345"},
		}})
		assert.Contains(t, out, "c1")
		assert.Contains(t, out, "/x")
		assert.Contains(t, out, "abc12345")
	})
}
