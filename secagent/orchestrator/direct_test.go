package orchestrator

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/history"
)

// scriptedFireFn returns a Fire callback that records invocations and returns a join that yields the given turns.
// Allows tests to assert which workers had their iter+1 runs fired.
func scriptedFireFn(t *testing.T, turns map[int][]agent.TurnSummary) (FireWorkerFunc, func() []int) {
	t.Helper()

	var mu sync.Mutex
	var fired []int
	return func(_ context.Context, w *WorkerState) func() []agent.TurnSummary {
			mu.Lock()
			fired = append(fired, w.ID)
			mu.Unlock()
			result := turns[w.ID]
			return func() []agent.TurnSummary { return result }
		}, func() []int {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(fired)
		}
}

func TestRunDecisionPhase(t *testing.T) {
	t.Parallel()

	t.Run("one_call_per_worker", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{AssistantText: "decide w1"},
			{AssistantText: "decide w2"},
		}}
		var turn int
		director.OnDrain = func(_ int) {
			turn++
			switch turn {
			case 1:
				decisions.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 1, Instruction: "next w1"})
			case 2:
				decisions.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 2, Instruction: "next w2"})
			}
		}
		w1 := &WorkerState{ID: 1, Alive: true, Agent: &agent.FakeAgent{}, LastInstruction: "old1"}
		w2 := &WorkerState{ID: 2, Alive: true, Agent: &agent.FakeAgent{}, LastInstruction: "old2"}
		dirChat := NewDirectorChat()
		fire, fired := scriptedFireFn(t, map[int][]agent.TurnSummary{
			1: {{AssistantText: "w1 iter+1 turn"}},
			2: {{AssistantText: "w2 iter+1 turn"}},
		})
		res := RunDecisionPhase(t.Context(), DecisionPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			Workers: []*WorkerState{w1, w2},
			Fire:    fire,
		}, nil)

		assert.Equal(t, 2, turn)
		assert.Equal(t, []int{1, 2}, fired())
		require.Len(t, decisions.WorkerDecisions, 2)
		assert.Equal(t, "next w1", w1.LastInstruction)
		assert.Equal(t, "next w2", w2.LastInstruction)
		assert.Len(t, res.Wait(), 2)
	})

	t.Run("defaults_to_continue", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "I forgot to call the tool"}}}
		w1 := &WorkerState{ID: 1, Alive: true, Agent: &agent.FakeAgent{}, LastInstruction: "stale"}
		dirChat := NewDirectorChat()
		fire, _ := scriptedFireFn(t, nil)
		RunDecisionPhase(t.Context(), DecisionPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			Workers: []*WorkerState{w1}, Fire: fire,
		}, nil)
		require.Len(t, decisions.WorkerDecisions, 1)
		assert.Equal(t, "continue", decisions.WorkerDecisions[0].Kind)
		assert.Equal(t, "stale", w1.LastInstruction)
	})

	t.Run("bounded_drain_falls_back_to_continue", func(t *testing.T) {
		decisions := NewDecisionQueue()
		// Director drains but never adds a decision to simulate the stuck-on-rejection case
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "stuck loop"}}}
		w1 := &WorkerState{ID: 1, Alive: true, Agent: &agent.FakeAgent{}, LastInstruction: "stale"}
		dirChat := NewDirectorChat()
		fire, _ := scriptedFireFn(t, nil)
		RunDecisionPhase(t.Context(), DecisionPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			Workers: []*WorkerState{w1}, Fire: fire,
		}, nil)
		require.Len(t, director.MaxRoundsSeen, 1)
		assert.Equal(t, decisionDrainMaxRounds, director.MaxRoundsSeen[0])
		require.Len(t, decisions.WorkerDecisions, 1)
		assert.Equal(t, "continue", decisions.WorkerDecisions[0].Kind)
		assert.Equal(t, "stale", w1.LastInstruction)
	})

	t.Run("stop_invokes_retire", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "decide"}}}
		director.OnDrain = func(_ int) {
			decisions.AddDecision(WorkerDecision{Kind: "stop", WorkerID: 1, Reason: "exhausted"})
		}
		w1 := &WorkerState{ID: 1, Alive: true, Agent: &agent.FakeAgent{}}
		dirChat := NewDirectorChat()
		var retired []*WorkerState
		var retiredReason string
		fire, _ := scriptedFireFn(t, nil)
		RunDecisionPhase(t.Context(), DecisionPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			Workers: []*WorkerState{w1}, Fire: fire,
			Retire: func(w *WorkerState, reason string, _ int) {
				retired = append(retired, w)
				retiredReason = reason
			},
		}, nil)
		require.Len(t, retired, 1)
		assert.Equal(t, w1, retired[0])
		assert.Equal(t, "exhausted", retiredReason)
	})

	t.Run("fork_spawns_and_fires", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "decide+fork"}}}
		director.OnDrain = func(_ int) {
			decisions.AddDecision(WorkerDecision{
				Kind: "expand", WorkerID: 1, Instruction: "pivot parent",
				Fork: &ForkSubAction{NewWorkerID: 9, Instruction: "child probes /admin"},
			})
		}
		w1 := &WorkerState{ID: 1, Alive: true, Agent: &agent.FakeAgent{}}
		dirChat := NewDirectorChat()
		fire, fired := scriptedFireFn(t, map[int][]agent.TurnSummary{
			1: {{AssistantText: "w1 iter+1"}},
			9: {{AssistantText: "child iter 1"}},
		})
		var spawnedID int
		var spawnedInstruction string
		spawn := func(_ context.Context, id int, instruction string) (*WorkerState, error) {
			spawnedID = id
			spawnedInstruction = instruction
			return &WorkerState{ID: id, Alive: true, Agent: &agent.FakeAgent{}, LastInstruction: instruction}, nil
		}
		RunDecisionPhase(t.Context(), DecisionPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			Workers: []*WorkerState{w1}, Fire: fire,
			SpawnChild: spawn,
			Iter:       3,
		}, nil)
		assert.Equal(t, 9, spawnedID)
		assert.Equal(t, "child probes /admin", spawnedInstruction)
		assert.ElementsMatch(t, []int{1, 9}, fired())
	})

	t.Run("aborts_on_canceled_ctx", func(t *testing.T) {
		decisions := NewDecisionQueue()
		// Director would otherwise default-continue on every drain error
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "would never run"}}}
		w1 := &WorkerState{ID: 1, Alive: true, Agent: &agent.FakeAgent{}, LastInstruction: "stale1"}
		w2 := &WorkerState{ID: 2, Alive: true, Agent: &agent.FakeAgent{}, LastInstruction: "stale2"}
		dirChat := NewDirectorChat()
		fire, fired := scriptedFireFn(t, nil)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		RunDecisionPhase(ctx, DecisionPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			Workers: []*WorkerState{w1, w2}, Fire: fire,
		}, nil)
		assert.Empty(t, decisions.WorkerDecisions)
		assert.Empty(t, fired())
	})

	t.Run("appends_activity_and_decision", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "decide"}}}
		director.OnDrain = func(_ int) {
			decisions.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 1, Instruction: "next"})
		}
		workerAgent := &agent.FakeAgent{
			LastBoundaryID: 0,
			SnapshotMessages: []agent.Message{
				{Role: "assistant", Content: "worker activity"},
				{Role: "tool", ToolName: "proxy_poll", Content: "tool result"},
			},
		}
		w := &WorkerState{ID: 1, Alive: true, Agent: workerAgent}
		dirChat := NewDirectorChat()
		fire, _ := scriptedFireFn(t, nil)
		RunDecisionPhase(t.Context(), DecisionPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			Workers: []*WorkerState{w}, Fire: fire, Iter: 2,
		}, nil)
		assert.Len(t, dirChat.Messages, 3)
		assert.Equal(t, 1, dirChat.Meta[0].WorkerID)
		last := dirChat.Messages[len(dirChat.Messages)-1]
		assert.Contains(t, last.Content, "director decision recorded for worker 1")
		assert.Contains(t, last.Content, "continue")
	})

	t.Run("flushes_pending_self_prune_drops", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "decide"}}}
		director.OnDrain = func(_ int) {
			decisions.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 1, Instruction: "next"})
		}
		// Pre-populate dirChat with a prior iteration's worker activity that includes a tool-call we'll mark for pruning
		dirChat := NewDirectorChat()
		dirChat.AppendWorkerActivity(1, 1, []agent.Message{
			{
				Role:      "assistant",
				ToolCalls: []agent.ToolCall{{ID: "old1", Function: agent.ToolFunction{Name: "proxy_poll"}}},
			},
			{Role: "tool", ToolCallID: "old1", ToolName: "proxy_poll", Content: "old result"},
		})
		require.Len(t, dirChat.Messages, 2)

		workerAgent := &agent.FakeAgent{LastBoundaryID: 0}
		w := &WorkerState{
			ID: 1, Alive: true, Agent: workerAgent,
			Chronicle: history.NewChronicle([]agent.Message{
				{
					Role:      "assistant",
					ToolCalls: []agent.ToolCall{{ID: "old1", Function: agent.ToolFunction{Name: "proxy_poll"}}},
				},
				{Role: "tool", ToolCallID: "old1", ToolName: "proxy_poll", Content: "old result"},
				{Role: "assistant", Content: "kept"},
			}, []int{1, 1, 1}),
		}
		w.BufferSelfPrunes([]string{"old1"})
		fire, _ := scriptedFireFn(t, nil)
		RunDecisionPhase(t.Context(), DecisionPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			Workers: []*WorkerState{w}, Fire: fire, Iter: 2,
		}, nil)
		assert.Empty(t, w.DrainSelfPrunes())
		for _, m := range dirChat.Messages {
			assert.NotEqual(t, "old1", m.ToolCallID)
			for _, tc := range m.ToolCalls {
				assert.NotEqual(t, "old1", tc.ID)
			}
		}
		chronMsgs := w.Chronicle.Messages()
		require.Len(t, chronMsgs, 1)
		assert.Equal(t, "kept", chronMsgs[0].Content)
	})
}

func TestRunSynthesisPhase(t *testing.T) {
	t.Parallel()

	t.Run("closes_iteration", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "synth"}}}
		director.OnDrain = func(_ int) {
			decisions.SetDirectionDone("ok")
		}
		dirChat := NewDirectorChat()
		closed := RunSynthesisPhase(t.Context(), SynthesisPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			MaxWorkers: 4,
		}, nil)
		assert.True(t, closed)
		assert.True(t, decisions.HasDirectionDone)
		assert.Equal(t, "ok", decisions.DirectionDoneSummary)
	})

	t.Run("auto_closes_on_no_tool", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "no tool call"}}}
		dirChat := NewDirectorChat()
		RunSynthesisPhase(t.Context(), SynthesisPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			MaxWorkers: 4,
		}, nil)
		assert.True(t, decisions.HasDirectionDone)
		assert.Contains(t, decisions.DirectionDoneSummary, "auto: synthesis did not call direction_done")
	})

	t.Run("aborts_on_canceled_ctx", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "would never run"}}}
		dirChat := NewDirectorChat()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		closed := RunSynthesisPhase(ctx, SynthesisPhaseInput{
			Director: director, DirChat: dirChat, Decisions: decisions,
			MaxWorkers: 4,
		}, nil)
		assert.False(t, closed)
		assert.False(t, decisions.HasDirectionDone)
	})
}

func TestRunIter1ReconReviewCall(t *testing.T) {
	t.Parallel()

	t.Run("appends_response_to_dirchat", func(t *testing.T) {
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{
			AssistantText: "Worker 2: probe /admin. Worker 3: probe /api.",
		}}}
		dirChat := NewDirectorChat()
		dirChat.Append(agent.Message{Role: "user", Content: "recon summary..."}, 0, 1)
		RunIter1ReconReviewCall(t.Context(), director, dirChat, "iter status", 1, 5, nil)
		require.Len(t, dirChat.Messages, 2)
		assert.Equal(t, "assistant", dirChat.Messages[1].Role)
		assert.Contains(t, dirChat.Messages[1].Content, "Worker 2: probe /admin")
		assert.Equal(t, 0, dirChat.Meta[1].WorkerID)
	})

	t.Run("empty_response_dropped", func(t *testing.T) {
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "   "}}}
		dirChat := NewDirectorChat()
		RunIter1ReconReviewCall(t.Context(), director, dirChat, "iter status", 1, 5, nil)
		assert.Empty(t, dirChat.Messages)
	})
}

func TestRunIter1ReconPlanCall(t *testing.T) {
	t.Parallel()

	t.Run("plan_lands_no_retry", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{{AssistantText: "planning"}}}
		director.OnDrain = func(_ int) {
			decisions.SetPlan([]PlanEntry{{WorkerID: 2, Assignment: "probe /admin"}})
			decisions.SetDirectionDone("planned for iter 2")
		}
		dirChat := NewDirectorChat()
		RunIter1ReconPlanCall(t.Context(), director, dirChat, decisions, "iter status", 5, nil)
		assert.True(t, decisions.HasPlan)
		assert.True(t, decisions.HasDirectionDone)
		require.Len(t, decisions.Plan, 1)
		assert.Equal(t, 2, decisions.Plan[0].WorkerID)
		assert.Empty(t, director.Turns)
	})

	t.Run("retry_lands_plan", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{AssistantText: "first response (no plan)"},
			{AssistantText: "retry response (with plan)"},
		}}
		var turn int
		director.OnDrain = func(_ int) {
			turn++
			if turn == 1 {
				decisions.SetDirectionDone("done without plan")
			}
			if turn == 2 {
				decisions.SetPlan([]PlanEntry{{WorkerID: 2, Assignment: "probe /admin"}})
			}
		}
		dirChat := NewDirectorChat()
		RunIter1ReconPlanCall(t.Context(), director, dirChat, decisions, "iter status", 5, nil)
		assert.Equal(t, 2, turn)
		assert.True(t, decisions.HasPlan)
		require.Len(t, decisions.Plan, 1)
		assert.Equal(t, 2, decisions.Plan[0].WorkerID)
	})

	t.Run("retry_still_no_plan", func(t *testing.T) {
		decisions := NewDecisionQueue()
		director := &agent.FakeAgent{Turns: []agent.TurnSummary{
			{AssistantText: "first"},
			{AssistantText: "retry still no plan"},
		}}
		var turn int
		director.OnDrain = func(_ int) {
			turn++
			if turn == 1 {
				decisions.SetDirectionDone("done early")
			}
		}
		dirChat := NewDirectorChat()
		RunIter1ReconPlanCall(t.Context(), director, dirChat, decisions, "iter status", 5, nil)
		assert.Equal(t, 2, turn)
		assert.False(t, decisions.HasPlan)
		assert.True(t, decisions.HasDirectionDone)
	})
}
