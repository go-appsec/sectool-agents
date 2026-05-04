package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/secagent/agent"
)

func TestDecisionQueue(t *testing.T) {
	t.Parallel()

	t.Run("full_lifecycle_tracks_state", func(t *testing.T) {
		q := NewDecisionQueue()
		assert.Equal(t, agent.PhaseIdle, q.Phase())

		q.BeginPhase(agent.PhaseVerification)
		assert.Equal(t, agent.PhaseVerification, q.Phase())

		q.SetPlan([]PlanEntry{{WorkerID: 1, Assignment: "x"}})
		assert.True(t, q.HasPlan)
		q.AddDecision(WorkerDecision{Kind: "continue", WorkerID: 1})
		q.AddFinding(FindingFiled{Title: "xss"})
		q.AddDismissal(CandidateDismissal{CandidateID: "c1", Reason: "no repro"})
		q.SetVerificationDone("all set")
		assert.True(t, q.HasVerificationDone)

		q.BeginPhase(agent.PhaseDirection)
		assert.True(t, q.HasVerificationDone)
		q.SetDirectionDone("planned")
		assert.True(t, q.HasDirectionDone)

		q.SetEndRun("run over")
		assert.True(t, q.HasEndRun)

		q.Reset()
		assert.False(t, q.HasPlan)
		assert.Empty(t, q.WorkerDecisions)
		assert.Empty(t, q.Findings)
		assert.Empty(t, q.Dismissals)
		assert.False(t, q.HasEndRun)
		assert.False(t, q.HasVerificationDone)
		assert.False(t, q.HasDirectionDone)
		assert.Equal(t, agent.PhaseIdle, q.Phase())
	})

	t.Run("begin_phase_clears_own_done", func(t *testing.T) {
		q := NewDecisionQueue()
		q.SetVerificationDone("v")
		q.SetDirectionDone("d")
		q.BeginPhase(agent.PhaseVerification)
		assert.False(t, q.HasVerificationDone)
		assert.True(t, q.HasDirectionDone)

		q.SetVerificationDone("v2")
		q.BeginPhase(agent.PhaseDirection)
		assert.True(t, q.HasVerificationDone)
		assert.False(t, q.HasDirectionDone)
	})

	t.Run("per_worker_decision_hint", func(t *testing.T) {
		q := NewDecisionQueue()
		assert.Equal(t, 0, q.AskedWorkerID())
		q.BeginPerWorkerDecision(7)
		assert.Equal(t, 7, q.AskedWorkerID())
		q.BeginPerWorkerDecision(0)
		assert.Equal(t, 0, q.AskedWorkerID())
	})
}
