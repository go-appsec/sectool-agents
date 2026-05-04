package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCandidatePoolAddAndPending(t *testing.T) {
	t.Parallel()

	p := NewCandidatePool()
	before := p.Counter()
	c1 := p.Add(AddInput{WorkerID: 1, Title: "x", Severity: "low", FlowIDs: []string{"abc123"}})
	c2 := p.Add(AddInput{WorkerID: 2, Title: "y", Severity: "low", FlowIDs: []string{"def456"}})

	assert.Equal(t, "c001", c1)
	assert.Equal(t, "c002", c2)
	assert.Equal(t, []string{"c001"}, p.IDsSinceForWorker(before, 1))
	assert.Equal(t, []string{"c002"}, p.IDsSinceForWorker(before, 2))
	assert.Empty(t, p.IDsSinceForWorker(before, 3))

	p.Mark("c001", CandidateStatusVerified)
	pending := p.Pending()
	require.Len(t, pending, 1)
	assert.Equal(t, "c002", pending[0].CandidateID)
}

func TestCandidatePoolByID(t *testing.T) {
	t.Parallel()

	p := NewCandidatePool()
	id := p.Add(AddInput{WorkerID: 1, Title: "x", FlowIDs: []string{"f1"}})

	got := p.ByID(id)
	require.NotNil(t, got)
	assert.Equal(t, id, got.CandidateID)
	assert.Equal(t, []string{"f1"}, got.FlowIDs)

	// Mutations on the returned copy must not bleed into the pool.
	got.FlowIDs[0] = "mutated"
	again := p.ByID(id)
	assert.Equal(t, "f1", again.FlowIDs[0])

	assert.Nil(t, p.ByID("nope"))
}

func TestCandidatePoolMark(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		first  string
		second string
		want   string
	}{
		{"verified_is_terminal", CandidateStatusVerified, CandidateStatusDismissed, CandidateStatusVerified},
		{"dismissed_is_terminal", CandidateStatusDismissed, CandidateStatusVerified, CandidateStatusDismissed},
		{"invalid_status_ignored", "nonsense", "", CandidateStatusPending},
		{"empty_status_ignored", "", "", CandidateStatusPending},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := NewCandidatePool()
			id := p.Add(AddInput{WorkerID: 1, Title: "x"})
			p.Mark(id, c.first)
			if c.second != "" {
				p.Mark(id, c.second)
			}
			assert.Equal(t, c.want, p.ByID(id).Status)
		})
	}

	t.Run("unknown_id_noop", func(t *testing.T) {
		p := NewCandidatePool()
		require.NotPanics(t, func() {
			p.Mark("c999", CandidateStatusVerified)
		})
		assert.Empty(t, p.Pending())
	})
}
