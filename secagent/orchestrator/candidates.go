package orchestrator

import (
	"fmt"
	"slices"
	"sync"
)

// Candidate lifecycle statuses.
const (
	CandidateStatusPending   = "pending"
	CandidateStatusVerified  = "verified"
	CandidateStatusDismissed = "dismissed"
)

// FindingCandidate is a worker-reported, unverified issue.
type FindingCandidate struct {
	CandidateID      string
	WorkerID         int
	Title            string
	Severity         string
	Endpoint         string
	FlowIDs          []string
	Summary          string
	EvidenceNotes    string
	ReproductionHint string
	Status           string
}

type CandidatePool struct {
	mu      sync.Mutex
	byID    map[string]*FindingCandidate
	order   []string
	counter int
}

func NewCandidatePool() *CandidatePool {
	return &CandidatePool{byID: map[string]*FindingCandidate{}}
}

// AddInput is the set of fields for Add.
type AddInput struct {
	WorkerID         int
	Title            string
	Severity         string
	Endpoint         string
	FlowIDs          []string
	Summary          string
	EvidenceNotes    string
	ReproductionHint string
}

// Add records a new candidate attributed to workerID and returns its ID.
func (p *CandidatePool) Add(in AddInput) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.counter++
	cid := fmt.Sprintf("c%03d", p.counter)
	p.byID[cid] = &FindingCandidate{
		CandidateID:      cid,
		WorkerID:         in.WorkerID,
		Title:            in.Title,
		Severity:         in.Severity,
		Endpoint:         in.Endpoint,
		FlowIDs:          slices.Clone(in.FlowIDs),
		Summary:          in.Summary,
		EvidenceNotes:    in.EvidenceNotes,
		ReproductionHint: in.ReproductionHint,
		Status:           CandidateStatusPending,
	}
	p.order = append(p.order, cid)
	return cid
}

// Mark sets the status of a candidate if present. Only pending -> verified and pending -> dismissed
// transitions are accepted; verified and dismissed are terminal and cannot be overwritten.
func (p *CandidatePool) Mark(id, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	c := p.byID[id]
	if c == nil {
		return
	} else if c.Status != CandidateStatusPending {
		return
	} else if status != CandidateStatusVerified && status != CandidateStatusDismissed {
		return
	}
	c.Status = status
}

// ByID returns a copy of the candidate with the given id, or nil if not found.
func (p *CandidatePool) ByID(id string) *FindingCandidate {
	p.mu.Lock()
	defer p.mu.Unlock()

	c := p.byID[id]
	if c == nil {
		return nil
	}
	cp := *c
	cp.FlowIDs = slices.Clone(c.FlowIDs)
	return &cp
}

// Pending returns a snapshot of pending candidates in insertion order.
func (p *CandidatePool) Pending() []FindingCandidate {
	p.mu.Lock()
	defer p.mu.Unlock()

	var out []FindingCandidate
	for _, id := range p.order {
		if c := p.byID[id]; c != nil && c.Status == CandidateStatusPending {
			out = append(out, *c)
		}
	}
	return out
}

// Counter returns the current total of minted candidates.
func (p *CandidatePool) Counter() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.counter
}

// IDsSinceForWorker returns candidate IDs minted after counterBefore attributed to workerID.
func (p *CandidatePool) IDsSinceForWorker(counterBefore, workerID int) []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	var out []string
	for i := counterBefore + 1; i <= p.counter; i++ {
		cid := fmt.Sprintf("c%03d", i)
		if c := p.byID[cid]; c != nil && c.WorkerID == workerID {
			out = append(out, cid)
		}
	}
	return out
}
