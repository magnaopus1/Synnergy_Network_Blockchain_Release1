package liquidity

import (
	"errors"
	"sync"
	"time"
)

// Governance represents the governance structure for the liquidity sidechain
type Governance struct {
	mu          sync.RWMutex
	proposals   map[string]*Proposal
	voters      map[string]*Voter
	quorum      float64
	voteTimeout time.Duration
}

// Proposal represents a governance proposal
type Proposal struct {
	ID           string
	Title        string
	Description  string
	CreationTime time.Time
	Deadline     time.Time
	Votes        map[string]bool
	Results      map[bool]int
	Status       string
}

// Voter represents a participant who can vote
type Voter struct {
	ID    string
	Power int
}

// NewGovernance creates a new Governance instance
func NewGovernance(quorum float64, voteTimeout time.Duration) *Governance {
	return &Governance{
		proposals:   make(map[string]*Proposal),
		voters:      make(map[string]*Voter),
		quorum:      quorum,
		voteTimeout: voteTimeout,
	}
}

// AddVoter adds a new voter with voting power
func (g *Governance) AddVoter(voterID string, power int) error {
	if power <= 0 {
		return errors.New("voting power must be positive")
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.voters[voterID] = &Voter{ID: voterID, Power: power}
	return nil
}

// RemoveVoter removes a voter
func (g *Governance) RemoveVoter(voterID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.voters[voterID]; !exists {
		return errors.New("voter not found")
	}

	delete(g.voters, voterID)
	return nil
}

// CreateProposal creates a new proposal
func (g *Governance) CreateProposal(id, title, description string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.proposals[id]; exists {
		return errors.New("proposal with this ID already exists")
	}

	proposal := &Proposal{
		ID:           id,
		Title:        title,
		Description:  description,
		CreationTime: time.Now(),
		Deadline:     time.Now().Add(g.voteTimeout),
		Votes:        make(map[string]bool),
		Results:      make(map[bool]int),
		Status:       "active",
	}

	g.proposals[id] = proposal
	return nil
}

// Vote allows a voter to vote on a proposal
func (g *Governance) Vote(voterID, proposalID string, vote bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	voter, exists := g.voters[voterID]
	if !exists {
		return errors.New("voter not found")
	}

	proposal, exists := g.proposals[proposalID]
	if !exists {
		return errors.New("proposal not found")
	}

	if time.Now().After(proposal.Deadline) {
		return errors.New("voting period for this proposal has ended")
	}

	if _, voted := proposal.Votes[voterID]; voted {
		return errors.New("voter has already voted on this proposal")
	}

	proposal.Votes[voterID] = vote
	if vote {
		proposal.Results[true] += voter.Power
	} else {
		proposal.Results[false] += voter.Power
	}

	return nil
}

// TallyResults tallies the votes for a proposal and updates its status
func (g *Governance) TallyResults(proposalID string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	proposal, exists := g.proposals[proposalID]
	if !exists {
		return "", errors.New("proposal not found")
	}

	if time.Now().Before(proposal.Deadline) {
		return "", errors.New("voting period for this proposal is still active")
	}

	totalVotes := proposal.Results[true] + proposal.Results[false]
	if float64(totalVotes)/float64(len(g.voters)) < g.quorum {
		proposal.Status = "quorum not met"
	} else if proposal.Results[true] > proposal.Results[false] {
		proposal.Status = "approved"
	} else {
		proposal.Status = "rejected"
	}

	return proposal.Status, nil
}

// GetProposalStatus gets the status of a proposal
func (g *Governance) GetProposalStatus(proposalID string) (string, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	proposal, exists := g.proposals[proposalID]
	if !exists {
		return "", errors.New("proposal not found")
	}

	return proposal.Status, nil
}

// GetVoterInfo gets the information of a voter
func (g *Governance) GetVoterInfo(voterID string) (*Voter, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	voter, exists := g.voters[voterID]
	if !exists {
		return nil, errors.New("voter not found")
	}

	return voter, nil
}

// ListProposals lists all proposals
func (g *Governance) ListProposals() []*Proposal {
	g.mu.RLock()
	defer g.mu.RUnlock()

	proposals := make([]*Proposal, 0, len(g.proposals))
	for _, proposal := range g.proposals {
		proposals = append(proposals, proposal)
	}

	return proposals
}
