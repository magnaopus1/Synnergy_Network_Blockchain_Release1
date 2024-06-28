package synthron_coin

import (
	"errors"
	"sync"
	"time"
)

// GovernanceModule handles all aspects of community governance for Synthron Coin.
type GovernanceModule struct {
	Proposals     map[int]*Proposal
	ActiveVotes   map[int]map[string]bool
	ProposalCount int
	lock          sync.Mutex
}

// Proposal defines a governance proposal.
type Proposal struct {
	ID          int
	Description string
	CreatedAt   time.Time
	EndsAt      time.Time
	Approved    bool
	Votes       map[string]bool // map of voter address to vote (true for yes, false for no)
	MinimumQuorum int           // Minimum number of votes to consider the proposal valid
	MajorityPercentage float64  // Percentage of yes votes to total votes needed to approve the proposal
}

// NewGovernanceModule initializes a new instance of the governance module.
func NewGovernanceModule() *GovernanceModule {
	return &GovernanceModule{
		Proposals:   make(map[int]*Proposal),
		ActiveVotes: make(map[int]map[string]bool),
	}
}

// CreateProposal allows a community member to submit a proposal.
func (gm *GovernanceModule) CreateProposal(description string, duration time.Duration, quorum int, majority float64) int {
	gm.lock.Lock()
	defer gm.lock.Unlock()

	proposalID := gm.ProposalCount + 1
	gm.Proposals[proposalID] = &Proposal{
		ID:          proposalID,
		Description: description,
		CreatedAt:   time.Now(),
		EndsAt:      time.Now().Add(duration),
		Votes:       make(map[string]bool),
		MinimumQuorum: quorum,
		MajorityPercentage: majority,
	}
	gm.ProposalCount++

	return proposalID
}

// Vote allows a community member to vote on a proposal.
func (gm *GovernanceModule) Vote(proposalID int, voter string, vote bool) error {
	gm.lock.Lock()
	defer gm.lock.Unlock()

	proposal, exists := gm.Proposals[proposalID]
	if !exists {
		return errors.New("proposal does not exist")
	}

	if time.Now().After(proposal.EndsAt) {
		return errors.New("voting period has ended")
	}

	proposal.Votes[voter] = vote
	return nil
}

// TallyVotes finalizes the voting process for a proposal.
func (gm *GovernanceModule) TallyVotes(proposalID int) error {
	gm.lock.Lock()
	defer gm.lock.Unlock()

	proposal, exists := gm.Proposals[proposalID]
	if !exists {
		return errors.New("proposal does not exist")
	}

	if !time.Now().After(proposal.EndsAt) {
		return errors.New("voting period has not ended yet")
	}

	totalVotes := len(proposal.Votes)
	if totalVotes < proposal.MinimumQuorum {
		return errors.New("not enough votes to meet quorum")
	}

	var yesVotes int
	for _, vote := range proposal.Votes {
		if vote {
			yesVotes++
		}
	}

	yesPercentage := (float64(yesVotes) / float64(totalVotes)) * 100
	if yesPercentage >= proposal.MajorityPercentage {
		proposal.Approved = true
	} else {
		proposal.Approved = false
	}

	return nil
}

var (
	ErrProposalNotFound       = errors.New("proposal not found")
	ErrVotingPeriodNotEnded   = errors.New("voting period not ended yet")
	ErrVotingPeriodEnded      = errors.New("voting period has ended")
	ErrNotEnoughVotes         = errors.New("not enough votes cast to meet quorum")
	ErrMajorityNotAchieved    = errors.New("majority not achieved")
)
