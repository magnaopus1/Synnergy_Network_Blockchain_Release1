package decision_making

import (
    "crypto/sha256"
    "encoding/hex"
    "time"
    "errors"
    "sync"
    "fmt"
)

// ProposalStatus represents the status of a proposal
type ProposalStatus int

const (
    Pending ProposalStatus = iota
    Approved
    Rejected
    Implemented
)

// Proposal represents a governance proposal
type Proposal struct {
    ID            string
    Title         string
    Description   string
    Proposer      string
    SubmissionTime time.Time
    Status        ProposalStatus
    Votes         map[string]bool // VoterID -> Vote (true for approve, false for reject)
    VoteCounts    VoteCounts
    Mutex         sync.Mutex
}

// VoteCounts represents the count of votes
type VoteCounts struct {
    Approve int
    Reject  int
}

// ProposalSystem handles the governance proposals
type ProposalSystem struct {
    Proposals map[string]*Proposal
    Mutex     sync.Mutex
}

// NewProposalSystem initializes a new ProposalSystem
func NewProposalSystem() *ProposalSystem {
    return &ProposalSystem{
        Proposals: make(map[string]*Proposal),
    }
}

// SubmitProposal submits a new proposal
func (ps *ProposalSystem) SubmitProposal(title, description, proposer string) string {
    ps.Mutex.Lock()
    defer ps.Mutex.Unlock()

    proposalID := generateProposalID(title, description, proposer)
    proposal := &Proposal{
        ID:            proposalID,
        Title:         title,
        Description:   description,
        Proposer:      proposer,
        SubmissionTime: time.Now(),
        Status:        Pending,
        Votes:         make(map[string]bool),
    }

    ps.Proposals[proposalID] = proposal
    return proposalID
}

// VoteProposal allows a stakeholder to vote on a proposal
func (ps *ProposalSystem) VoteProposal(proposalID, voterID string, approve bool) error {
    ps.Mutex.Lock()
    defer ps.Mutex.Unlock()

    proposal, exists := ps.Proposals[proposalID]
    if !exists {
        return errors.New("proposal not found")
    }

    proposal.Mutex.Lock()
    defer proposal.Mutex.Unlock()

    if proposal.Status != Pending {
        return errors.New("voting is closed for this proposal")
    }

    // Record the vote
    if _, voted := proposal.Votes[voterID]; voted {
        return errors.New("voter has already voted on this proposal")
    }

    proposal.Votes[voterID] = approve
    if approve {
        proposal.VoteCounts.Approve++
    } else {
        proposal.VoteCounts.Reject++
    }

    return nil
}

// CheckProposalStatus checks the status of a proposal
func (ps *ProposalSystem) CheckProposalStatus(proposalID string) (ProposalStatus, error) {
    ps.Mutex.Lock()
    defer ps.Mutex.Unlock()

    proposal, exists := ps.Proposals[proposalID]
    if !exists {
        return 0, errors.New("proposal not found")
    }

    proposal.Mutex.Lock()
    defer proposal.Mutex.Unlock()

    return proposal.Status, nil
}

// TallyVotes tallies the votes for a proposal and updates its status
func (ps *ProposalSystem) TallyVotes(proposalID string) error {
    ps.Mutex.Lock()
    defer ps.Mutex.Unlock()

    proposal, exists := ps.Proposals[proposalID]
    if !exists {
        return errors.New("proposal not found")
    }

    proposal.Mutex.Lock()
    defer proposal.Mutex.Unlock()

    if proposal.Status != Pending {
        return errors.New("voting is already closed for this proposal")
    }

    if proposal.VoteCounts.Approve > proposal.VoteCounts.Reject {
        proposal.Status = Approved
    } else {
        proposal.Status = Rejected
    }

    return nil
}

// ImplementProposal marks an approved proposal as implemented
func (ps *ProposalSystem) ImplementProposal(proposalID string) error {
    ps.Mutex.Lock()
    defer ps.Mutex.Unlock()

    proposal, exists := ps.Proposals[proposalID]
    if !exists {
        return errors.New("proposal not found")
    }

    proposal.Mutex.Lock()
    defer proposal.Mutex.Unlock()

    if proposal.Status != Approved {
        return errors.New("only approved proposals can be implemented")
    }

    proposal.Status = Implemented
    return nil
}

// generateProposalID generates a unique ID for a proposal based on its contents
func generateProposalID(title, description, proposer string) string {
    data := fmt.Sprintf("%s:%s:%s:%d", title, description, proposer, time.Now().UnixNano())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
