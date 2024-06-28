package behavioural_proof

import (
	"sync"
	"time"
)

// GovernanceManager handles governance-related operations, ensuring compliance with network rules and policies.
type GovernanceManager struct {
	mutex          sync.Mutex
	governanceData map[string]float64
	proposals      []*GovernanceProposal
	voting         *VotingSystem
}

// GovernanceProposal represents a governance proposal in the network.
type GovernanceProposal struct {
	ID          string
	Description string
	ProposedBy  string
	VoteCount   int
	Status      string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// VotingSystem handles voting on governance proposals.
type VotingSystem struct {
	mutex   sync.Mutex
	votes   map[string]int
	results map[string]bool
}

// NewGovernanceManager initializes a new instance of GovernanceManager.
func NewGovernanceManager() *GovernanceManager {
	return &GovernanceManager{
		governanceData: make(map[string]float64),
		proposals:      make([]*GovernanceProposal, 0),
		voting:         NewVotingSystem(),
	}
}

// NewVotingSystem initializes a new VotingSystem.
func NewVotingSystem() *VotingSystem {
	return &VotingSystem{
		votes:   make(map[string]int),
		results: make(map[string]bool),
	}
}

// SubmitProposal allows a validator to submit a governance proposal.
func (gm *GovernanceManager) SubmitProposal(proposal *GovernanceProposal) {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()

	proposal.ID = generateProposalID()
	proposal.CreatedAt = time.Now()
	proposal.ExpiresAt = proposal.CreatedAt.Add(72 * time.Hour) // Proposals expire in 72 hours
	gm.proposals = append(gm.proposals, proposal)
}

// VoteOnProposal allows a validator to vote on a proposal.
func (vs *VotingSystem) VoteOnProposal(proposalID string, approve bool) error {
	vs.mutex.Lock()
	defer vs.mutex.Unlock()

	if _, exists := vs.votes[proposalID]; !exists {
		vs.votes[proposalID] = 0
	}

	if approve {
		vs.votes[proposalID]++
		return nil
	}
	vs.votes[proposalID]--
	return nil
}

// TallyVotes calculates the result of the voting on a proposal.
func (vs *VotingSystem) TallyVotes(proposalID string) bool {
	vs.mutex.Lock()
	defer vs.mutex.Unlock()

	votes, exists := vs.votes[proposalID]
	if !exists {
		return false
	}

	result := votes > 0 // Simple majority
	vs.results[proposalID] = result
	return result
}

// ListProposals returns a list of all proposals in the system.
func (gm *GovernanceManager) ListProposals() []*GovernanceProposal {
	return gm.proposals
}

// generateProposalID generates a unique identifier for a proposal.
func generateProposalID() string {
	// Simple random ID generation logic
	return fmt.Sprintf("prop-%d", rand.Intn(1000000))
}

