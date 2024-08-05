package management

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// ProposalStatus represents the status of a governance proposal
type ProposalStatus string

const (
	ProposalPending   ProposalStatus = "pending"
	ProposalApproved  ProposalStatus = "approved"
	ProposalRejected  ProposalStatus = "rejected"
)

// GovernanceProposal represents a proposal for changes to the debt instrument terms
type GovernanceProposal struct {
	ProposalID     string          `json:"proposal_id"`
	ProposerID     string          `json:"proposer_id"`
	Title          string          `json:"title"`
	Description    string          `json:"description"`
	TargetDebtID   string          `json:"target_debt_id"`
	Changes        map[string]interface{} `json:"changes"`
	Status         ProposalStatus  `json:"status"`
	VotesFor       int             `json:"votes_for"`
	VotesAgainst   int             `json:"votes_against"`
	CreationDate   time.Time       `json:"creation_date"`
	LastUpdatedDate time.Time      `json:"last_updated_date"`
}

// DecentralizedGovernance manages governance proposals and voting
type DecentralizedGovernance struct {
	mu sync.Mutex
	proposals map[string]GovernanceProposal
}

// NewDecentralizedGovernance creates a new instance of DecentralizedGovernance
func NewDecentralizedGovernance() *DecentralizedGovernance {
	return &DecentralizedGovernance{
		proposals: make(map[string]GovernanceProposal),
	}
}

// ProposeChange creates a new governance proposal
func (dg *DecentralizedGovernance) ProposeChange(proposerID, title, description, targetDebtID string, changes map[string]interface{}) (string, error) {
	dg.mu.Lock()
	defer dg.mu.Unlock()

	proposalID := generateProposalID()
	creationDate := time.Now()

	proposal := GovernanceProposal{
		ProposalID:     proposalID,
		ProposerID:     proposerID,
		Title:          title,
		Description:    description,
		TargetDebtID:   targetDebtID,
		Changes:        changes,
		Status:         ProposalPending,
		VotesFor:       0,
		VotesAgainst:   0,
		CreationDate:   creationDate,
		LastUpdatedDate: creationDate,
	}

	dg.proposals[proposalID] = proposal
	err := saveProposalToStorage(proposal)
	if err != nil {
		return "", err
	}

	return proposalID, nil
}

// VoteOnProposal registers a vote for a governance proposal
func (dg *DecentralizedGovernance) VoteOnProposal(proposalID string, voteFor bool) error {
	dg.mu.Lock()
	defer dg.mu.Unlock()

	proposal, exists := dg.proposals[proposalID]
	if !exists {
		return errors.New("proposal not found")
	}

	if proposal.Status != ProposalPending {
		return errors.New("proposal is not in a pending state")
	}

	if voteFor {
		proposal.VotesFor++
	} else {
		proposal.VotesAgainst++
	}

	proposal.LastUpdatedDate = time.Now()
	dg.proposals[proposalID] = proposal
	err := saveProposalToStorage(proposal)
	if err != nil {
		return err
	}

	return nil
}

// FinalizeProposal finalizes the voting on a proposal and updates its status
func (dg *DecentralizedGovernance) FinalizeProposal(proposalID string) error {
	dg.mu.Lock()
	defer dg.mu.Unlock()

	proposal, exists := dg.proposals[proposalID]
	if !exists {
		return errors.New("proposal not found")
	}

	if proposal.Status != ProposalPending {
		return errors.New("proposal is not in a pending state")
	}

	if proposal.VotesFor > proposal.VotesAgainst {
		proposal.Status = ProposalApproved
	} else {
		proposal.Status = ProposalRejected
	}

	proposal.LastUpdatedDate = time.Now()
	dg.proposals[proposalID] = proposal
	err := saveProposalToStorage(proposal)
	if err != nil {
		return err
	}

	return nil
}

// GetProposal retrieves a governance proposal by ID
func (dg *DecentralizedGovernance) GetProposal(proposalID string) (GovernanceProposal, error) {
	dg.mu.Lock()
	defer dg.mu.Unlock()

	proposal, exists := dg.proposals[proposalID]
	if !exists {
		return GovernanceProposal{}, errors.New("proposal not found")
	}

	return proposal, nil
}

// generateProposalID generates a unique ID for the proposal
func generateProposalID() string {
	// Implement unique ID generation logic, for example using UUID
	return "unique-proposal-id"
}

// saveProposalToStorage securely stores proposal data
func saveProposalToStorage(proposal GovernanceProposal) error {
	data, err := json.Marshal(proposal)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("governanceProposal", proposal.ProposalID, encryptedData)
}

// deleteProposalFromStorage deletes proposal data from storage
func deleteProposalFromStorage(proposalID string) error {
	return storage.Delete("governanceProposal", proposalID)
}
