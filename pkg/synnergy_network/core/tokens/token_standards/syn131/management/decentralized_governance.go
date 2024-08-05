package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/events"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/storage"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/transactions"
)

type ProposalStatus string

const (
	ProposalPending   ProposalStatus = "pending"
	ProposalApproved  ProposalStatus = "approved"
	ProposalRejected  ProposalStatus = "rejected"
)

type Proposal struct {
	ID           string         `json:"id"`
	Title        string         `json:"title"`
	Description  string         `json:"description"`
	Status       ProposalStatus `json:"status"`
	VotesFor     int            `json:"votes_for"`
	VotesAgainst int            `json:"votes_against"`
}

type DecentralizedGovernance struct {
	Storage         storage.Storage
	OwnershipLedger *ledger.OwnershipLedger
	EventDispatcher events.EventDispatcher
	mutex           sync.Mutex
	proposals       map[string]Proposal
}

func NewDecentralizedGovernance(storage storage.Storage, ownershipLedger *ledger.OwnershipLedger, eventDispatcher events.EventDispatcher) *DecentralizedGovernance {
	return &DecentralizedGovernance{
		Storage:         storage,
		OwnershipLedger: ownershipLedger,
		EventDispatcher: eventDispatcher,
		proposals:       make(map[string]Proposal),
	}
}

// CreateProposal creates a new governance proposal
func (dg *DecentralizedGovernance) CreateProposal(title, description string) (string, error) {
	dg.mutex.Lock()
	defer dg.mutex.Unlock()

	proposalID := fmt.Sprintf("proposal_%d", len(dg.proposals)+1)
	proposal := Proposal{
		ID:           proposalID,
		Title:        title,
		Description:  description,
		Status:       ProposalPending,
		VotesFor:     0,
		VotesAgainst: 0,
	}

	dg.proposals[proposalID] = proposal

	event := events.Event{
		Type:    events.ProposalCreated,
		Payload: map[string]interface{}{"proposalID": proposalID},
	}
	if err := dg.EventDispatcher.Dispatch(event); err != nil {
		return "", fmt.Errorf("failed to dispatch proposal created event: %w", err)
	}

	return proposalID, nil
}

// GetProposal retrieves a proposal by ID
func (dg *DecentralizedGovernance) GetProposal(proposalID string) (Proposal, error) {
	dg.mutex.Lock()
	defer dg.mutex.Unlock()

	proposal, exists := dg.proposals[proposalID]
	if !exists {
		return Proposal{}, errors.New("proposal not found")
	}

	return proposal, nil
}

// VoteOnProposal casts a vote on a proposal
func (dg *DecentralizedGovernance) VoteOnProposal(proposalID string, voteFor bool) error {
	dg.mutex.Lock()
	defer dg.mutex.Unlock()

	proposal, exists := dg.proposals[proposalID]
	if !exists {
		return errors.New("proposal not found")
	}

	if voteFor {
		proposal.VotesFor++
	} else {
		proposal.VotesAgainst++
	}

	if proposal.VotesFor > proposal.VotesAgainst {
		proposal.Status = ProposalApproved
	} else {
		proposal.Status = ProposalRejected
	}

	dg.proposals[proposalID] = proposal

	event := events.Event{
		Type:    events.ProposalVoted,
		Payload: map[string]interface{}{"proposalID": proposalID, "voteFor": voteFor},
	}
	if err := dg.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch proposal voted event: %w", err)
	}

	return nil
}

// ListProposals lists all governance proposals
func (dg *DecentralizedGovernance) ListProposals() ([]Proposal, error) {
	dg.mutex.Lock()
	defer dg.mutex.Unlock()

	var proposalsList []Proposal
	for _, proposal := range dg.proposals {
		proposalsList = append(proposalsList, proposal)
	}

	return proposalsList, nil
}

// EncryptAndStoreProposal encrypts and stores sensitive proposal information
func (dg *DecentralizedGovernance) EncryptAndStoreProposal(proposalID string, proposalData []byte, passphrase string) error {
	salt, err := security.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	encryptedData, err := security.Encrypt(proposalData, passphrase, salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt proposal data: %w", err)
	}

	storeData := append(salt, encryptedData...)
	if err := dg.Storage.Save(fmt.Sprintf("encrypted_proposal_%s", proposalID), storeData); err != nil {
		return fmt.Errorf("failed to save encrypted proposal data: %w", err)
	}

	return nil
}

// DecryptAndRetrieveProposal decrypts and retrieves sensitive proposal information
func (dg *DecentralizedGovernance) DecryptAndRetrieveProposal(proposalID string, passphrase string) ([]byte, error) {
	storeData, err := dg.Storage.Load(fmt.Sprintf("encrypted_proposal_%s", proposalID))
	if err != nil {
		return nil, fmt.Errorf("failed to load encrypted proposal data: %w", err)
	}

	salt := storeData[:security.SaltSize]
	encryptedData := storeData[security.SaltSize:]

	data, err := security.Decrypt(encryptedData, passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt proposal data: %w", err)
	}

	return data, nil
}

// ValidateProposalApproval validates if a proposal has been approved
func (dg *DecentralizedGovernance) ValidateProposalApproval(proposalID string) (bool, error) {
	proposal, err := dg.GetProposal(proposalID)
	if err != nil {
		return false, err
	}

	return proposal.Status == ProposalApproved, nil
}

// GenerateGovernanceReport generates a comprehensive report of all proposals and their statuses
func (dg *DecentralizedGovernance) GenerateGovernanceReport() (map[string]interface{}, error) {
	proposals, err := dg.ListProposals()
	if err != nil {
		return nil, fmt.Errorf("failed to list proposals: %w", err)
	}

	report := make(map[string]interface{})
	for _, proposal := range proposals {
		report[proposal.ID] = map[string]interface{}{
			"proposal":   proposal,
			"title":      proposal.Title,
			"description": proposal.Description,
			"status":     proposal.Status,
			"votes_for":  proposal.VotesFor,
			"votes_against": proposal.VotesAgainst,
		}
	}

	return report, nil
}
