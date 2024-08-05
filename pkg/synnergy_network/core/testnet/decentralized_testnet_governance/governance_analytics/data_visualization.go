package decision_making

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/cryptography"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/messaging"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/storage"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/testnet/decentralized_testnet_governance/voting_mechanism"
)

// Proposal represents a governance proposal
type Proposal struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Proposer    string    `json:"proposer"`
	CreatedAt   time.Time `json:"created_at"`
	Status      string    `json:"status"`
	Votes       Votes     `json:"votes"`
}

// Votes represents the votes for a proposal
type Votes struct {
	For       int `json:"for"`
	Against   int `json:"against"`
	Abstain   int `json:"abstain"`
	Threshold int `json:"threshold"`
}

// ProposalApproval handles the approval process of proposals
type ProposalApproval struct {
	storage       storage.Storage
	messaging     messaging.Messaging
	votingMechanism voting_mechanism.VotingMechanism
}

// NewProposalApproval creates a new ProposalApproval instance
func NewProposalApproval(storage storage.Storage, messaging messaging.Messaging, votingMechanism voting_mechanism.VotingMechanism) *ProposalApproval {
	return &ProposalApproval{
		storage:       storage,
		messaging:     messaging,
		votingMechanism: votingMechanism,
	}
}

// SubmitProposal submits a new proposal for approval
func (pa *ProposalApproval) SubmitProposal(title, description, proposer string, threshold int) (string, error) {
	proposalID := generateProposalID(title, description, proposer)
	proposal := Proposal{
		ID:          proposalID,
		Title:       title,
		Description: description,
		Proposer:    proposer,
		CreatedAt:   time.Now(),
		Status:      "Pending",
		Votes: Votes{
			Threshold: threshold,
		},
	}

	data, err := json.Marshal(proposal)
	if err != nil {
		return "", err
	}

	err = pa.storage.Save(proposalID, data)
	if err != nil {
		return "", err
	}

	return proposalID, nil
}

// VoteOnProposal allows a user to vote on a proposal
func (pa *ProposalApproval) VoteOnProposal(proposalID, voterID string, vote int) error {
	data, err := pa.storage.Load(proposalID)
	if err != nil {
		return err
	}

	var proposal Proposal
	err = json.Unmarshal(data, &proposal)
	if err != nil {
		return err
	}

	if proposal.Status != "Pending" {
		return errors.New("proposal is not in pending status")
	}

	switch vote {
	case 1:
		proposal.Votes.For++
	case -1:
		proposal.Votes.Against++
	case 0:
		proposal.Votes.Abstain++
	default:
		return errors.New("invalid vote")
	}

	if proposal.Votes.For >= proposal.Votes.Threshold {
		proposal.Status = "Approved"
	} else if proposal.Votes.Against >= proposal.Votes.Threshold {
		proposal.Status = "Rejected"
	}

	data, err = json.Marshal(proposal)
	if err != nil {
		return err
	}

	err = pa.storage.Save(proposalID, data)
	if err != nil {
		return err
	}

	// Notify stakeholders about the vote
	err = pa.messaging.NotifyStakeholders("ProposalVote", proposal)
	if err != nil {
		return err
	}

	return nil
}

// GetProposal retrieves a proposal by ID
func (pa *ProposalApproval) GetProposal(proposalID string) (Proposal, error) {
	data, err := pa.storage.Load(proposalID)
	if err != nil {
		return Proposal{}, err
	}

	var proposal Proposal
	err = json.Unmarshal(data, &proposal)
	if err != nil {
		return Proposal{}, err
	}

	return proposal, nil
}

// generateProposalID generates a unique ID for a proposal
func generateProposalID(title, description, proposer string) string {
	hash := sha256.New()
	hash.Write([]byte(title + description + proposer + time.Now().String()))
	return hex.EncodeToString(hash.Sum(nil))
}

// VerifyProposalID verifies the integrity of a proposal ID
func VerifyProposalID(proposalID, title, description, proposer string) bool {
	expectedID := generateProposalID(title, description, proposer)
	return subtle.ConstantTimeCompare([]byte(proposalID), []byte(expectedID)) == 1
}

// ValidateProposal verifies the proposal details before submission
func (pa *ProposalApproval) ValidateProposal(title, description, proposer string) error {
	if len(title) == 0 || len(description) == 0 || len(proposer) == 0 {
		return errors.New("title, description, and proposer cannot be empty")
	}
	if len(title) > 100 {
		return errors.New("title exceeds maximum length")
	}
	if len(description) > 1000 {
		return errors.New("description exceeds maximum length")
	}
	// Further validation logic can be added here
	return nil
}

// EncryptProposalDetails encrypts proposal details using the best encryption algorithm for the situation
func EncryptProposalDetails(proposal Proposal, secretKey string) (string, error) {
	proposalData, err := json.Marshal(proposal)
	if err != nil {
		return "", err
	}
	encryptedData, err := cryptography.Encrypt(proposalData, secretKey, cryptography.Argon2)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encryptedData), nil
}

// DecryptProposalDetails decrypts proposal details using the best encryption algorithm for the situation
func DecryptProposalDetails(encryptedData, secretKey string) (Proposal, error) {
	encryptedBytes, err := hex.DecodeString(encryptedData)
	if err != nil {
		return Proposal{}, err
	}
	decryptedData, err := cryptography.Decrypt(encryptedBytes, secretKey, cryptography.Argon2)
	if err != nil {
		return Proposal{}, err
	}
	var proposal Proposal
	err = json.Unmarshal(decryptedData, &proposal)
	if err != nil {
		return Proposal{}, err
	}
	return proposal, nil
}
