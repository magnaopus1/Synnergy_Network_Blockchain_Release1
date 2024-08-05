package management

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

// GovernanceProposal represents a proposal within the decentralized governance system
type GovernanceProposal struct {
	ProposalID   string
	Title        string
	Description  string
	Proposer     string
	Status       string
	Votes        map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// DecentralizedGovernance manages the proposals and voting within the governance system
type DecentralizedGovernance struct {
	proposals map[string]GovernanceProposal
}

// NewDecentralizedGovernance creates a new decentralized governance manager
func NewDecentralizedGovernance() *DecentralizedGovernance {
	return &DecentralizedGovernance{proposals: make(map[string]GovernanceProposal)}
}

// CreateProposal creates a new governance proposal
func (dg *DecentralizedGovernance) CreateProposal(proposalID, title, description, proposer string) (GovernanceProposal, error) {
	if _, exists := dg.proposals[proposalID]; exists {
		return GovernanceProposal{}, errors.New("proposal with this ID already exists")
	}

	proposal := GovernanceProposal{
		ProposalID:  proposalID,
		Title:       title,
		Description: description,
		Proposer:    proposer,
		Status:      "Pending",
		Votes:       make(map[string]string),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	dg.proposals[proposalID] = proposal
	return proposal, nil
}

// VoteOnProposal allows a stakeholder to vote on a proposal
func (dg *DecentralizedGovernance) VoteOnProposal(proposalID, voterID, vote string) error {
	proposal, exists := dg.proposals[proposalID]
	if !exists {
		return errors.New("proposal not found")
	}

	if proposal.Status != "Pending" {
		return errors.New("voting is closed for this proposal")
	}

	proposal.Votes[voterID] = vote
	proposal.UpdatedAt = time.Now()
	dg.proposals[proposalID] = proposal
	return nil
}

// CloseProposal closes voting on a proposal and sets its status based on the votes
func (dg *DecentralizedGovernance) CloseProposal(proposalID string) error {
	proposal, exists := dg.proposals[proposalID]
	if !exists {
		return errors.New("proposal not found")
	}

	if proposal.Status != "Pending" {
		return errors.New("proposal is already closed")
	}

	// Calculate the result of the vote
	voteCounts := map[string]int{"Yes": 0, "No": 0, "Abstain": 0}
	for _, vote := range proposal.Votes {
		if count, exists := voteCounts[vote]; exists {
			voteCounts[vote] = count + 1
		}
	}

	if voteCounts["Yes"] > voteCounts["No"] {
		proposal.Status = "Approved"
	} else {
		proposal.Status = "Rejected"
	}
	proposal.UpdatedAt = time.Now()
	dg.proposals[proposalID] = proposal
	return nil
}

// GetProposal retrieves a proposal by its ID
func (dg *DecentralizedGovernance) GetProposal(proposalID string) (GovernanceProposal, error) {
	proposal, exists := dg.proposals[proposalID]
	if !exists {
		return GovernanceProposal{}, errors.New("proposal not found")
	}
	return proposal, nil
}

// ListProposals lists all proposals
func (dg *DecentralizedGovernance) ListProposals() ([]GovernanceProposal, error) {
	var proposals []GovernanceProposal
	for _, proposal := range dg.proposals {
		proposals = append(proposals, proposal)
	}
	return proposals, nil
}

// SecureStorage handles secure storage of data
type SecureStorage struct {
	key []byte
}

// NewSecureStorage creates a new secure storage with a key
func NewSecureStorage(password string) *SecureStorage {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	key := argon2.Key([]byte(password), salt, 3, 32*1024, 4, 32)
	return &SecureStorage{key: key}
}

// Encrypt encrypts data using AES
func (s *SecureStorage) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// Decrypt decrypts data using AES
func (s *SecureStorage) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// SecureGovernanceData securely stores governance data
func (dg *DecentralizedGovernance) SecureGovernanceData(secureStorage *SecureStorage) (string, error) {
	jsonData, err := json.Marshal(dg.proposals)
	if err != nil {
		return "", err
	}

	encryptedData, err := secureStorage.Encrypt(jsonData)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", encryptedData), nil
}

// RetrieveGovernanceData retrieves and decrypts governance data
func (dg *DecentralizedGovernance) RetrieveGovernanceData(encryptedDataHex string, secureStorage *SecureStorage) error {
	encryptedData, err := hex.DecodeString(encryptedDataHex)
	if err != nil {
		return err
	}

	jsonData, err := secureStorage.Decrypt(encryptedData)
	if err != nil {
		return err
	}

	var proposals map[string]GovernanceProposal
	err = json.Unmarshal(jsonData, &proposals)
	if err != nil {
		return err
	}

	dg.proposals = proposals
	return nil
}

// GenerateGovernanceReport generates a report for all proposals
func (dg *DecentralizedGovernance) GenerateGovernanceReport() (string, error) {
	report := "Governance Report\n"
	report += "----------------\n"

	for _, proposal := range dg.proposals {
		report += fmt.Sprintf("Proposal ID: %s\nTitle: %s\nDescription: %s\nProposer: %s\nStatus: %s\nCreated At: %s\nUpdated At: %s\nVotes:\n",
			proposal.ProposalID, proposal.Title, proposal.Description, proposal.Proposer, proposal.Status, proposal.CreatedAt.String(), proposal.UpdatedAt.String())

		for voter, vote := range proposal.Votes {
			report += fmt.Sprintf("  - %s: %s\n", voter, vote)
		}
		report += "\n"
	}

	return report, nil
}
