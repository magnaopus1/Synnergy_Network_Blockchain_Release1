package decentralized

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

// ProposalStatus represents the status of an upgrade proposal
type ProposalStatus int

const (
	Proposed ProposalStatus = iota
	Accepted
	Rejected
)

// GovernanceProposal represents an upgrade proposal in the governance model
type GovernanceProposal struct {
	ID              string
	Title           string
	Description     string
	ProposerID      string
	Status          ProposalStatus
	VotesFor        int
	VotesAgainst    int
	Deadline        time.Time
	EncryptedDetails string
}

// UpgradeProposals manages upgrade proposals in the governance model
type UpgradeProposals struct {
	Proposals map[string]GovernanceProposal
	mutex     sync.Mutex
}

// NewUpgradeProposals initializes a new UpgradeProposals
func NewUpgradeProposals() *UpgradeProposals {
	return &UpgradeProposals{
		Proposals: make(map[string]GovernanceProposal),
	}
}

// SubmitProposal allows a stakeholder to submit a new upgrade proposal
func (up *UpgradeProposals) SubmitProposal(title, description, proposerID, secret string, deadline time.Time) (string, error) {
	up.mutex.Lock()
	defer up.mutex.Unlock()

	id := uuid.New().String()
	details := fmt.Sprintf("%s:%s:%s:%s", id, title, description, proposerID)
	encryptedDetails, err := encryptData(secret, details)
	if err != nil {
		return "", err
	}

	proposal := GovernanceProposal{
		ID:              id,
		Title:           title,
		Description:     description,
		ProposerID:      proposerID,
		Status:          Proposed,
		VotesFor:        0,
		VotesAgainst:    0,
		Deadline:        deadline,
		EncryptedDetails: encryptedDetails,
	}
	up.Proposals[id] = proposal
	return id, nil
}

// ValidateProposal validates and finalizes a proposal
func (up *UpgradeProposals) ValidateProposal(proposalID, secret string) error {
	up.mutex.Lock()
	defer up.mutex.Unlock()

	proposal, exists := up.Proposals[proposalID]
	if !exists {
		return errors.New("proposal does not exist")
	}

	decryptedDetails, err := decryptData(secret, proposal.EncryptedDetails)
	if err != nil {
		return err
	}

	if proposal.Status != Proposed {
		return errors.New("proposal already validated")
	}

	if decryptedDetails == fmt.Sprintf("%s:%s:%s:%s", proposal.ID, proposal.Title, proposal.Description, proposal.ProposerID) {
		proposal.Status = Accepted
	} else {
		proposal.Status = Rejected
	}

	up.Proposals[proposalID] = proposal
	return nil
}

// ListProposals lists all proposals
func (up *UpgradeProposals) ListProposals() []GovernanceProposal {
	up.mutex.Lock()
	defer up.mutex.Unlock()

	proposals := []GovernanceProposal{}
	for _, proposal := range up.Proposals {
		proposals = append(proposals, proposal)
	}
	return proposals
}

// VoteOnProposal allows a stakeholder to vote on a proposal
func (up *UpgradeProposals) VoteOnProposal(proposalID, voterID string, voteFor bool, secret string) error {
	up.mutex.Lock()
	defer up.mutex.Unlock()

	proposal, exists := up.Proposals[proposalID]
	if !exists {
		return errors.New("proposal does not exist")
	}

	if proposal.Status != Proposed {
		return errors.New("proposal not open for voting")
	}

	signature := generateSignature(fmt.Sprintf("%s:%s:%t", proposalID, voterID, voteFor), secret)

	if voteFor {
		proposal.VotesFor++
	} else {
		proposal.VotesAgainst++
	}

	up.Proposals[proposalID] = proposal
	return nil
}

// encryptData encrypts the given data using AES
func encryptData(secret, data string) (string, error) {
	block, err := aes.NewCipher([]byte(createHash(secret)))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	encrypted := aesGCM.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(encrypted), nil
}

// decryptData decrypts the given data using AES
func decryptData(secret, encryptedData string) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(createHash(secret)))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// createHash creates a hash from the secret key
func createHash(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// generateSignature generates a signature for the vote using Argon2
func generateSignature(data, secret string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}
