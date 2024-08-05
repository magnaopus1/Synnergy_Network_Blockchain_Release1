package management

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

// DecisionStatus represents the status of a decision in the governance model
type DecisionStatus int

const (
	Pending DecisionStatus = iota
	Approved
	Rejected
)

// Decision represents a decision proposal in the governance model
type Decision struct {
	ID               string
	Title            string
	Description      string
	ProposerID       string
	Status           DecisionStatus
	VotesFor         int
	VotesAgainst     int
	Deadline         time.Time
	EncryptedDetails string
}

// DecisionMakingProcess manages decision proposals in the governance model
type DecisionMakingProcess struct {
	Decisions map[string]Decision
	mutex     sync.Mutex
}

// NewDecisionMakingProcess initializes a new DecisionMakingProcess
func NewDecisionMakingProcess() *DecisionMakingProcess {
	return &DecisionMakingProcess{
		Decisions: make(map[string]Decision),
	}
}

// SubmitDecision allows a stakeholder to submit a new decision proposal
func (dmp *DecisionMakingProcess) SubmitDecision(title, description, proposerID, secret string, deadline time.Time) (string, error) {
	dmp.mutex.Lock()
	defer dmp.mutex.Unlock()

	id := uuid.New().String()
	details := fmt.Sprintf("%s:%s:%s:%s", id, title, description, proposerID)
	encryptedDetails, err := encryptData(secret, details)
	if err != nil {
		return "", err
	}

	decision := Decision{
		ID:               id,
		Title:            title,
		Description:      description,
		ProposerID:       proposerID,
		Status:           Pending,
		VotesFor:         0,
		VotesAgainst:     0,
		Deadline:         deadline,
		EncryptedDetails: encryptedDetails,
	}
	dmp.Decisions[id] = decision
	return id, nil
}

// ValidateDecision validates and finalizes a decision proposal
func (dmp *DecisionMakingProcess) ValidateDecision(decisionID, secret string) error {
	dmp.mutex.Lock()
	defer dmp.mutex.Unlock()

	decision, exists := dmp.Decisions[decisionID]
	if !exists {
		return errors.New("decision does not exist")
	}

	decryptedDetails, err := decryptData(secret, decision.EncryptedDetails)
	if err != nil {
		return err
	}

	if decision.Status != Pending {
		return errors.New("decision already validated")
	}

	if decryptedDetails == fmt.Sprintf("%s:%s:%s:%s", decision.ID, decision.Title, decision.Description, decision.ProposerID) {
		decision.Status = Approved
	} else {
		decision.Status = Rejected
	}

	dmp.Decisions[decisionID] = decision
	return nil
}

// ListDecisions lists all decision proposals
func (dmp *DecisionMakingProcess) ListDecisions() []Decision {
	dmp.mutex.Lock()
	defer dmp.mutex.Unlock()

	decisions := []Decision{}
	for _, decision := range dmp.Decisions {
		decisions = append(decisions, decision)
	}
	return decisions
}

// VoteOnDecision allows a stakeholder to vote on a decision proposal
func (dmp *DecisionMakingProcess) VoteOnDecision(decisionID, voterID string, voteFor bool, secret string) error {
	dmp.mutex.Lock()
	defer dmp.mutex.Unlock()

	decision, exists := dmp.Decisions[decisionID]
	if !exists {
		return errors.New("decision does not exist")
	}

	if decision.Status != Pending {
		return errors.New("decision not open for voting")
	}

	signature := generateSignature(fmt.Sprintf("%s:%s:%t", decisionID, voterID, voteFor), secret)

	if voteFor {
		decision.VotesFor++
	} else {
		decision.VotesAgainst++
	}

	dmp.Decisions[decisionID] = decision
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
