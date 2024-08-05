package cross_chain_governance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// GovernanceProposal represents a proposal for cross-chain governance
type GovernanceProposal struct {
	ID          string
	Title       string
	Description string
	Proposer    string
	Status      ProposalStatus
	Votes       map[string]Vote
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ProposalStatus represents the status of a proposal
type ProposalStatus string

const (
	Pending   ProposalStatus = "Pending"
	Approved  ProposalStatus = "Approved"
	Rejected  ProposalStatus = "Rejected"
	Executed  ProposalStatus = "Executed"
)

// Vote represents a vote on a proposal
type Vote struct {
	Voter    string
	VoteType VoteType
	Timestamp time.Time
}

// VoteType represents the type of a vote
type VoteType string

const (
	Yes   VoteType = "Yes"
	No    VoteType = "No"
	Abstain VoteType = "Abstain"
)

// GovernanceManager manages cross-chain governance proposals
type GovernanceManager struct {
	mu         sync.Mutex
	proposals  map[string]GovernanceProposal
	secretKey  string
	threshold  int
}

// NewGovernanceManager initializes a new GovernanceManager
func NewGovernanceManager(secretKey string, threshold int) *GovernanceManager {
	return &GovernanceManager{
		proposals: make(map[string]GovernanceProposal),
		secretKey: secretKey,
		threshold: threshold,
	}
}

// CreateProposal creates a new governance proposal
func (gm *GovernanceManager) CreateProposal(title, description, proposer string) (string, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	id := generateID()
	proposal := GovernanceProposal{
		ID:          id,
		Title:       title,
		Description: description,
		Proposer:    proposer,
		Status:      Pending,
		Votes:       make(map[string]Vote),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	gm.proposals[id] = proposal
	log.Printf("Created proposal: %+v", proposal)
	return id, nil
}

// VoteProposal votes on a governance proposal
func (gm *GovernanceManager) VoteProposal(id, voter string, voteType VoteType) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	proposal, exists := gm.proposals[id]
	if !exists {
		return errors.New("proposal not found")
	}

	if proposal.Status != Pending {
		return errors.New("proposal is not in a pending state")
	}

	vote := Vote{
		Voter:    voter,
		VoteType: voteType,
		Timestamp: time.Now(),
	}

	proposal.Votes[voter] = vote
	proposal.UpdatedAt = time.Now()
	gm.proposals[id] = proposal
	log.Printf("Voted on proposal: %+v", proposal)

	gm.evaluateProposal(id)

	return nil
}

// evaluateProposal evaluates the status of a proposal based on votes
func (gm *GovernanceManager) evaluateProposal(id string) {
	proposal, exists := gm.proposals[id]
	if !exists {
		return
	}

	yesVotes := 0
	noVotes := 0

	for _, vote := range proposal.Votes {
		switch vote.VoteType {
		case Yes:
			yesVotes++
		case No:
			noVotes++
		}
	}

	if yesVotes >= gm.threshold {
		proposal.Status = Approved
	} else if noVotes >= gm.threshold {
		proposal.Status = Rejected
	}

	proposal.UpdatedAt = time.Now()
	gm.proposals[id] = proposal
	log.Printf("Evaluated proposal: %+v", proposal)
}

// ExecuteProposal executes an approved governance proposal
func (gm *GovernanceManager) ExecuteProposal(id string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	proposal, exists := gm.proposals[id]
	if !exists {
		return errors.New("proposal not found")
	}

	if proposal.Status != Approved {
		return errors.New("proposal is not approved")
	}

	proposal.Status = Executed
	proposal.UpdatedAt = time.Now()
	gm.proposals[id] = proposal
	log.Printf("Executed proposal: %+v", proposal)
	return nil
}

// GetProposal returns the details of a proposal
func (gm *GovernanceManager) GetProposal(id string) (GovernanceProposal, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	proposal, exists := gm.proposals[id]
	if !exists {
		return GovernanceProposal{}, errors.New("proposal not found")
	}

	return proposal, nil
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (gm *GovernanceManager) Encrypt(message, secretKey string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(secretKey), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(message))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(message))

	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a message using AES encryption with Scrypt derived key
func (gm *GovernanceManager) Decrypt(encryptedMessage, secretKey string) (string, error) {
	parts := split(encryptedMessage, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted message format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(secretKey), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func split(s string, sep string) []string {
	var parts []string
	var buf []rune
	for _, r := range s {
		if string(r) == sep {
			parts = append(parts, string(buf))
			buf = []rune{}
		} else {
			buf = append(buf, r)
		}
	}
	parts = append(parts, string(buf))
	return parts
}

// Hash generates a SHA-256 hash of the input string
func Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// generateID generates a unique identifier for a proposal
func generateID() string {
	return hex.EncodeToString(randBytes(16))
}

// randBytes generates random bytes of the given length
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// SecurePassword hashes a password using Argon2
func SecurePassword(password, salt string) string {
	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// VerifyPassword verifies a password against a hash using Argon2
func VerifyPassword(password, salt, hash string) bool {
	return SecurePassword(password, salt) == hash
}
