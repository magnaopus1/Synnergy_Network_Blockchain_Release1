package gamification

import (
	"encoding/json"
	"fmt"
	"time"
	"math/rand"

	"github.com/synthron_blockchain_final/pkg/layer0/blockchain"
	"golang.org/x/crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"errors"
)

// CommunityChallenge represents a community challenge for sustainability initiatives.
type CommunityChallenge struct {
	ChallengeID      string   `json:"challenge_id"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	StartDate        string   `json:"start_date"`
	EndDate          string   `json:"end_date"`
	Participants     []string `json:"participants"`
	Rewards          int      `json:"rewards"`
	CurrentProgress  float64  `json:"current_progress"`
	Target           float64  `json:"target"`
	Status           string   `json:"status"`
}

// NewCommunityChallenge creates a new community challenge.
func NewCommunityChallenge(name, description string, startDate, endDate string, target float64, rewards int) *CommunityChallenge {
	return &CommunityChallenge{
		ChallengeID:     fmt.Sprintf("challenge-%d", rand.Int()),
		Name:            name,
		Description:     description,
		StartDate:       startDate,
		EndDate:         endDate,
		Participants:    []string{},
		Rewards:         rewards,
		CurrentProgress: 0,
		Target:          target,
		Status:          "Active",
	}
}

// AddParticipant adds a participant to the community challenge.
func (challenge *CommunityChallenge) AddParticipant(participantID string) {
	challenge.Participants = append(challenge.Participants, participantID)
}

// UpdateProgress updates the progress of the community challenge.
func (challenge *CommunityChallenge) UpdateProgress(progress float64) {
	challenge.CurrentProgress += progress
	if challenge.CurrentProgress >= challenge.Target {
		challenge.Status = "Completed"
	} else {
		challenge.Status = "Active"
	}
}

// SaveChallenge saves the community challenge to the blockchain.
func (challenge *CommunityChallenge) SaveChallenge() error {
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		return err
	}
	return blockchain.PutState(challenge.ChallengeID, challengeJSON)
}

// GetChallenge retrieves a community challenge from the blockchain.
func GetChallenge(challengeID string) (*CommunityChallenge, error) {
	challengeJSON, err := blockchain.GetState(challengeID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if challengeJSON == nil {
		return nil, fmt.Errorf("the challenge %s does not exist", challengeID)
	}

	var challenge CommunityChallenge
	err = json.Unmarshal(challengeJSON, &challenge)
	if err != nil {
		return nil, err
	}

	return &challenge, nil
}

// ListAllChallenges lists all community challenges.
func ListAllChallenges() ([]CommunityChallenge, error) {
	// Placeholder for a method to list all community challenges.
	// This would typically involve querying the blockchain ledger for all challenge records.
	// For now, we return an empty list.
	return []CommunityChallenge{}, nil
}

// RewardParticipants rewards participants of a completed challenge.
func (challenge *CommunityChallenge) RewardParticipants() error {
	if challenge.Status != "Completed" {
		return fmt.Errorf("challenge %s is not completed yet", challenge.ChallengeID)
	}

	for _, participantID := range challenge.Participants {
		// Placeholder for a method to reward participants.
		// This could involve transferring tokens or issuing certificates.
		fmt.Printf("Rewarding participant %s with %d tokens\n", participantID, challenge.Rewards)
	}

	return nil
}

// ChallengeUpdateRequest represents a request to update a community challenge.
type ChallengeUpdateRequest struct {
	ChallengeID string  `json:"challenge_id"`
	Progress    float64 `json:"progress"`
}

// HandleChallengeUpdate handles the update request for a community challenge.
func HandleChallengeUpdate(request ChallengeUpdateRequest) error {
	challenge, err := GetChallenge(request.ChallengeID)
	if err != nil {
		return err
	}

	challenge.UpdateProgress(request.Progress)
	return challenge.SaveChallenge()
}

// EncryptData encrypts data using AES.
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptData decrypts data using AES.
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 32 {
		return nil, errors.New("invalid data")
	}

	salt, ciphertext := data[:32], data[32:]

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
