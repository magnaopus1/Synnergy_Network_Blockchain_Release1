package gamification

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
	"github.com/synthron_blockchain_final/pkg/layer0/blockchain"
	"time"
)

// SustainabilityGame represents a game to promote sustainability.
type SustainabilityGame struct {
	GameID        string   `json:"game_id"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	StartDate     string   `json:"start_date"`
	EndDate       string   `json:"end_date"`
	Participants  []string `json:"participants"`
	Rewards       int      `json:"rewards"`
	CurrentPoints map[string]int `json:"current_points"`
	TargetPoints  int      `json:"target_points"`
	Status        string   `json:"status"`
}

// NewSustainabilityGame creates a new sustainability game.
func NewSustainabilityGame(name, description string, startDate, endDate string, targetPoints int, rewards int) *SustainabilityGame {
	return &SustainabilityGame{
		GameID:        fmt.Sprintf("game-%d", rand.Int()),
		Name:          name,
		Description:   description,
		StartDate:     startDate,
		EndDate:       endDate,
		Participants:  []string{},
		Rewards:       rewards,
		CurrentPoints: make(map[string]int),
		TargetPoints:  targetPoints,
		Status:        "Active",
	}
}

// AddParticipant adds a participant to the sustainability game.
func (game *SustainabilityGame) AddParticipant(participantID string) {
	game.Participants = append(game.Participants, participantID)
	game.CurrentPoints[participantID] = 0
}

// UpdatePoints updates the points of a participant in the sustainability game.
func (game *SustainabilityGame) UpdatePoints(participantID string, points int) error {
	if _, exists := game.CurrentPoints[participantID]; !exists {
		return fmt.Errorf("participant %s is not part of the game", participantID)
	}
	game.CurrentPoints[participantID] += points
	if game.CurrentPoints[participantID] >= game.TargetPoints {
		game.Status = "Completed"
	}
	return nil
}

// SaveGame saves the sustainability game to the blockchain.
func (game *SustainabilityGame) SaveGame() error {
	gameJSON, err := json.Marshal(game)
	if err != nil {
		return err
	}
	return blockchain.PutState(game.GameID, gameJSON)
}

// GetGame retrieves a sustainability game from the blockchain.
func GetGame(gameID string) (*SustainabilityGame, error) {
	gameJSON, err := blockchain.GetState(gameID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if gameJSON == nil {
		return nil, fmt.Errorf("the game %s does not exist", gameID)
	}

	var game SustainabilityGame
	err = json.Unmarshal(gameJSON, &game)
	if err != nil {
		return nil, err
	}

	return &game, nil
}

// ListAllGames lists all sustainability games.
func ListAllGames() ([]SustainabilityGame, error) {
	// Placeholder for a method to list all sustainability games.
	// This would typically involve querying the blockchain ledger for all game records.
	// For now, we return an empty list.
	return []SustainabilityGame{}, nil
}

// RewardParticipants rewards participants of a completed game.
func (game *SustainabilityGame) RewardParticipants() error {
	if game.Status != "Completed" {
		return fmt.Errorf("game %s is not completed yet", game.GameID)
	}

	for participantID, points := range game.CurrentPoints {
		// Placeholder for a method to reward participants.
		// This could involve transferring tokens or issuing certificates.
		fmt.Printf("Rewarding participant %s with %d tokens for %d points\n", participantID, game.Rewards, points)
	}

	return nil
}

// GameUpdateRequest represents a request to update a sustainability game.
type GameUpdateRequest struct {
	GameID       string `json:"game_id"`
	ParticipantID string `json:"participant_id"`
	Points       int    `json:"points"`
}

// HandleGameUpdate handles the update request for a sustainability game.
func HandleGameUpdate(request GameUpdateRequest) error {
	game, err := GetGame(request.GameID)
	if err != nil {
		return err
	}

	err = game.UpdatePoints(request.ParticipantID, request.Points)
	if err != nil {
		return err
	}
	return game.SaveGame()
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
