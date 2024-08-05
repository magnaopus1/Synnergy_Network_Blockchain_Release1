// game_linking.go

package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// GameType defines different types of games that can be associated with gambling tokens
type GameType string

const (
	Blackjack       GameType = "Blackjack"
	Craps                     = "Craps"
	ThreeCardPoker            = "ThreeCardPoker"
	Baccarat                  = "Baccarat"
	Slots                     = "Slots"
	Sports                   = "Sports"
	Casino                   = "Casino"
	Bingo                    = "Bingo"
	Other                    = "Other"
)

// GameLinkage represents the association between a gambling token and a game type
type GameLinkage struct {
	TokenID    string    // Unique identifier for the token
	GameType   GameType  // Type of game linked to the token
	LinkedDate time.Time // Date when the token was linked to the game
	SecureHash string    // Secure hash for verifying linkage integrity
}

// GameLinker manages the linkage between gambling tokens and game types
type GameLinker struct {
	mu       sync.RWMutex
	linkages map[string]*GameLinkage // In-memory storage of game linkages
}

// NewGameLinker creates a new instance of GameLinker
func NewGameLinker() *GameLinker {
	return &GameLinker{
		linkages: make(map[string]*GameLinkage),
	}
}

// LinkTokenToGame links a gambling token to a specific game type
func (gl *GameLinker) LinkTokenToGame(tokenID string, gameType GameType) (*GameLinkage, error) {
	gl.mu.Lock()
	defer gl.mu.Unlock()

	// Generate a unique linkage and secure hash
	linkedDate := time.Now()
	secureHash := generateLinkageSecureHash(tokenID, gameType, linkedDate)

	// Create the GameLinkage
	linkage := &GameLinkage{
		TokenID:    tokenID,
		GameType:   gameType,
		LinkedDate: linkedDate,
		SecureHash: secureHash,
	}

	// Store the linkage
	gl.linkages[tokenID] = linkage

	return linkage, nil
}

// VerifyGameLinkage verifies the integrity and authenticity of a game linkage
func (gl *GameLinker) VerifyGameLinkage(tokenID string) (bool, error) {
	gl.mu.RLock()
	defer gl.mu.RUnlock()

	linkage, exists := gl.linkages[tokenID]
	if !exists {
		return false, fmt.Errorf("game linkage not found")
	}

	expectedHash := generateLinkageSecureHash(linkage.TokenID, linkage.GameType, linkage.LinkedDate)
	return expectedHash == linkage.SecureHash, nil
}

// generateLinkageSecureHash generates a secure hash for a game linkage
func generateLinkageSecureHash(tokenID string, gameType GameType, linkedDate time.Time) string {
	hash := sha256.New()
	hash.Write([]byte(tokenID))
	hash.Write([]byte(string(gameType)))
	hash.Write([]byte(linkedDate.String()))
	return hex.EncodeToString(hash.Sum(nil))
}
