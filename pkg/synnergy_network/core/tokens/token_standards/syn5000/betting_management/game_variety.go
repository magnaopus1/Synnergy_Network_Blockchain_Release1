// game_variety.go

package betting_management

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// GameType represents different types of gambling games supported by the platform
type GameType string

const (
	GameBlackjack      GameType = "Blackjack"
	GameCraps                    = "Craps"
	GameThreeCardPoker           = "ThreeCardPoker"
	GameBaccarat                 = "Baccarat"
	GameSlots                    = "Slots"
	GameSportsBetting            = "SportsBetting"
	GameCasino                   = "Casino"
	GameBingo                    = "Bingo"
	GamePredictionMarket         = "PredictionMarket"
	// Additional game types can be added here
)

// Game represents a specific game with associated metadata
type Game struct {
	GameID       string    // Unique identifier for the game
	GameType     GameType  // Type of game
	Description  string    // Description of the game
	CreationTime time.Time // Time when the game was registered
	SecureHash   string    // Secure hash for verifying game integrity
}

// GameManager manages the registration and information retrieval of games
type GameManager struct {
	mu    sync.RWMutex
	games map[string]*Game // In-memory storage of games
}

// NewGameManager creates a new instance of GameManager
func NewGameManager() *GameManager {
	return &GameManager{
		games: make(map[string]*Game),
	}
}

// RegisterGame registers a new game with the platform
func (gm *GameManager) RegisterGame(gameType GameType, description string) (*Game, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// Generate unique GameID and secure hash
	gameID := generateUniqueID()
	creationTime := time.Now()
	secureHash := generateGameSecureHash(gameID, gameType, description, creationTime)

	// Create the Game instance
	game := &Game{
		GameID:       gameID,
		GameType:     gameType,
		Description:  description,
		CreationTime: creationTime,
		SecureHash:   secureHash,
	}

	// Store the game
	gm.games[gameID] = game

	return game, nil
}

// GetGame retrieves game details by its ID
func (gm *GameManager) GetGame(gameID string) (*Game, error) {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	game, exists := gm.games[gameID]
	if !exists {
		return nil, errors.New("game not found")
	}

	return game, nil
}

// GetAllGames returns a list of all registered games
func (gm *GameManager) GetAllGames() []*Game {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	var gamesList []*Game
	for _, game := range gm.games {
		gamesList = append(gamesList, game)
	}

	return gamesList
}

// generateUniqueID generates a unique identifier for games using Argon2
func generateUniqueID() string {
	return hex.EncodeToString(sha256.New().Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))
}

// generateGameSecureHash generates a secure hash for game verification
func generateGameSecureHash(gameID string, gameType GameType, description string, creationTime time.Time) string {
	hash := sha256.New()
	hash.Write([]byte(gameID))
	hash.Write([]byte(string(gameType)))
	hash.Write([]byte(description))
	hash.Write([]byte(creationTime.String()))
	return hex.EncodeToString(hash.Sum(nil))
}
