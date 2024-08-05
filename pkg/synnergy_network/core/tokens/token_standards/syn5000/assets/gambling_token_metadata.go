// gambling_token_metadata.go

package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"golang.org/x/crypto/argon2"
	"math/rand"
	"sync"
)

// GamblingToken represents a gambling token with associated metadata
type Syn5000Token struct {
	TokenID        string    // Unique identifier for the token
	GameType       string    // Type of game associated with the token
	Amount         float64   // Amount or value associated with the token
	Owner          string    // Owner's identifier (e.g., wallet address)
	IssuedDate     time.Time // Date when the token was issued
	ExpiryDate     time.Time // Date when the token expires
	Active         bool      // Status of the token (active/inactive)
	TransactionHistory []TransactionRecord // History of transactions involving this token
	SecureHash     string    // Secure hash for verifying token integrity
}

// TransactionRecord represents a record of a transaction involving a gambling token
type TransactionRecord struct {
	TransactionID string    // Unique identifier for the transaction
	Timestamp     time.Time // Time when the transaction occurred
	Amount        float64   // Amount transferred in the transaction
	Description   string    // Description of the transaction
	SecureHash    string    // Secure hash for transaction integrity
}

// TokenManager manages gambling tokens and their metadata
type TokenManager struct {
	mu            sync.RWMutex
	tokens        map[string]*GamblingToken // In-memory storage of tokens
	ownerIndex    map[string][]string       // Index of tokens by owner
}

// NewTokenManager creates a new instance of TokenManager
func NewTokenManager() *TokenManager {
	return &TokenManager{
		tokens:     make(map[string]*GamblingToken),
		ownerIndex: make(map[string][]string),
	}
}

// CreateToken generates a new gambling token with provided metadata
func (tm *TokenManager) CreateToken(gameType string, amount float64, owner string, expiryDate time.Time) (*GamblingToken, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Generate a unique TokenID and SecureHash
	tokenID := generateUniqueID()
	issuedDate := time.Now()
	secureHash := generateSecureHash(tokenID, gameType, amount, owner, issuedDate, expiryDate)

	// Create the GamblingToken
	token := &GamblingToken{
		TokenID:    tokenID,
		GameType:   gameType,
		Amount:     amount,
		Owner:      owner,
		IssuedDate: issuedDate,
		ExpiryDate: expiryDate,
		Active:     true,
		SecureHash: secureHash,
	}

	// Store the token and update the owner index
	tm.tokens[tokenID] = token
	tm.ownerIndex[owner] = append(tm.ownerIndex[owner], tokenID)

	return token, nil
}

// TransferToken transfers ownership of a gambling token to another user
func (tm *TokenManager) TransferToken(tokenID, newOwner string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	token, exists := tm.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token not found")
	}
	if !token.Active {
		return fmt.Errorf("token is inactive")
	}

	// Update ownership and secure hash
	oldOwner := token.Owner
	token.Owner = newOwner
	token.SecureHash = generateSecureHash(token.TokenID, token.GameType, token.Amount, newOwner, token.IssuedDate, token.ExpiryDate)

	// Update the owner index
	tm.ownerIndex[oldOwner] = removeFromSlice(tm.ownerIndex[oldOwner], tokenID)
	tm.ownerIndex[newOwner] = append(tm.ownerIndex[newOwner], tokenID)

	return nil
}

// VerifyToken verifies the integrity and ownership of a gambling token
func (tm *TokenManager) VerifyToken(tokenID string) (bool, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	token, exists := tm.tokens[tokenID]
	if !exists {
		return false, fmt.Errorf("token not found")
	}

	expectedHash := generateSecureHash(token.TokenID, token.GameType, token.Amount, token.Owner, token.IssuedDate, token.ExpiryDate)
	return expectedHash == token.SecureHash, nil
}

// Generate a unique ID for a new token
func generateUniqueID() string {
	return hex.EncodeToString(argon2.IDKey([]byte(time.Now().String()), []byte(fmt.Sprintf("%d", rand.Int())), 1, 64*1024, 4, 32))
}

// Generate a secure hash for a token
func generateSecureHash(tokenID, gameType string, amount float64, owner string, issuedDate, expiryDate time.Time) string {
	hash := sha256.New()
	hash.Write([]byte(tokenID))
	hash.Write([]byte(gameType))
	hash.Write([]byte(fmt.Sprintf("%f", amount)))
	hash.Write([]byte(owner))
	hash.Write([]byte(issuedDate.String()))
	hash.Write([]byte(expiryDate.String()))
	return hex.EncodeToString(hash.Sum(nil))
}

// Remove a token ID from a slice of tokens
func removeFromSlice(slice []string, tokenID string) []string {
	for i, id := range slice {
		if id == tokenID {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
