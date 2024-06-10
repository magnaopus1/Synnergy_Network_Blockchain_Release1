package behavioural_incentives

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// LoyaltyToken represents a loyalty token issued to users as a reward for their positive contributions
type LoyaltyToken struct {
	TokenID      string
	UserID       string
	Value        float64
	IssuedAt     time.Time
	ExpiryDate   time.Time
}

// LoyaltyTokenManager manages the issuance, redemption, and tracking of loyalty tokens
type LoyaltyTokenManager struct {
	tokens map[string]*LoyaltyToken
	mu     sync.Mutex
}

// NewLoyaltyTokenManager initializes a new LoyaltyTokenManager
func NewLoyaltyTokenManager() *LoyaltyTokenManager {
	return &LoyaltyTokenManager{
		tokens: make(map[string]*LoyaltyToken),
	}
}

// IssueToken issues a new loyalty token to a user
func (ltm *LoyaltyTokenManager) IssueToken(userID string, value float64, expiryDuration time.Duration) (*LoyaltyToken, error) {
	if value <= 0 {
		return nil, errors.New("token value must be positive")
	}

	tokenID, err := generateTokenID()
	if err != nil {
		return nil, err
	}

	token := &LoyaltyToken{
		TokenID:    tokenID,
		UserID:     userID,
		Value:      value,
		IssuedAt:   time.Now(),
		ExpiryDate: time.Now().Add(expiryDuration),
	}

	ltm.mu.Lock()
	defer ltm.mu.Unlock()
	ltm.tokens[tokenID] = token

	fmt.Printf("Issued token %s to user %s with value %.2f\n", tokenID, userID, value)
	return token, nil
}

// RedeemToken redeems a loyalty token by its ID
func (ltm *LoyaltyTokenManager) RedeemToken(tokenID string) (*LoyaltyToken, error) {
	ltm.mu.Lock()
	defer ltm.mu.Unlock()

	token, exists := ltm.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}

	if time.Now().After(token.ExpiryDate) {
		return nil, errors.New("token has expired")
	}

	delete(ltm.tokens, tokenID)
	fmt.Printf("Redeemed token %s with value %.2f\n", tokenID, token.Value)
	return token, nil
}

// GetToken returns a loyalty token by its ID
func (ltm *LoyaltyTokenManager) GetToken(tokenID string) (*LoyaltyToken, error) {
	ltm.mu.Lock()
	defer ltm.mu.Unlock()

	token, exists := ltm.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}

	return token, nil
}

// ListTokens returns all tokens for a specific user
func (ltm *LoyaltyTokenManager) ListTokens(userID string) []*LoyaltyToken {
	ltm.mu.Lock()
	defer ltm.mu.Unlock()

	var userTokens []*LoyaltyToken
	for _, token := range ltm.tokens {
		if token.UserID == userID {
			userTokens = append(userTokens, token)
		}
	}
	return userTokens
}

// CleanExpiredTokens removes expired tokens from the system
func (ltm *LoyaltyTokenManager) CleanExpiredTokens() {
	ltm.mu.Lock()
	defer ltm.mu.Unlock()

	for tokenID, token := range ltm.tokens {
		if time.Now().After(token.ExpiryDate) {
			delete(ltm.tokens, tokenID)
			fmt.Printf("Removed expired token %s\n", tokenID)
		}
	}
}

// generateTokenID generates a unique token ID
func generateTokenID() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	hash := sha256.New()
	if _, err := hash.Write(nonce); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func main() {
	ltm := NewLoyaltyTokenManager()
	token, err := ltm.IssueToken("user1", 100.0, 30*24*time.Hour) // 30 days expiry
	if err != nil {
		fmt.Println("Error issuing token:", err)
		return
	}

	fmt.Println("Issued token:", token)

	redeemedToken, err := ltm.RedeemToken(token.TokenID)
	if err != nil {
		fmt.Println("Error redeeming token:", err)
		return
	}

	fmt.Println("Redeemed token:", redeemedToken)

	allTokens := ltm.ListTokens("user1")
	fmt.Println("All tokens for user1:", allTokens)

	ltm.CleanExpiredTokens()
}
