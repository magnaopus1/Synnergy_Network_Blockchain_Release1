package testnet_faucet

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/scrypt"
)

const (
	rateLimit       = 5                   // requests per minute
	tokenExpiration = time.Hour * 24      // token expiration duration
	saltSize        = 32                  // salt size for hashing
	scryptN         = 32768               // scrypt parameter N
	scryptR         = 8                   // scrypt parameter R
	scryptP         = 1                   // scrypt parameter P
	privateKeySize  = 2048                // size of RSA private key
)

// FaucetService provides methods for dispensing test coins.
type FaucetService struct {
	mu            sync.Mutex
	requests      map[string]time.Time
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	issuedTokens  map[string]time.Time
	dispenseLimit int
	coinAmount    int
}

// NewFaucetService initializes a new FaucetService.
func NewFaucetService(dispenseLimit, coinAmount int) (*FaucetService, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, privateKeySize)
	if err != nil {
		return nil, err
	}
	service := &FaucetService{
		requests:      make(map[string]time.Time),
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
		issuedTokens:  make(map[string]time.Time),
		dispenseLimit: dispenseLimit,
		coinAmount:    coinAmount,
	}
	return service, nil
}

// DispenseCoins handles coin dispensing requests.
func (fs *FaucetService) DispenseCoins(w http.ResponseWriter, r *http.Request) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	ip := r.RemoteAddr
	if !fs.validateRateLimit(ip) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	userID, err := fs.authenticateUser(r)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	if !fs.validateDispenseLimit(userID) {
		http.Error(w, "Dispense limit reached", http.StatusForbidden)
		return
	}

	txID, err := fs.sendCoins(userID)
	if err != nil {
		http.Error(w, "Failed to dispense coins", http.StatusInternalServerError)
		return
	}

	fs.recordDispense(userID)
	fs.recordRequest(ip)

	response := fmt.Sprintf("Dispensed %d SYNN to user %s. Transaction ID: %s", fs.coinAmount, userID, txID)
	w.Write([]byte(response))
}

// validateRateLimit checks if the IP has exceeded the rate limit.
func (fs *FaucetService) validateRateLimit(ip string) bool {
	now := time.Now()
	if lastRequest, exists := fs.requests[ip]; exists {
		if now.Sub(lastRequest).Minutes() < 1.0/rateLimit {
			return false
		}
	}
	fs.requests[ip] = now
	return true
}

// authenticateUser authenticates the user based on JWT token.
func (fs *FaucetService) authenticateUser(r *http.Request) (string, error) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		return "", errors.New("missing token")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return fs.publicKey, nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["sub"].(string), nil
	}
	return "", errors.New("invalid token")
}

// validateDispenseLimit checks if the user has reached the dispense limit.
func (fs *FaucetService) validateDispenseLimit(userID string) bool {
	if dispenseTime, exists := fs.issuedTokens[userID]; exists {
		if time.Since(dispenseTime) < tokenExpiration {
			return false
		}
	}
	return true
}

// sendCoins sends the specified amount of coins to the user.
func (fs *FaucetService) sendCoins(userID string) (string, error) {
	// Implement the logic to send coins. This is a placeholder for the actual blockchain transaction.
	txID := generateTransactionID()
	log.Printf("Sending %d SYNN to user %s. Transaction ID: %s", fs.coinAmount, userID, txID)
	return txID, nil
}

// recordDispense records the dispense time for the user.
func (fs *FaucetService) recordDispense(userID string) {
	fs.issuedTokens[userID] = time.Now()
}

// recordRequest records the request time for the IP.
func (fs *FaucetService) recordRequest(ip string) {
	fs.requests[ip] = time.Now()
}

// generateTransactionID generates a random transaction ID.
func generateTransactionID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate transaction ID: %v", err)
	}
	return hex.EncodeToString(bytes)
}

// hashPassword hashes the password using scrypt.
func hashPassword(password, salt string) (string, error) {
	dk, err := scrypt.Key([]byte(password), []byte(salt), scryptN, scryptR, scryptP, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(dk), nil
}

// validatePassword validates the password against the stored hash.
func validatePassword(password, hash, salt string) bool {
	computedHash, err := hashPassword(password, salt)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		return false
	}
	return computedHash == hash
}
