package atomic_swaps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"time"
)

// CrossChainSwap represents a single cross-chain atomic swap.
type CrossChainSwap struct {
	ID              string
	Sender          string
	Receiver        string
	Amount          float64
	TokenFrom       string
	TokenTo         string
	HashLock        string
	SecretLock      string
	InitiatedAt     time.Time
	ExpirationTime  time.Time
	Status          string
}

// CrossChainSwapManager manages cross-chain atomic swaps.
type CrossChainSwapManager struct {
	swaps map[string]CrossChainSwap
}

// NewCrossChainSwapManager creates a new CrossChainSwapManager.
func NewCrossChainSwapManager() *CrossChainSwapManager {
	return &CrossChainSwapManager{
		swaps: make(map[string]CrossChainSwap),
	}
}

// InitiateSwap initializes a new cross-chain atomic swap.
func (ccsm *CrossChainSwapManager) InitiateSwap(sender, receiver string, amount float64, tokenFrom, tokenTo string, expirationMinutes int) (string, string, error) {
	id := generateID(sender, receiver, amount, tokenFrom, tokenTo)
	hashLock, secretLock := generateHashLocks()
	expirationTime := time.Now().Add(time.Duration(expirationMinutes) * time.Minute)

	swap := CrossChainSwap{
		ID:             id,
		Sender:         sender,
		Receiver:       receiver,
		Amount:         amount,
		TokenFrom:      tokenFrom,
		TokenTo:        tokenTo,
		HashLock:       hashLock,
		SecretLock:     secretLock,
		InitiatedAt:    time.Now(),
		ExpirationTime: expirationTime,
		Status:         "initiated",
	}

	ccsm.swaps[id] = swap
	log.Printf("Initiated cross-chain swap: %+v\n", swap)
	return id, secretLock, nil
}

// RedeemSwap redeems a cross-chain atomic swap by providing the secret.
func (ccsm *CrossChainSwapManager) RedeemSwap(id, secret string) error {
	swap, exists := ccsm.swaps[id]
	if !exists {
		return fmt.Errorf("swap with ID %s not found", id)
	}
	if swap.Status != "initiated" {
		return fmt.Errorf("swap with ID %s is not in initiated state", id)
	}
	if time.Now().After(swap.ExpirationTime) {
		return fmt.Errorf("swap with ID %s has expired", id)
	}
	if generateHash(secret) != swap.SecretLock {
		return fmt.Errorf("invalid secret for swap with ID %s", id)
	}

	swap.Status = "redeemed"
	ccsm.swaps[id] = swap
	log.Printf("Redeemed cross-chain swap: %+v\n", swap)
	return nil
}

// RefundSwap refunds a cross-chain atomic swap if it has expired.
func (ccsm *CrossChainSwapManager) RefundSwap(id string) error {
	swap, exists := ccsm.swaps[id]
	if !exists {
		return fmt.Errorf("swap with ID %s not found", id)
	}
	if swap.Status != "initiated" {
		return fmt.Errorf("swap with ID %s is not in initiated state", id)
	}
	if time.Now().Before(swap.ExpirationTime) {
		return fmt.Errorf("swap with ID %s has not expired yet", id)
	}

	swap.Status = "refunded"
	ccsm.swaps[id] = swap
	log.Printf("Refunded cross-chain swap: %+v\n", swap)
	return nil
}

// GetSwapStatus returns the status of a cross-chain swap.
func (ccsm *CrossChainSwapManager) GetSwapStatus(id string) (string, error) {
	swap, exists := ccsm.swaps[id]
	if !exists {
		return "", fmt.Errorf("swap with ID %s not found", id)
	}
	return swap.Status, nil
}

// ListSwaps returns a list of all cross-chain swaps.
func (ccsm *CrossChainSwapManager) ListSwaps() []CrossChainSwap {
	swaps := []CrossChainSwap{}
	for _, swap := range ccsm.swaps {
		swaps = append(swaps, swap)
	}
	return swaps
}

// generateID generates a unique ID for a swap.
func generateID(sender, receiver string, amount float64, tokenFrom, tokenTo string) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s:%s:%f:%s:%s:%d", sender, receiver, amount, tokenFrom, tokenTo, time.Now().UnixNano())))
	return hex.EncodeToString(hash.Sum(nil))
}

// generateHashLocks generates a hash lock and a corresponding secret.
func generateHashLocks() (string, string) {
	secret := generateRandomString(32)
	hashLock := generateHash(secret)
	return hashLock, secret
}

// generateHash generates a SHA-256 hash of the input.
func generateHash(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}

// generateRandomString generates a random string of specified length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}
