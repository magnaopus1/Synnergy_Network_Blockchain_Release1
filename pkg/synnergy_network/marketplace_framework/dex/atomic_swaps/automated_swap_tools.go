package atomic_swaps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"time"
)

// Swap represents a single atomic swap.
type Swap struct {
	ID              string
	Sender          string
	Receiver        string
	Amount          float64
	Token           string
	HashLock        string
	SecretLock      string
	InitiatedAt     time.Time
	ExpirationTime  time.Time
	Status          string
}

// SwapManager manages atomic swaps.
type SwapManager struct {
	swaps map[string]Swap
}

// NewSwapManager creates a new SwapManager.
func NewSwapManager() *SwapManager {
	return &SwapManager{
		swaps: make(map[string]Swap),
	}
}

// InitiateSwap initializes a new atomic swap.
func (sm *SwapManager) InitiateSwap(sender, receiver string, amount float64, token string, expirationMinutes int) (string, string, error) {
	id := generateID(sender, receiver, amount, token)
	hashLock, secretLock := generateHashLocks()
	expirationTime := time.Now().Add(time.Duration(expirationMinutes) * time.Minute)

	swap := Swap{
		ID:             id,
		Sender:         sender,
		Receiver:       receiver,
		Amount:         amount,
		Token:          token,
		HashLock:       hashLock,
		SecretLock:     secretLock,
		InitiatedAt:    time.Now(),
		ExpirationTime: expirationTime,
		Status:         "initiated",
	}

	sm.swaps[id] = swap
	log.Printf("Initiated swap: %+v\n", swap)
	return id, secretLock, nil
}

// RedeemSwap redeems an atomic swap by providing the secret.
func (sm *SwapManager) RedeemSwap(id, secret string) error {
	swap, exists := sm.swaps[id]
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
	sm.swaps[id] = swap
	log.Printf("Redeemed swap: %+v\n", swap)
	return nil
}

// RefundSwap refunds an atomic swap if it has expired.
func (sm *SwapManager) RefundSwap(id string) error {
	swap, exists := sm.swaps[id]
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
	sm.swaps[id] = swap
	log.Printf("Refunded swap: %+v\n", swap)
	return nil
}

// GetSwapStatus returns the status of a swap.
func (sm *SwapManager) GetSwapStatus(id string) (string, error) {
	swap, exists := sm.swaps[id]
	if !exists {
		return "", fmt.Errorf("swap with ID %s not found", id)
	}
	return swap.Status, nil
}

// ListSwaps returns a list of all swaps.
func (sm *SwapManager) ListSwaps() []Swap {
	swaps := []Swap{}
	for _, swap := range sm.swaps {
		swaps = append(swaps, swap)
	}
	return swaps
}

// generateID generates a unique ID for a swap.
func generateID(sender, receiver string, amount float64, token string) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s:%s:%f:%s:%d", sender, receiver, amount, token, time.Now().UnixNano())))
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
