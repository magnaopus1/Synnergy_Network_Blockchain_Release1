package asset_transfer_mechanisms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/scrypt"
)

// AtomicSwap represents the structure of an atomic swap transaction
type AtomicSwap struct {
	Initiator         string    // Address of the person initiating the swap
	Participant       string    // Address of the person participating in the swap
	InitiatorAmount   big.Int   // Amount from the initiator
	ParticipantAmount big.Int   // Amount from the participant
	SecretHash        []byte    // Hash of the secret for the swap
	Secret            []byte    // Secret for the swap
	CreatedAt         time.Time // Timestamp of the swap creation
	ExpiresAt         time.Time // Expiry time of the swap
}

// AtomicSwapManager manages atomic swaps
type AtomicSwapManager struct {
	swaps map[string]*AtomicSwap // In-memory store of active swaps
}

// NewAtomicSwapManager creates a new AtomicSwapManager
func NewAtomicSwapManager() *AtomicSwapManager {
	return &AtomicSwapManager{
		swaps: make(map[string]*AtomicSwap),
	}
}

// InitiateSwap initiates a new atomic swap
func (asm *AtomicSwapManager) InitiateSwap(initiator, participant string, initiatorAmount, participantAmount big.Int, secret []byte, duration time.Duration) (string, error) {
	secretHash := sha256.Sum256(secret)
	swapID := hex.EncodeToString(secretHash[:])

	// Ensure the swap ID is unique
	if _, exists := asm.swaps[swapID]; exists {
		return "", errors.New("swap with this secret already exists")
	}

	swap := &AtomicSwap{
		Initiator:         initiator,
		Participant:       participant,
		InitiatorAmount:   initiatorAmount,
		ParticipantAmount: participantAmount,
		SecretHash:        secretHash[:],
		Secret:            secret,
		CreatedAt:         time.Now(),
		ExpiresAt:         time.Now().Add(duration),
	}

	asm.swaps[swapID] = swap

	return swapID, nil
}

// RedeemSwap redeems an atomic swap by the participant
func (asm *AtomicSwapManager) RedeemSwap(swapID string, secret []byte) error {
	swap, exists := asm.swaps[swapID]
	if !exists {
		return errors.New("swap not found")
	}

	// Verify the provided secret matches the hash
	providedSecretHash := sha256.Sum256(secret)
	if !bytes.Equal(providedSecretHash[:], swap.SecretHash) {
		return errors.New("invalid secret")
	}

	// Ensure the swap has not expired
	if time.Now().After(swap.ExpiresAt) {
		return errors.New("swap has expired")
	}

	// Perform the asset transfer (mocked here)
	fmt.Printf("Transferring %s from %s to %s\n", swap.InitiatorAmount.String(), swap.Initiator, swap.Participant)
	fmt.Printf("Transferring %s from %s to %s\n", swap.ParticipantAmount.String(), swap.Participant, swap.Initiator)

	delete(asm.swaps, swapID)

	return nil
}

// RefundSwap refunds an atomic swap by the initiator after expiry
func (asm *AtomicSwapManager) RefundSwap(swapID string) error {
	swap, exists := asm.swaps[swapID]
	if !exists {
		return errors.New("swap not found")
	}

	// Ensure the swap has expired
	if time.Now().Before(swap.ExpiresAt) {
		return errors.New("swap has not expired yet")
	}

	// Perform the refund (mocked here)
	fmt.Printf("Refunding %s to %s\n", swap.InitiatorAmount.String(), swap.Initiator)

	delete(asm.swaps, swapID)

	return nil
}

// EncryptSecret encrypts a secret using AES
func EncryptSecret(secret, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, secret, nil)
	return ciphertext, nil
}

// DecryptSecret decrypts an AES encrypted secret
func DecryptSecret(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateKey derives a key using scrypt
func GenerateKey(passphrase, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(passphrase, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}
