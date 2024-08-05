package payment_channels

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// Escrow represents an escrow payment channel
type Escrow struct {
	EscrowID    string
	SenderID    string
	ReceiverID  string
	Amount      int64
	Status      string
	Timestamp   time.Time
	lock        sync.RWMutex
}

const (
	EscrowPending   = "PENDING"
	EscrowCompleted = "COMPLETED"
	EscrowFailed    = "FAILED"
	EscrowReleased  = "RELEASED"
)

// NewEscrow initializes a new Escrow instance
func NewEscrow(escrowID, senderID, receiverID string, amount int64) *Escrow {
	return &Escrow{
		EscrowID:   escrowID,
		SenderID:   senderID,
		ReceiverID: receiverID,
		Amount:     amount,
		Status:     EscrowPending,
		Timestamp:  time.Now(),
	}
}

// ReleaseEscrow releases the escrow payment to the receiver
func (e *Escrow) ReleaseEscrow() error {
	e.lock.Lock()
	defer e.lock.Unlock()

	if e.Status != EscrowPending {
		return errors.New("escrow is not pending")
	}

	// Simulate escrow release logic
	if e.Amount <= 0 {
		e.Status = EscrowFailed
		return errors.New("invalid escrow amount")
	}

	e.Status = EscrowReleased
	e.Timestamp = time.Now()
	return nil
}

// CompleteEscrow completes the escrow payment
func (e *Escrow) CompleteEscrow() error {
	e.lock.Lock()
	defer e.lock.Unlock()

	if e.Status != EscrowReleased {
		return errors.New("escrow is not released")
	}

	e.Status = EscrowCompleted
	e.Timestamp = time.Now()
	return nil
}

// EncryptEscrow encrypts the escrow details
func (e *Escrow) EncryptEscrow(key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	data := fmt.Sprintf("%s|%s|%s|%d|%s",
		e.EscrowID, e.SenderID, e.ReceiverID, e.Amount, e.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptEscrow decrypts the escrow details
func (e *Escrow) DecryptEscrow(encryptedData string, key []byte) error {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	parts := utils.Split(string(data), '|')
	if len(parts) != 5 {
		return errors.New("invalid encrypted data format")
	}

	e.EscrowID = parts[0]
	e.SenderID = parts[1]
	e.ReceiverID = parts[2]
	e.Amount = utils.ParseAmount(parts[3])
	e.Status = parts[4]
	return nil
}

// GetEscrowDetails returns the details of the escrow
func (e *Escrow) GetEscrowDetails() (string, string, string, int64, string) {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return e.EscrowID, e.SenderID, e.ReceiverID, e.Amount, e.Status
}

// ValidateEscrow validates the escrow details
func (e *Escrow) ValidateEscrow() error {
	e.lock.RLock()
	defer e.lock.RUnlock()

	if e.EscrowID == "" || e.SenderID == "" || e.ReceiverID == "" {
		return errors.New("escrow ID, sender ID, and receiver ID cannot be empty")
	}

	if e.Amount <= 0 {
		return errors.New("amount must be greater than zero")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the escrow
func (e *Escrow) UpdateTimestamp() {
	e.lock.Lock()
	defer e.lock.Unlock()
	e.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the escrow
func (e *Escrow) GetTimestamp() time.Time {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return e.Timestamp
}

// GenerateKey generates a cryptographic key using Argon2
func GenerateKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// GenerateSalt generates a cryptographic salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// HashData hashes the data using SHA-256
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (e *Escrow) String() string {
	return fmt.Sprintf("EscrowID: %s, Status: %s, Timestamp: %s", e.EscrowID, e.Status, e.Timestamp)
}
