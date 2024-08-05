package interoperability

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

// AtomicSwap represents the atomic swap mechanism for cross-chain interoperability
type AtomicSwap struct {
	SwapID         string
	ParticipantAID string
	ParticipantBID string
	AmountA        int64
	AmountB        int64
	Timestamp      time.Time
	Status         string
	HashLock       []byte
	Secret         []byte
	lock           sync.RWMutex
}

const (
	SwapActive   = "ACTIVE"
	SwapExpired  = "EXPIRED"
	SwapComplete = "COMPLETE"
)

// NewAtomicSwap initializes a new AtomicSwap instance
func NewAtomicSwap(swapID, participantAID, participantBID string, amountA, amountB int64, secret []byte) *AtomicSwap {
	hashLock := sha256.Sum256(secret)
	return &AtomicSwap{
		SwapID:         swapID,
		ParticipantAID: participantAID,
		ParticipantBID: participantBID,
		AmountA:        amountA,
		AmountB:        amountB,
		Timestamp:      time.Now(),
		Status:         SwapActive,
		HashLock:       hashLock[:],
		Secret:         secret,
	}
}

// CompleteSwap completes the atomic swap if the secret is valid
func (as *AtomicSwap) CompleteSwap(secret []byte) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	if as.Status != SwapActive {
		return errors.New("swap is not active")
	}

	hashLock := sha256.Sum256(secret)
	if !utils.Equal(hashLock[:], as.HashLock) {
		return errors.New("invalid secret")
	}

	as.Secret = secret
	as.Status = SwapComplete
	as.Timestamp = time.Now()
	return nil
}

// ExpireSwap marks the atomic swap as expired
func (as *AtomicSwap) ExpireSwap() {
	as.lock.Lock()
	defer as.lock.Unlock()
	as.Status = SwapExpired
	as.Timestamp = time.Now()
}

// EncryptSwap encrypts the atomic swap details
func (as *AtomicSwap) EncryptSwap(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%d|%d|%s|%s|%s",
		as.SwapID, as.ParticipantAID, as.ParticipantBID, as.AmountA, as.AmountB, as.Status,
		base64.StdEncoding.EncodeToString(as.HashLock), base64.StdEncoding.EncodeToString(as.Secret))
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSwap decrypts the atomic swap details
func (as *AtomicSwap) DecryptSwap(encryptedData string, key []byte) error {
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
	if len(parts) != 8 {
		return errors.New("invalid encrypted data format")
	}

	as.SwapID = parts[0]
	as.ParticipantAID = parts[1]
	as.ParticipantBID = parts[2]
	as.AmountA = utils.ParseInt64(parts[3])
	as.AmountB = utils.ParseInt64(parts[4])
	as.Status = parts[5]
	as.HashLock, err = base64.StdEncoding.DecodeString(parts[6])
	if err != nil {
		return err
	}
	as.Secret, err = base64.StdEncoding.DecodeString(parts[7])
	if err != nil {
		return err
	}

	return nil
}

// GetSwapDetails returns the details of the atomic swap
func (as *AtomicSwap) GetSwapDetails() (string, string, int64, int64, string) {
	as.lock.RLock()
	defer as.lock.RUnlock()
	return as.ParticipantAID, as.ParticipantBID, as.AmountA, as.AmountB, as.Status
}

// UpdateTimestamp updates the timestamp of the atomic swap
func (as *AtomicSwap) UpdateTimestamp() {
	as.lock.Lock()
	defer as.lock.Unlock()
	as.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the atomic swap
func (as *AtomicSwap) GetTimestamp() time.Time {
	as.lock.RLock()
	defer as.lock.RUnlock()
	return as.Timestamp
}

// GetHashLock returns the hash lock of the atomic swap
func (as *AtomicSwap) GetHashLock() []byte {
	as.lock.RLock()
	defer as.lock.RUnlock()
	return as.HashLock
}

// ValidateSwap validates the atomic swap details
func (as *AtomicSwap) ValidateSwap() error {
	as.lock.RLock()
	defer as.lock.RUnlock()

	if as.ParticipantAID == "" || as.ParticipantBID == "" {
		return errors.New("participant IDs cannot be empty")
	}

	if as.AmountA <= 0 || as.AmountB <= 0 {
		return errors.New("amounts must be greater than zero")
	}

	if len(as.HashLock) == 0 {
		return errors.New("hash lock cannot be empty")
	}

	return nil
}
