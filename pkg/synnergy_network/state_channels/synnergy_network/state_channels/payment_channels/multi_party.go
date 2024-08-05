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

// MultiPartyPayment represents a multi-party payment channel
type MultiPartyPayment struct {
	PaymentID      string
	SenderIDs      []string
	ReceiverIDs    []string
	Amounts        map[string]int64
	Status         string
	Timestamp      time.Time
	lock           sync.RWMutex
}

const (
	MultiPartyPaymentPending   = "PENDING"
	MultiPartyPaymentCompleted = "COMPLETED"
	MultiPartyPaymentFailed    = "FAILED"
)

// NewMultiPartyPayment initializes a new MultiPartyPayment instance
func NewMultiPartyPayment(paymentID string, senderIDs, receiverIDs []string, amounts map[string]int64) *MultiPartyPayment {
	return &MultiPartyPayment{
		PaymentID:   paymentID,
		SenderIDs:   senderIDs,
		ReceiverIDs: receiverIDs,
		Amounts:     amounts,
		Status:      MultiPartyPaymentPending,
		Timestamp:   time.Now(),
	}
}

// ExecutePayment executes the multi-party payment
func (mpp *MultiPartyPayment) ExecutePayment() error {
	mpp.lock.Lock()
	defer mpp.lock.Unlock()

	if mpp.Status != MultiPartyPaymentPending {
		return errors.New("payment is not pending")
	}

	// Simulate multi-party payment execution logic
	for _, receiverID := range mpp.ReceiverIDs {
		if amount, ok := mpp.Amounts[receiverID]; !ok || amount <= 0 {
			mpp.Status = MultiPartyPaymentFailed
			return errors.New("invalid payment details")
		}
	}

	mpp.Status = MultiPartyPaymentCompleted
	mpp.Timestamp = time.Now()
	return nil
}

// EncryptPayment encrypts the payment details
func (mpp *MultiPartyPayment) EncryptPayment(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%s|%s",
		mpp.PaymentID, mpp.SenderIDs, mpp.ReceiverIDs, mpp.Amounts, mpp.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptPayment decrypts the payment details
func (mpp *MultiPartyPayment) DecryptPayment(encryptedData string, key []byte) error {
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

	mpp.PaymentID = parts[0]
	mpp.SenderIDs = utils.ParseIDs(parts[1])
	mpp.ReceiverIDs = utils.ParseIDs(parts[2])
	mpp.Amounts = utils.ParseAmounts(parts[3])
	mpp.Status = parts[4]
	return nil
}

// GetPaymentDetails returns the details of the multi-party payment
func (mpp *MultiPartyPayment) GetPaymentDetails() (string, []string, []string, map[string]int64, string) {
	mpp.lock.RLock()
	defer mpp.lock.RUnlock()
	return mpp.PaymentID, mpp.SenderIDs, mpp.ReceiverIDs, mpp.Amounts, mpp.Status
}

// ValidatePayment validates the payment details
func (mpp *MultiPartyPayment) ValidatePayment() error {
	mpp.lock.RLock()
	defer mpp.lock.RUnlock()

	if mpp.PaymentID == "" {
		return errors.New("payment ID cannot be empty")
	}

	if len(mpp.SenderIDs) == 0 || len(mpp.ReceiverIDs) == 0 || len(mpp.Amounts) == 0 {
		return errors.New("sender IDs, receiver IDs, and amounts cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the multi-party payment
func (mpp *MultiPartyPayment) UpdateTimestamp() {
	mpp.lock.Lock()
	defer mpp.lock.Unlock()
	mpp.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the multi-party payment
func (mpp *MultiPartyPayment) GetTimestamp() time.Time {
	mpp.lock.RLock()
	defer mpp.lock.RUnlock()
	return mpp.Timestamp
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

func (mpp *MultiPartyPayment) String() string {
	return fmt.Sprintf("PaymentID: %s, Status: %s, Timestamp: %s", mpp.PaymentID, mpp.Status, mpp.Timestamp)
}
