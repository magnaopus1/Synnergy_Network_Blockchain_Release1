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

// AtomicMultiPayment represents an atomic multi-payment channel
type AtomicMultiPayment struct {
	PaymentID      string
	SenderID       string
	ReceiverIDs    []string
	Amounts        map[string]int64
	Status         string
	Timestamp      time.Time
	lock           sync.RWMutex
}

const (
	PaymentPending = "PENDING"
	PaymentCompleted = "COMPLETED"
	PaymentFailed = "FAILED"
)

// NewAtomicMultiPayment initializes a new AtomicMultiPayment instance
func NewAtomicMultiPayment(paymentID, senderID string, receiverIDs []string, amounts map[string]int64) *AtomicMultiPayment {
	return &AtomicMultiPayment{
		PaymentID:   paymentID,
		SenderID:    senderID,
		ReceiverIDs: receiverIDs,
		Amounts:     amounts,
		Status:      PaymentPending,
		Timestamp:   time.Now(),
	}
}

// ExecutePayment executes the atomic multi-payment
func (amp *AtomicMultiPayment) ExecutePayment() error {
	amp.lock.Lock()
	defer amp.lock.Unlock()

	if amp.Status != PaymentPending {
		return errors.New("payment is not pending")
	}

	// Simulate payment execution logic
	for _, receiverID := range amp.ReceiverIDs {
		if amount, ok := amp.Amounts[receiverID]; !ok || amount <= 0 {
			amp.Status = PaymentFailed
			return errors.New("invalid payment details")
		}
	}

	amp.Status = PaymentCompleted
	amp.Timestamp = time.Now()
	return nil
}

// EncryptPayment encrypts the payment details
func (amp *AtomicMultiPayment) EncryptPayment(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%s",
		amp.PaymentID, amp.SenderID, amp.Amounts, amp.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptPayment decrypts the payment details
func (amp *AtomicMultiPayment) DecryptPayment(encryptedData string, key []byte) error {
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
	if len(parts) != 4 {
		return errors.New("invalid encrypted data format")
	}

	amp.PaymentID = parts[0]
	amp.SenderID = parts[1]
	amp.Amounts = utils.ParseAmounts(parts[2])
	amp.Status = parts[3]
	return nil
}

// GetPaymentDetails returns the details of the atomic multi-payment
func (amp *AtomicMultiPayment) GetPaymentDetails() (string, string, map[string]int64, string) {
	amp.lock.RLock()
	defer amp.lock.RUnlock()
	return amp.PaymentID, amp.SenderID, amp.Amounts, amp.Status
}

// ValidatePayment validates the payment details
func (amp *AtomicMultiPayment) ValidatePayment() error {
	amp.lock.RLock()
	defer amp.lock.RUnlock()

	if amp.PaymentID == "" || amp.SenderID == "" {
		return errors.New("payment ID and sender ID cannot be empty")
	}

	if len(amp.ReceiverIDs) == 0 || len(amp.Amounts) == 0 {
		return errors.New("receiver IDs and amounts cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the atomic multi-payment
func (amp *AtomicMultiPayment) UpdateTimestamp() {
	amp.lock.Lock()
	defer amp.lock.Unlock()
	amp.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the atomic multi-payment
func (amp *AtomicMultiPayment) GetTimestamp() time.Time {
	amp.lock.RLock()
	defer amp.lock.RUnlock()
	return amp.Timestamp
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

func (amp *AtomicMultiPayment) String() string {
	return fmt.Sprintf("PaymentID: %s, Status: %s, Timestamp: %s", amp.PaymentID, amp.Status, amp.Timestamp)
}
