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

// Micropayment represents a micropayment channel
type Micropayment struct {
	PaymentID  string
	SenderID   string
	ReceiverID string
	Amount     int64
	Status     string
	Timestamp  time.Time
	lock       sync.RWMutex
}

const (
	MicropaymentPending   = "PENDING"
	MicropaymentCompleted = "COMPLETED"
	MicropaymentFailed    = "FAILED"
)

// NewMicropayment initializes a new Micropayment instance
func NewMicropayment(paymentID, senderID, receiverID string, amount int64) *Micropayment {
	return &Micropayment{
		PaymentID:  paymentID,
		SenderID:   senderID,
		ReceiverID: receiverID,
		Amount:     amount,
		Status:     MicropaymentPending,
		Timestamp:  time.Now(),
	}
}

// ExecuteMicropayment executes the micropayment
func (mp *Micropayment) ExecuteMicropayment() error {
	mp.lock.Lock()
	defer mp.lock.Unlock()

	if mp.Status != MicropaymentPending {
		return errors.New("micropayment is not pending")
	}

	// Simulate micropayment execution logic
	if mp.Amount <= 0 {
		mp.Status = MicropaymentFailed
		return errors.New("invalid micropayment amount")
	}

	mp.Status = MicropaymentCompleted
	mp.Timestamp = time.Now()
	return nil
}

// EncryptMicropayment encrypts the micropayment details
func (mp *Micropayment) EncryptMicropayment(key []byte) (string, error) {
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
		mp.PaymentID, mp.SenderID, mp.ReceiverID, mp.Amount, mp.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptMicropayment decrypts the micropayment details
func (mp *Micropayment) DecryptMicropayment(encryptedData string, key []byte) error {
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

	mp.PaymentID = parts[0]
	mp.SenderID = parts[1]
	mp.ReceiverID = parts[2]
	mp.Amount = utils.ParseAmount(parts[3])
	mp.Status = parts[4]
	return nil
}

// GetMicropaymentDetails returns the details of the micropayment
func (mp *Micropayment) GetMicropaymentDetails() (string, string, string, int64, string) {
	mp.lock.RLock()
	defer mp.lock.RUnlock()
	return mp.PaymentID, mp.SenderID, mp.ReceiverID, mp.Amount, mp.Status
}

// ValidateMicropayment validates the micropayment details
func (mp *Micropayment) ValidateMicropayment() error {
	mp.lock.RLock()
	defer mp.lock.RUnlock()

	if mp.PaymentID == "" || mp.SenderID == "" || mp.ReceiverID == "" {
		return errors.New("payment ID, sender ID, and receiver ID cannot be empty")
	}

	if mp.Amount <= 0 {
		return errors.New("amount must be greater than zero")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the micropayment
func (mp *Micropayment) UpdateTimestamp() {
	mp.lock.Lock()
	defer mp.lock.Unlock()
	mp.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the micropayment
func (mp *Micropayment) GetTimestamp() time.Time {
	mp.lock.RLock()
	defer mp.lock.RUnlock()
	return mp.Timestamp
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

func (mp *Micropayment) String() string {
	return fmt.Sprintf("PaymentID: %s, Status: %s, Timestamp: %s", mp.PaymentID, mp.Status, mp.Timestamp)
}
