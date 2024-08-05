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

// PaymentChannel represents a general payment channel
type PaymentChannel struct {
	ChannelID     string
	SenderID      string
	ReceiverID    string
	Amount        int64
	Status        string
	Timestamp     time.Time
	lock          sync.RWMutex
}

const (
	PaymentChannelPending   = "PENDING"
	PaymentChannelCompleted = "COMPLETED"
	PaymentChannelFailed    = "FAILED"
)

// NewPaymentChannel initializes a new PaymentChannel instance
func NewPaymentChannel(channelID, senderID, receiverID string, amount int64) *PaymentChannel {
	return &PaymentChannel{
		ChannelID:   channelID,
		SenderID:    senderID,
		ReceiverID:  receiverID,
		Amount:      amount,
		Status:      PaymentChannelPending,
		Timestamp:   time.Now(),
	}
}

// ExecutePayment executes the payment in the payment channel
func (pc *PaymentChannel) ExecutePayment() error {
	pc.lock.Lock()
	defer pc.lock.Unlock()

	if pc.Status != PaymentChannelPending {
		return errors.New("payment is not pending")
	}

	// Simulate payment execution logic
	if pc.Amount <= 0 {
		pc.Status = PaymentChannelFailed
		return errors.New("invalid payment amount")
	}

	pc.Status = PaymentChannelCompleted
	pc.Timestamp = time.Now()
	return nil
}

// EncryptPaymentChannel encrypts the payment channel details
func (pc *PaymentChannel) EncryptPaymentChannel(key []byte) (string, error) {
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
		pc.ChannelID, pc.SenderID, pc.ReceiverID, pc.Amount, pc.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptPaymentChannel decrypts the payment channel details
func (pc *PaymentChannel) DecryptPaymentChannel(encryptedData string, key []byte) error {
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

	pc.ChannelID = parts[0]
	pc.SenderID = parts[1]
	pc.ReceiverID = parts[2]
	pc.Amount = utils.ParseAmount(parts[3])
	pc.Status = parts[4]
	return nil
}

// GetPaymentChannelDetails returns the details of the payment channel
func (pc *PaymentChannel) GetPaymentChannelDetails() (string, string, string, int64, string) {
	pc.lock.RLock()
	defer pc.lock.RUnlock()
	return pc.ChannelID, pc.SenderID, pc.ReceiverID, pc.Amount, pc.Status
}

// ValidatePaymentChannel validates the payment channel details
func (pc *PaymentChannel) ValidatePaymentChannel() error {
	pc.lock.RLock()
	defer pc.lock.RUnlock()

	if pc.ChannelID == "" || pc.SenderID == "" || pc.ReceiverID == "" {
		return errors.New("channel ID, sender ID, and receiver ID cannot be empty")
	}

	if pc.Amount <= 0 {
		return errors.New("amount must be greater than zero")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the payment channel
func (pc *PaymentChannel) UpdateTimestamp() {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	pc.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the payment channel
func (pc *PaymentChannel) GetTimestamp() time.Time {
	pc.lock.RLock()
	defer pc.lock.RUnlock()
	return pc.Timestamp
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

func (pc *PaymentChannel) String() string {
	return fmt.Sprintf("ChannelID: %s, Status: %s, Timestamp: %s", pc.ChannelID, pc.Status, pc.Timestamp)
}
