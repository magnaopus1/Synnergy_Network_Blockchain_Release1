package privacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"github.com/synnergy_network/utils"
)

const (
	TransactionPending   = "PENDING"
	TransactionCompleted = "COMPLETED"
	TransactionFailed    = "FAILED"
)

// ConfidentialTransaction represents a confidential transaction
type ConfidentialTransaction struct {
	TransactionID string
	SenderID      string
	ReceiverID    string
	Amount        float64
	Status        string
	Timestamp     time.Time
	lock          sync.RWMutex
}

// NewConfidentialTransaction initializes a new ConfidentialTransaction instance
func NewConfidentialTransaction(transactionID, senderID, receiverID string, amount float64) *ConfidentialTransaction {
	return &ConfidentialTransaction{
		TransactionID: transactionID,
		SenderID:      senderID,
		ReceiverID:    receiverID,
		Amount:        amount,
		Status:        TransactionPending,
		Timestamp:     time.Now(),
	}
}

// CompleteTransaction marks the transaction as completed
func (ct *ConfidentialTransaction) CompleteTransaction() error {
	ct.lock.Lock()
	defer ct.lock.Unlock()

	if ct.Status != TransactionPending {
		return errors.New("transaction is not pending")
	}

	ct.Status = TransactionCompleted
	ct.Timestamp = time.Now()
	return nil
}

// FailTransaction marks the transaction as failed
func (ct *ConfidentialTransaction) FailTransaction() error {
	ct.lock.Lock()
	defer ct.lock.Unlock()

	if ct.Status != TransactionPending {
		return errors.New("transaction is not pending")
	}

	ct.Status = TransactionFailed
	ct.Timestamp = time.Now()
	return nil
}

// EncryptTransaction encrypts the transaction details
func (ct *ConfidentialTransaction) EncryptTransaction(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%f|%s|%s",
		ct.TransactionID, ct.SenderID, ct.ReceiverID, ct.Amount, ct.Status, ct.Timestamp)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptTransaction decrypts the transaction details
func (ct *ConfidentialTransaction) DecryptTransaction(encryptedData string, key []byte) error {
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
	if len(parts) != 6 {
		return errors.New("invalid encrypted data format")
	}

	ct.TransactionID = parts[0]
	ct.SenderID = parts[1]
	ct.ReceiverID = parts[2]
	ct.Amount = utils.ParseFloat(parts[3])
	ct.Status = parts[4]
	ct.Timestamp = utils.ParseTime(parts[5])
	return nil
}

// GenerateKey generates a cryptographic key using Argon2 or Scrypt
func GenerateKey(password, salt []byte, useArgon2 bool) ([]byte, error) {
	if useArgon2 {
		return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
	}

	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
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

func (ct *ConfidentialTransaction) String() string {
	return fmt.Sprintf("TransactionID: %s, Amount: %f, Status: %s, Timestamp: %s",
		ct.TransactionID, ct.Amount, ct.Status, ct.Timestamp)
}
