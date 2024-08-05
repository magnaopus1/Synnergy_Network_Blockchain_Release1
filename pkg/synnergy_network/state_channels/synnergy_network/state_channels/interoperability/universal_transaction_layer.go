package interoperability

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
	"github.com/synnergy_network/utils"
)

// UniversalTransaction represents a transaction in the universal transaction layer for cross-chain interoperability
type UniversalTransaction struct {
	TransactionID  string
	SourceChainID  string
	DestinationChainID string
	SenderID       string
	ReceiverID     string
	Amount         int64
	Timestamp      time.Time
	Status         string
	lock           sync.RWMutex
}

const (
	TransactionPending   = "PENDING"
	TransactionConfirmed = "CONFIRMED"
	TransactionFailed    = "FAILED"
)

// NewUniversalTransaction initializes a new UniversalTransaction instance
func NewUniversalTransaction(transactionID, sourceChainID, destinationChainID, senderID, receiverID string, amount int64) *UniversalTransaction {
	return &UniversalTransaction{
		TransactionID:  transactionID,
		SourceChainID:  sourceChainID,
		DestinationChainID: destinationChainID,
		SenderID:       senderID,
		ReceiverID:     receiverID,
		Amount:         amount,
		Timestamp:      time.Now(),
		Status:         TransactionPending,
	}
}

// ConfirmTransaction confirms the universal transaction
func (ut *UniversalTransaction) ConfirmTransaction() error {
	ut.lock.Lock()
	defer ut.lock.Unlock()

	if ut.Status != TransactionPending {
		return errors.New("transaction is not pending")
	}

	ut.Status = TransactionConfirmed
	ut.Timestamp = time.Now()
	return nil
}

// FailTransaction marks the universal transaction as failed
func (ut *UniversalTransaction) FailTransaction() error {
	ut.lock.Lock()
	defer ut.lock.Unlock()

	if ut.Status != TransactionPending {
		return errors.New("transaction is not pending")
	}

	ut.Status = TransactionFailed
	ut.Timestamp = time.Now()
	return nil
}

// EncryptTransaction encrypts the universal transaction details
func (ut *UniversalTransaction) EncryptTransaction(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s",
		ut.TransactionID, ut.SourceChainID, ut.DestinationChainID, ut.SenderID, ut.ReceiverID, ut.Amount, ut.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptTransaction decrypts the universal transaction details
func (ut *UniversalTransaction) DecryptTransaction(encryptedData string, key []byte) error {
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
	if len(parts) != 7 {
		return errors.New("invalid encrypted data format")
	}

	ut.TransactionID = parts[0]
	ut.SourceChainID = parts[1]
	ut.DestinationChainID = parts[2]
	ut.SenderID = parts[3]
	ut.ReceiverID = parts[4]
	ut.Amount = utils.ParseInt64(parts[5])
	ut.Status = parts[6]
	return nil
}

// GetTransactionDetails returns the details of the universal transaction
func (ut *UniversalTransaction) GetTransactionDetails() (string, string, string, string, string, int64, string) {
	ut.lock.RLock()
	defer ut.lock.RUnlock()
	return ut.TransactionID, ut.SourceChainID, ut.DestinationChainID, ut.SenderID, ut.ReceiverID, ut.Amount, ut.Status
}

// ValidateTransaction validates the universal transaction details
func (ut *UniversalTransaction) ValidateTransaction() error {
	ut.lock.RLock()
	defer ut.lock.RUnlock()

	if ut.TransactionID == "" || ut.SourceChainID == "" || ut.DestinationChainID == "" || ut.SenderID == "" || ut.ReceiverID == "" {
		return errors.New("transaction, chain, and participant IDs cannot be empty")
	}

	if ut.Amount <= 0 {
		return errors.New("amount must be greater than zero")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the universal transaction
func (ut *UniversalTransaction) UpdateTimestamp() {
	ut.lock.Lock()
	defer ut.lock.Unlock()
	ut.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the universal transaction
func (ut *UniversalTransaction) GetTimestamp() time.Time {
	ut.lock.RLock()
	defer ut.lock.RUnlock()
	return ut.Timestamp
}
