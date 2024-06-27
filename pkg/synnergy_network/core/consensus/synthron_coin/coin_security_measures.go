package synthron_coin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// SecurityMeasures handles the security measures for the Synthron Coin
type SecurityMeasures struct {
	EncryptionKey      []byte
	TransactionLock    sync.Mutex
	BlockLock          sync.Mutex
	StakeLock          sync.Mutex
	ValidatorLock      sync.Mutex
	Validators         map[string]bool
	TransactionHistory map[string]TransactionRecord
}

// TransactionRecord represents a record of a transaction for verification purposes
type TransactionRecord struct {
	Timestamp time.Time
	Amount    int64
	Sender    string
	Receiver  string
	Hash      string
}

// NewSecurityMeasures initializes a new instance of SecurityMeasures with a given encryption key
func NewSecurityMeasures(encryptionKey string) *SecurityMeasures {
	return &SecurityMeasures{
		EncryptionKey:      []byte(encryptionKey),
		Validators:         make(map[string]bool),
		TransactionHistory: make(map[string]TransactionRecord),
	}
}

// GenerateKey generates a secure encryption key using Argon2
func GenerateKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// Encrypt encrypts plaintext using AES-GCM with the encryption key
func (sm *SecurityMeasures) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(sm.EncryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM with the encryption key
func (sm *SecurityMeasures) Decrypt(ciphertext string) (string, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(sm.EncryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// ValidateTransaction ensures the integrity and validity of a transaction
func (sm *SecurityMeasures) ValidateTransaction(txID string) (bool, error) {
	sm.TransactionLock.Lock()
	defer sm.TransactionLock.Unlock()

	txRecord, exists := sm.TransactionHistory[txID]
	if !exists {
		return false, errors.New("transaction not found")
	}

	expectedHash := sm.generateTransactionHash(txRecord)
	if expectedHash != txRecord.Hash {
		return false, errors.New("transaction hash mismatch")
	}

	return true, nil
}

// AddTransaction adds a new transaction to the transaction history
func (sm *SecurityMeasures) AddTransaction(amount int64, sender, receiver string) (string, error) {
	sm.TransactionLock.Lock()
	defer sm.TransactionLock.Unlock()

	txID := sm.generateTransactionID(sender, receiver, amount)
	txRecord := TransactionRecord{
		Timestamp: time.Now(),
		Amount:    amount,
		Sender:    sender,
		Receiver:  receiver,
		Hash:      sm.generateTransactionHash(TransactionRecord{Timestamp: time.Now(), Amount: amount, Sender: sender, Receiver: receiver}),
	}

	sm.TransactionHistory[txID] = txRecord
	return txID, nil
}

// generateTransactionID generates a unique transaction ID
func (sm *SecurityMeasures) generateTransactionID(sender, receiver string, amount int64) string {
	data := fmt.Sprintf("%s%s%d%d", sender, receiver, amount, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateTransactionHash generates a hash for a transaction
func (sm *SecurityMeasures) generateTransactionHash(record TransactionRecord) string {
	data := fmt.Sprintf("%s%d%s%s", record.Timestamp, record.Amount, record.Sender, record.Receiver)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// AddValidator adds a new validator to the network
func (sm *SecurityMeasures) AddValidator(validatorID string) {
	sm.ValidatorLock.Lock()
	defer sm.ValidatorLock.Unlock()

	sm.Validators[validatorID] = true
}

// RemoveValidator removes a validator from the network
func (sm *SecurityMeasures) RemoveValidator(validatorID string) {
	sm.ValidatorLock.Lock()
	defer sm.ValidatorLock.Unlock()

	delete(sm.Validators, validatorID)
}

// IsValidator checks if a given ID is a validator
func (sm *SecurityMeasures) IsValidator(validatorID string) bool {
	sm.ValidatorLock.Lock()
	defer sm.ValidatorLock.Unlock()

	return sm.Validators[validatorID]
}

// EncryptTransactionData encrypts transaction data for secure transmission
func (sm *SecurityMeasures) EncryptTransactionData(txData string) (string, error) {
	encryptedData, err := sm.Encrypt(txData)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptTransactionData decrypts transaction data for verification
func (sm *SecurityMeasures) DecryptTransactionData(encryptedData string) (string, error) {
	decryptedData, err := sm.Decrypt(encryptedData)
	if err != nil {
		return "", err
	}
	return decryptedData, nil
}

// LogSecurityEvent logs security events for auditing
func (sm *SecurityMeasures) LogSecurityEvent(event string) {
	log.Printf("Security Event: %s", event)
}

