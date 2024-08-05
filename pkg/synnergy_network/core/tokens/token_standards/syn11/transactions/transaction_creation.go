package transactions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
	"sync"

	"synnergy_network/core/tokens/token_standards/syn11/ledger"
	"synnergy_network/core/tokens/token_standards/syn11/security"
	"synnergy_network/core/tokens/token_standards/syn11/storage"
)

// TransactionManager handles the creation and management of SYN11 token transactions.
type TransactionManager struct {
	ledger        *ledger.LedgerManager
	storage       *storage.StorageManager
	mutex         sync.Mutex
	encryptionKey []byte
}

// NewTransactionManager creates a new instance of TransactionManager.
func NewTransactionManager(ledger *ledger.LedgerManager, storage *storage.StorageManager, passphrase string) (*TransactionManager, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	return &TransactionManager{
		ledger:        ledger,
		storage:       storage,
		encryptionKey: key,
	}, nil
}

// CreateTransaction initializes a new transaction for transferring SYN11 tokens.
func (tm *TransactionManager) CreateTransaction(tokenID, from, to string, amount float64) (string, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Verify the ownership, balance, and KYC
	if !tm.ledger.VerifyOwnership(tokenID, from) {
		return "", errors.New("ownership verification failed")
	}

	if !security.VerifyKYC(from) || !security.VerifyKYC(to) {
		return "", errors.New("KYC verification failed")
	}

	// Ensure sufficient balance
	if !tm.ledger.VerifyBalance(from, amount) {
		return "", errors.New("insufficient balance")
	}

	// Create transaction details
	transactionDetails := &ledger.TransactionDetails{
		TokenID:   tokenID,
		From:      from,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now().UTC(),
		Nonce:     generateNonce(),
	}

	// Encrypt the transaction details
	encryptedDetails, err := tm.encryptData(transactionDetails)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt transaction details: %w", err)
	}

	// Save the encrypted transaction details
	transactionID := fmt.Sprintf("transaction_%s.json", transactionDetails.Nonce)
	err = tm.storage.SaveData(transactionID, encryptedDetails)
	if err != nil {
		return "", fmt.Errorf("failed to save transaction details: %w", err)
	}

	// Update the ledger with the transaction
	if err := tm.ledger.RecordTransaction(transactionDetails); err != nil {
		return "", fmt.Errorf("failed to record transaction: %w", err)
	}

	return transactionID, nil
}

// encryptData encrypts data using AES-GCM with the manager's encryption key.
func (tm *TransactionManager) encryptData(data interface{}) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	block, err := aes.NewCipher(tm.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// generateKey generates a key from a passphrase using Scrypt.
func generateKey(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// generateNonce generates a unique nonce for each transaction record.
func generateNonce() string {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return fmt.Sprintf("%x", nonce)
}
