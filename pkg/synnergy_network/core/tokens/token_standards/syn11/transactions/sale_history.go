package transactions

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"golang.org/x/crypto/scrypt"
	"io"
	"sync"

	"synnergy_network/core/tokens/token_standards/syn11/ledger"
	"synnergy_network/core/tokens/token_standards/syn11/security"
	"synnergy_network/core/tokens/token_standards/syn11/storage"
)

// SaleHistoryManager manages the history of sales and transfers for SYN11 tokens.
type SaleHistoryManager struct {
	ledger        *ledger.LedgerManager
	storage       *storage.StorageManager
	mutex         sync.Mutex
	encryptionKey []byte
}

// NewSaleHistoryManager creates a new instance of SaleHistoryManager.
func NewSaleHistoryManager(ledger *ledger.LedgerManager, storage *storage.StorageManager, passphrase string) (*SaleHistoryManager, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	return &SaleHistoryManager{
		ledger:        ledger,
		storage:       storage,
		encryptionKey: key,
	}, nil
}

// RecordSale records the details of a sale or transfer of a SYN11 token.
func (shm *SaleHistoryManager) RecordSale(tokenID, from, to string, salePrice float64, saleDate time.Time) error {
	shm.mutex.Lock()
	defer shm.mutex.Unlock()

	// Verify the sale and ownership
	if !shm.ledger.VerifyOwnership(tokenID, from) {
		return errors.New("ownership verification failed")
	}

	if !security.VerifyKYC(to) {
		return errors.New("recipient KYC verification failed")
	}

	// Create a sale record
	saleRecord := &ledger.SaleRecord{
		TokenID:    tokenID,
		From:       from,
		To:         to,
		SalePrice:  salePrice,
		SaleDate:   saleDate.UTC(),
		Timestamp:  time.Now().UTC(),
		Nonce:      generateNonce(),
	}

	// Encrypt and save the sale record
	encryptedRecord, err := shm.encryptData(saleRecord)
	if err != nil {
		return fmt.Errorf("failed to encrypt sale record: %w", err)
	}

	err = shm.storage.SaveData(fmt.Sprintf("sale_%s.json", saleRecord.Nonce), encryptedRecord)
	if err != nil {
		return fmt.Errorf("failed to save sale record: %w", err)
	}

	// Update ledger with new ownership
	if err := shm.ledger.UpdateOwnership(tokenID, to); err != nil {
		return fmt.Errorf("failed to update ledger: %w", err)
	}

	return nil
}

// GetSaleHistory retrieves and decrypts the sale history for a specific token.
func (shm *SaleHistoryManager) GetSaleHistory(tokenID string) ([]*ledger.SaleRecord, error) {
	shm.mutex.Lock()
	defer shm.mutex.Unlock()

	records, err := shm.storage.LoadData(fmt.Sprintf("history_%s.json", tokenID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load sale history: %w", err)
	}

	var saleRecords []*ledger.SaleRecord
	err = json.Unmarshal(records, &saleRecords)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sale records: %w", err)
	}

	return saleRecords, nil
}

// encryptData encrypts data using AES-GCM with the manager's encryption key.
func (shm *SaleHistoryManager) encryptData(data interface{}) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	block, err := aes.NewCipher(shm.encryptionKey)
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

// generateNonce generates a unique nonce for each sale record.
func generateNonce() string {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return fmt.Sprintf("%x", nonce)
}
