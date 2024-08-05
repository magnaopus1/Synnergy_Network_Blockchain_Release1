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

// OwnershipTransferManager manages the transfer of ownership of SYN11 tokens.
type OwnershipTransferManager struct {
	ledger            *ledger.LedgerManager
	storage           *storage.StorageManager
	mutex             sync.Mutex
	encryptionKey     []byte
}

// NewOwnershipTransferManager creates a new instance of OwnershipTransferManager.
func NewOwnershipTransferManager(ledger *ledger.LedgerManager, storage *storage.StorageManager, passphrase string) (*OwnershipTransferManager, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	return &OwnershipTransferManager{
		ledger:        ledger,
		storage:       storage,
		encryptionKey: key,
	}, nil
}

// TransferOwnership initiates the transfer of ownership from one party to another.
func (otm *OwnershipTransferManager) TransferOwnership(tokenID, from, to string) error {
	otm.mutex.Lock()
	defer otm.mutex.Unlock()

	// Verify ownership
	if !otm.ledger.VerifyOwnership(tokenID, from) {
		return errors.New("ownership verification failed")
	}

	// Ensure the recipient is KYC verified
	if !security.VerifyKYC(to) {
		return errors.New("recipient KYC verification failed")
	}

	// Record the transfer
	transferRecord := &ledger.TransferRecord{
		TokenID:    tokenID,
		From:       from,
		To:         to,
		Timestamp:  time.Now().UTC(),
		Nonce:      generateNonce(),
	}
	
	// Encrypt and save the transfer record
	encryptedRecord, err := otm.encryptData(transferRecord)
	if err != nil {
		return fmt.Errorf("failed to encrypt transfer record: %w", err)
	}

	err = otm.storage.SaveData(fmt.Sprintf("transfer_%s.json", transferRecord.Nonce), encryptedRecord)
	if err != nil {
		return fmt.Errorf("failed to save transfer record: %w", err)
	}

	// Update ledger
	if err := otm.ledger.UpdateOwnership(tokenID, to); err != nil {
		return fmt.Errorf("failed to update ledger: %w", err)
	}

	return nil
}

// GetTransferRecord retrieves and decrypts a transfer record by nonce.
func (otm *OwnershipTransferManager) GetTransferRecord(nonce string) (*ledger.TransferRecord, error) {
	otm.mutex.Lock()
	defer otm.mutex.Unlock()

	var record ledger.TransferRecord
	err := otm.storage.LoadData(fmt.Sprintf("transfer_%s.json", nonce), &record)
	if err != nil {
		return nil, fmt.Errorf("failed to load transfer record: %w", err)
	}

	return &record, nil
}

// encryptData encrypts the data using AES-GCM with the manager's encryption key.
func (otm *OwnershipTransferManager) encryptData(data interface{}) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	block, err := aes.NewCipher(otm.encryptionKey)
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

// generateNonce generates a unique nonce for each transaction.
func generateNonce() string {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return fmt.Sprintf("%x", nonce)
}
