package transactions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"

	"synnergy_network/core/tokens/token_standards/syn12/ledger"
	"synnergy_network/core/tokens/token_standards/syn12/storage"
)

// SecureTransferManager manages secure transfers of T-Bill tokens.
type SecureTransferManager struct {
	ledger         *ledger.TransactionRecords
	storageManager *storage.StorageManager
	mu             sync.RWMutex
	encryptionKey  []byte
}

// NewSecureTransferManager creates a new SecureTransferManager.
func NewSecureTransferManager(ledger *ledger.TransactionRecords, storageManager *storage.StorageManager, encryptionKey []byte) *SecureTransferManager {
	if len(encryptionKey) != 32 {
		panic("encryption key must be 32 bytes long")
	}
	return &SecureTransferManager{
		ledger:         ledger,
		storageManager: storageManager,
		encryptionKey:  encryptionKey,
	}
}

// EncryptData encrypts the provided data using AES-GCM.
func (stm *SecureTransferManager) EncryptData(data string) (string, error) {
	block, err := aes.NewCipher(stm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the provided data using AES-GCM.
func (stm *SecureTransferManager) DecryptData(data string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(stm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Transfer securely transfers a T-Bill token from one party to another.
func (stm *SecureTransferManager) Transfer(tokenID, from, to string, transferData string) error {
	stm.mu.Lock()
	defer stm.mu.Unlock()

	// Verify the current ownership
	currentOwner, err := stm.ledger.GetOwner(tokenID)
	if err != nil {
		return fmt.Errorf("failed to get current owner: %v", err)
	}

	if currentOwner != from {
		return fmt.Errorf("transfer failed: %s does not own the token", from)
	}

	// Encrypt the transfer data
	encryptedData, err := stm.EncryptData(transferData)
	if err != nil {
		return fmt.Errorf("failed to encrypt transfer data: %v", err)
	}

	// Create a transfer record
	transferRecord := ledger.TransactionRecord{
		TokenID:      tokenID,
		From:         from,
		To:           to,
		Amount:       0, // Assuming no value exchange for simple transfer
		Data:         encryptedData,
		TransactionType: "Transfer",
	}

	// Record the transfer in the ledger
	if err := stm.ledger.RecordTransaction(transferRecord); err != nil {
		return fmt.Errorf("failed to record transfer in ledger: %v", err)
	}

	// Update ownership
	if err := stm.ledger.UpdateOwner(tokenID, to); err != nil {
		return fmt.Errorf("failed to update ownership: %v", err)
	}

	// Store the transfer record in persistent storage
	if err := stm.storageManager.SaveData(fmt.Sprintf("transfer_%s", tokenID), transferRecord); err != nil {
		return fmt.Errorf("failed to store transfer record: %v", err)
	}

	return nil
}

// GetTransferData retrieves the transfer data for a specific transaction.
func (stm *SecureTransferManager) GetTransferData(tokenID, transactionID string) (string, error) {
	stm.mu.RLock()
	defer stm.mu.RUnlock()

	// Retrieve the transaction record
	record, err := stm.ledger.GetTransactionByID(tokenID, transactionID)
	if err != nil {
		return "", fmt.Errorf("failed to get transaction record: %v", err)
	}

	// Decrypt the transfer data
	plaintext, err := stm.DecryptData(record.Data)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt transfer data: %v", err)
	}

	return plaintext, nil
}
