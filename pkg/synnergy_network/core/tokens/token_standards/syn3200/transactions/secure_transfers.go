package transactions

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/you/yourproject/pkg/cryptography"
	"golang.org/x/crypto/scrypt"
)

// SecureTransfer represents a secure transfer for a bill token
type SecureTransfer struct {
	TransferID   string    `json:"transfer_id"`
	BillID       string    `json:"bill_id"`
	From         string    `json:"from"`
	To           string    `json:"to"`
	Timestamp    time.Time `json:"timestamp"`
	Signature    string    `json:"signature"`
	TransferData string    `json:"transfer_data"`
	Status       string    `json:"status"`
}

// SecureTransferManager manages the secure transfers for bill tokens
type SecureTransferManager struct {
	storagePath string
	mu          sync.Mutex
}

// NewSecureTransferManager initializes a new SecureTransferManager
func NewSecureTransferManager(storagePath string) (*SecureTransferManager, error) {
	err := os.MkdirAll(storagePath, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return &SecureTransferManager{storagePath: storagePath}, nil
}

// CreateTransfer creates a new secure transfer
func (stm *SecureTransferManager) CreateTransfer(transfer SecureTransfer) error {
	stm.mu.Lock()
	defer stm.mu.Unlock()

	transfer.Timestamp = time.Now()
	encryptedData, err := encryptTransferData(transfer)
	if err != nil {
		return err
	}

	filename := filepath.Join(stm.storagePath, transfer.TransferID+".json")
	return os.WriteFile(filename, encryptedData, os.ModePerm)
}

// GetTransfer retrieves a secure transfer by its ID
func (stm *SecureTransferManager) GetTransfer(transferID string) (*SecureTransfer, error) {
	stm.mu.Lock()
	defer stm.mu.Unlock()

	filename := filepath.Join(stm.storagePath, transferID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return decryptTransferData(data)
}

// ListTransfers lists all secure transfers for a specific bill ID
func (stm *SecureTransferManager) ListTransfers(billID string) ([]SecureTransfer, error) {
	stm.mu.Lock()
	defer stm.mu.Unlock()

	var transfers []SecureTransfer
	files, err := os.ReadDir(stm.storagePath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(stm.storagePath, file.Name()))
		if err != nil {
			return nil, err
		}

		transfer, err := decryptTransferData(data)
		if err != nil {
			return nil, err
		}
		if transfer.BillID == billID {
			transfers = append(transfers, *transfer)
		}
	}
	return transfers, nil
}

// DeleteTransfer deletes a secure transfer by its ID
func (stm *SecureTransferManager) DeleteTransfer(transferID string) error {
	stm.mu.Lock()
	defer stm.mu.Unlock()

	filename := filepath.Join(stm.storagePath, transferID+".json")
	return os.Remove(filename)
}

// encryptTransferData encrypts the transfer data using a generated key
func encryptTransferData(transfer SecureTransfer) ([]byte, error) {
	key := generateKey(transfer.TransferID)
	data, err := json.Marshal(transfer)
	if err != nil {
		return nil, err
	}
	return cryptography.EncryptData(data, key)
}

// decryptTransferData decrypts the transfer data using a generated key
func decryptTransferData(data []byte) (*SecureTransfer, error) {
	var encryptedTransfer map[string]interface{}
	err := json.Unmarshal(data, &encryptedTransfer)
	if err != nil {
		return nil, err
	}

	key := generateKey(encryptedTransfer["transfer_id"].(string))
	decryptedData, err := cryptography.DecryptData(data, key)
	if err != nil {
		return nil, err
	}

	var transfer SecureTransfer
	err = json.Unmarshal(decryptedData, &transfer)
	if err != nil {
		return nil, err
	}
	return &transfer, nil
}

// generateKey generates a key for encryption and decryption
func generateKey(transferID string) []byte {
	key, _ := scrypt.Key([]byte(transferID), []byte("somesalt"), 32768, 8, 1, 32)
	return key
}
