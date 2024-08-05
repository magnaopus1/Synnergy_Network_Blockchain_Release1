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

// OwnershipTransfer represents a single ownership transfer for a bill token
type OwnershipTransfer struct {
	TransferID   string    `json:"transfer_id"`
	BillID       string    `json:"bill_id"`
	From         string    `json:"from"`
	To           string    `json:"to"`
	Timestamp    time.Time `json:"timestamp"`
	Signature    string    `json:"signature"`
	TransferData string    `json:"transfer_data"`
	Status       string    `json:"status"`
}

// OwnershipTransferHistory manages the history of ownership transfers
type OwnershipTransferHistory struct {
	storagePath string
	mu          sync.Mutex
}

// NewOwnershipTransferHistory initializes a new OwnershipTransferHistory manager
func NewOwnershipTransferHistory(storagePath string) (*OwnershipTransferHistory, error) {
	err := os.MkdirAll(storagePath, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return &OwnershipTransferHistory{storagePath: storagePath}, nil
}

// RecordTransfer stores a new ownership transfer in the history
func (oth *OwnershipTransferHistory) RecordTransfer(transfer OwnershipTransfer) error {
	oth.mu.Lock()
	defer oth.mu.Unlock()

	transfer.Timestamp = time.Now()
	encryptedData, err := encryptTransferData(transfer)
	if err != nil {
		return err
	}

	filename := filepath.Join(oth.storagePath, transfer.TransferID+".json")
	return os.WriteFile(filename, encryptedData, os.ModePerm)
}

// GetTransfer retrieves an ownership transfer by its ID
func (oth *OwnershipTransferHistory) GetTransfer(transferID string) (*OwnershipTransfer, error) {
	oth.mu.Lock()
	defer oth.mu.Unlock()

	filename := filepath.Join(oth.storagePath, transferID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return decryptTransferData(data)
}

// ListTransfers lists all ownership transfers for a specific bill ID
func (oth *OwnershipTransferHistory) ListTransfers(billID string) ([]OwnershipTransfer, error) {
	oth.mu.Lock()
	defer oth.mu.Unlock()

	var transfers []OwnershipTransfer
	files, err := os.ReadDir(oth.storagePath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(oth.storagePath, file.Name()))
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

// DeleteTransfer deletes an ownership transfer by its ID
func (oth *OwnershipTransferHistory) DeleteTransfer(transferID string) error {
	oth.mu.Lock()
	defer oth.mu.Unlock()

	filename := filepath.Join(oth.storagePath, transferID+".json")
	return os.Remove(filename)
}

// encryptTransferData encrypts the transfer data using a generated key
func encryptTransferData(transfer OwnershipTransfer) ([]byte, error) {
	key := generateKey(transfer.TransferID)
	data, err := json.Marshal(transfer)
	if err != nil {
		return nil, err
	}
	return cryptography.EncryptData(data, key)
}

// decryptTransferData decrypts the transfer data using a generated key
func decryptTransferData(data []byte) (*OwnershipTransfer, error) {
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

	var transfer OwnershipTransfer
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
