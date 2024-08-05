package transactions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/scrypt"
)

// OwnershipTransfer represents an ownership transfer transaction
type OwnershipTransfer struct {
	TransferID    string    `json:"transfer_id"`
	Timestamp     time.Time `json:"timestamp"`
	FromAddress   string    `json:"from_address"`
	ToAddress     string    `json:"to_address"`
	ETFID         string    `json:"etf_id"`
	Shares        float64   `json:"shares"`
	Signature     string    `json:"signature"`
}

// OwnershipTransferHistory manages the history of ownership transfers
type OwnershipTransferHistory struct {
	historyPath   string
	encryptionKey []byte
	transfers     map[string]OwnershipTransfer
}

// NewOwnershipTransferHistory creates a new instance of OwnershipTransferHistory
func NewOwnershipTransferHistory(historyPath, password string) (*OwnershipTransferHistory, error) {
	encryptionKey, err := generateKeyFromPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	return &OwnershipTransferHistory{
		historyPath:   historyPath,
		encryptionKey: encryptionKey,
		transfers:     make(map[string]OwnershipTransfer),
	}, nil
}

// AddTransfer adds a new ownership transfer to the history
func (oth *OwnershipTransferHistory) AddTransfer(transfer OwnershipTransfer) error {
	transferID := generateTransferID(transfer)
	transfer.TransferID = transferID
	oth.transfers[transferID] = transfer

	return oth.saveTransfers()
}

// GetTransfer retrieves an ownership transfer by its ID
func (oth *OwnershipTransferHistory) GetTransfer(transferID string) (OwnershipTransfer, error) {
	transfer, exists := oth.transfers[transferID]
	if !exists {
		return OwnershipTransfer{}, errors.New("transfer not found")
	}
	return transfer, nil
}

// GetAllTransfers retrieves all ownership transfers
func (oth *OwnershipTransferHistory) GetAllTransfers() ([]OwnershipTransfer, error) {
	var allTransfers []OwnershipTransfer
	for _, transfer := range oth.transfers {
		allTransfers = append(allTransfers, transfer)
	}
	return allTransfers, nil
}

// saveTransfers saves all ownership transfers to disk with encryption
func (oth *OwnershipTransferHistory) saveTransfers() error {
	data, err := json.Marshal(oth.transfers)
	if err != nil {
		return fmt.Errorf("failed to marshal transfers: %v", err)
	}

	encryptedData, err := oth.encryptData(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt transfers: %v", err)
	}

	filePath := filepath.Join(oth.historyPath, "transfers.dat")
	err = os.WriteFile(filePath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write transfers to file: %v", err)
	}

	return nil
}

// loadTransfers loads all ownership transfers from disk with decryption
func (oth *OwnershipTransferHistory) loadTransfers() error {
	filePath := filepath.Join(oth.historyPath, "transfers.dat")
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No transfers file exists yet, no problem
		}
		return fmt.Errorf("failed to read transfers from file: %v", err)
	}

	data, err := oth.decryptData(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt transfers: %v", err)
	}

	err = json.Unmarshal(data, &oth.transfers)
	if err != nil {
		return fmt.Errorf("failed to unmarshal transfers: %v", err)
	}

	return nil
}

// encryptData encrypts data using AES
func (oth *OwnershipTransferHistory) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(oth.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES
func (oth *OwnershipTransferHistory) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(oth.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}

// generateKeyFromPassword generates a key from a password using scrypt
func generateKeyFromPassword(password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return key, nil
}

// generateTransferID generates a unique ID for a transfer
func generateTransferID(transfer OwnershipTransfer) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%v%v%v%v", transfer.Timestamp, transfer.FromAddress, transfer.ToAddress, transfer.Shares)))
	return hex.EncodeToString(hash.Sum(nil))
}
