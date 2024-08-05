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
	"time"

	"golang.org/x/crypto/scrypt"
)

// SecureTransfer represents a secure transfer of ETF shares
type SecureTransfer struct {
	TransferID    string    `json:"transfer_id"`
	Timestamp     time.Time `json:"timestamp"`
	FromAddress   string    `json:"from_address"`
	ToAddress     string    `json:"to_address"`
	ETFID         string    `json:"etf_id"`
	Shares        float64   `json:"shares"`
	Signature     string    `json:"signature"`
}

// SecureTransferHistory manages the history of secure transfers
type SecureTransferHistory struct {
	historyPath   string
	encryptionKey []byte
	transfers     map[string]SecureTransfer
}

// NewSecureTransferHistory creates a new instance of SecureTransferHistory
func NewSecureTransferHistory(historyPath, password string) (*SecureTransferHistory, error) {
	encryptionKey, err := generateKeyFromPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	sth := &SecureTransferHistory{
		historyPath:   historyPath,
		encryptionKey: encryptionKey,
		transfers:     make(map[string]SecureTransfer),
	}
	err = sth.loadTransfers()
	if err != nil {
		return nil, err
	}

	return sth, nil
}

// AddTransfer adds a new secure transfer to the history
func (sth *SecureTransferHistory) AddTransfer(transfer SecureTransfer) error {
	transferID := generateTransferID(transfer)
	transfer.TransferID = transferID
	sth.transfers[transferID] = transfer

	return sth.saveTransfers()
}

// GetTransfer retrieves a secure transfer by its ID
func (sth *SecureTransferHistory) GetTransfer(transferID string) (SecureTransfer, error) {
	transfer, exists := sth.transfers[transferID]
	if !exists {
		return SecureTransfer{}, errors.New("transfer not found")
	}
	return transfer, nil
}

// GetAllTransfers retrieves all secure transfers
func (sth *SecureTransferHistory) GetAllTransfers() ([]SecureTransfer, error) {
	var allTransfers []SecureTransfer
	for _, transfer := range sth.transfers {
		allTransfers = append(allTransfers, transfer)
	}
	return allTransfers, nil
}

// saveTransfers saves all secure transfers to disk with encryption
func (sth *SecureTransferHistory) saveTransfers() error {
	data, err := json.Marshal(sth.transfers)
	if err != nil {
		return fmt.Errorf("failed to marshal transfers: %v", err)
	}

	encryptedData, err := sth.encryptData(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt transfers: %v", err)
	}

	filePath := filepath.Join(sth.historyPath, "secure_transfers.dat")
	err = os.WriteFile(filePath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write transfers to file: %v", err)
	}

	return nil
}

// loadTransfers loads all secure transfers from disk with decryption
func (sth *SecureTransferHistory) loadTransfers() error {
	filePath := filepath.Join(sth.historyPath, "secure_transfers.dat")
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No transfers file exists yet, no problem
		}
		return fmt.Errorf("failed to read transfers from file: %v", err)
	}

	data, err := sth.decryptData(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt transfers: %v", err)
	}

	err = json.Unmarshal(data, &sth.transfers)
	if err != nil {
		return fmt.Errorf("failed to unmarshal transfers: %v", err)
	}

	return nil
}

// encryptData encrypts data using AES
func (sth *SecureTransferHistory) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sth.encryptionKey)
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
func (sth *SecureTransferHistory) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sth.encryptionKey)
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
func generateTransferID(transfer SecureTransfer) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%v%v%v%v", transfer.Timestamp, transfer.FromAddress, transfer.ToAddress, transfer.Shares)))
	return hex.EncodeToString(hash.Sum(nil))
}
