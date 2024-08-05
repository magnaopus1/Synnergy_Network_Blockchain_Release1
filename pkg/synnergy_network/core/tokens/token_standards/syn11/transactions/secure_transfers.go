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

// SecureTransferManager manages secure transfers of SYN11 tokens.
type SecureTransferManager struct {
	ledger        *ledger.LedgerManager
	storage       *storage.StorageManager
	mutex         sync.Mutex
	encryptionKey []byte
}

// NewSecureTransferManager creates a new instance of SecureTransferManager.
func NewSecureTransferManager(ledger *ledger.LedgerManager, storage *storage.StorageManager, passphrase string) (*SecureTransferManager, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	return &SecureTransferManager{
		ledger:        ledger,
		storage:       storage,
		encryptionKey: key,
	}, nil
}

// TransferToken handles the secure transfer of a SYN11 token from one owner to another.
func (stm *SecureTransferManager) TransferToken(tokenID, from, to string) error {
	stm.mutex.Lock()
	defer stm.mutex.Unlock()

	// Verify the ownership and KYC
	if !stm.ledger.VerifyOwnership(tokenID, from) {
		return errors.New("ownership verification failed")
	}

	if !security.VerifyKYC(to) {
		return errors.New("recipient KYC verification failed")
	}

	// Encrypt the transfer details
	transferDetails := &ledger.TransferDetails{
		TokenID:   tokenID,
		From:      from,
		To:        to,
		Timestamp: time.Now().UTC(),
		Nonce:     generateNonce(),
	}

	encryptedDetails, err := stm.encryptData(transferDetails)
	if err != nil {
		return fmt.Errorf("failed to encrypt transfer details: %w", err)
	}

	// Save the encrypted transfer details
	err = stm.storage.SaveData(fmt.Sprintf("transfer_%s.json", transferDetails.Nonce), encryptedDetails)
	if err != nil {
		return fmt.Errorf("failed to save transfer details: %w", err)
	}

	// Update the ledger with new ownership
	if err := stm.ledger.UpdateOwnership(tokenID, to); err != nil {
		return fmt.Errorf("failed to update ledger: %w", err)
	}

	return nil
}

// encryptData encrypts data using AES-GCM with the manager's encryption key.
func (stm *SecureTransferManager) encryptData(data interface{}) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	block, err := aes.NewCipher(stm.encryptionKey)
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

// generateNonce generates a unique nonce for each transfer record.
func generateNonce() string {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return fmt.Sprintf("%x", nonce)
}
