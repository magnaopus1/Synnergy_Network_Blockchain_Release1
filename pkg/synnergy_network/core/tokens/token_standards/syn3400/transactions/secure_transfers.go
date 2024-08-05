package transactions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
)

const (
	scryptN  = 32768
	scryptR  = 8
	scryptP  = 1
	keySize  = 32
	saltSize = 16
)

// SecureTransfer represents a secure transfer of a Forex token
type SecureTransfer struct {
	TransferID    string
	TokenID       string
	From          string
	To            string
	EncryptedData string
	Timestamp     time.Time
	TransactionID string
}

// SecureTransferManager manages the secure transfers
type SecureTransferManager struct {
	transfers           []SecureTransfer
	mutex               sync.Mutex
	ledgerManager       *ledger.LedgerManager
	tokenManager        *assets.TokenManager
	eventLogger         *events.EventLogger
	transferChannel     chan SecureTransfer
	verificationChannel chan SecureTransfer
}

// NewSecureTransferManager initializes a new SecureTransferManager instance
func NewSecureTransferManager(ledgerMgr *ledger.LedgerManager, tokenMgr *assets.TokenManager, eventLogger *events.EventLogger) (*SecureTransferManager, error) {
	return &SecureTransferManager{
		transfers:           []SecureTransfer{},
		ledgerManager:       ledgerMgr,
		tokenManager:        tokenMgr,
		eventLogger:         eventLogger,
		transferChannel:     make(chan SecureTransfer, 100),
		verificationChannel: make(chan SecureTransfer, 100),
	}, nil
}

// StartProcessing starts processing secure transfers
func (stm *SecureTransferManager) StartProcessing() {
	go func() {
		for transfer := range stm.transferChannel {
			stm.mutex.Lock()
			stm.transfers = append(stm.transfers, transfer)
			stm.mutex.Unlock()
			stm.verifySecureTransfer(transfer)
			stm.recordTransfer(transfer)
			stm.logEvent(transfer)
		}
	}()
}

// generateTransferID generates a unique ID for a transfer
func generateTransferID() (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	hash := sha256.Sum256(id)
	return hex.EncodeToString(hash[:]), nil
}

// EncryptData encrypts the data using AES
func EncryptData(data, passphrase string) (string, error) {
	salt := make([]byte, saltSize)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return "", err
	}

	key, err := scryptKey(passphrase, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return fmt.Sprintf("%x:%x", salt, ciphertext), nil
}

// DecryptData decrypts the data using AES
func DecryptData(encryptedData, passphrase string) (string, error) {
	parts := split(encryptedData, ':')
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted data format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, err := scryptKey(passphrase, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// scryptKey generates a key using scrypt
func scryptKey(passphrase string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keySize)
}

// TransferOwnership securely transfers ownership of a Forex token
func (stm *SecureTransferManager) TransferOwnership(tokenID, from, to, passphrase string) error {
	stm.mutex.Lock()
	defer stm.mutex.Unlock()

	// Verify token ownership
	currentOwner, err := stm.tokenManager.GetOwner(tokenID)
	if err != nil {
		return err
	}
	if currentOwner != from {
		return errors.New("the from address does not own the token")
	}

	// Generate transfer ID
	transferID, err := generateTransferID()
	if err != nil {
		return err
	}

	// Encrypt transfer data
	data := fmt.Sprintf("TokenID:%s,From:%s,To:%s", tokenID, from, to)
	encryptedData, err := EncryptData(data, passphrase)
	if err != nil {
		return err
	}

	// Create a new transfer
	transfer := SecureTransfer{
		TransferID:    transferID,
		TokenID:       tokenID,
		From:          from,
		To:            to,
		EncryptedData: encryptedData,
		Timestamp:     time.Now(),
		TransactionID: "", // Generate or retrieve the transaction ID as needed
	}

	// Add transfer to the channel for processing
	stm.transferChannel <- transfer

	return nil
}

// verifySecureTransfer verifies the secure transfer
func (stm *SecureTransferManager) verifySecureTransfer(transfer SecureTransfer) {
	// Here, you can add logic to verify the transfer, such as checking digital signatures or other validation methods
	// For now, we'll assume the transfer is valid
	stm.verificationChannel <- transfer
}

// recordTransfer records the secure transfer in the ledger
func (stm *SecureTransferManager) recordTransfer(transfer SecureTransfer) error {
	return stm.ledgerManager.RecordTransfer(transfer.TransferID, transfer.TokenID, transfer.From, transfer.To, transfer.Timestamp)
}

// logEvent logs the secure transfer event
func (stm *SecureTransferManager) logEvent(transfer SecureTransfer) {
	event := events.Event{
		Type:      "SecureTransfer",
		Timestamp: transfer.Timestamp,
		Data: map[string]interface{}{
			"transferID":    transfer.TransferID,
			"tokenID":       transfer.TokenID,
			"from":          transfer.From,
			"to":            transfer.To,
			"encryptedData": transfer.EncryptedData,
		},
	}
	stm.eventLogger.LogEvent(event)
}

// Helper function to split a string by a delimiter
func split(s string, delimiter byte) []string {
	var result []string
	for len(s) > 0 {
		pos := indexOf(s, delimiter)
		if pos == -1 {
			result = append(result, s)
			break
		}
		result = append(result, s[:pos])
		s = s[pos+1:]
	}
	return result
}

// Helper function to find the index of a byte in a string
func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
