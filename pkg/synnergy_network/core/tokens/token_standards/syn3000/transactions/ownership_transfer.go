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
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn3000/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn3000/security"
)

// OwnershipTransfer represents a transaction for transferring ownership of a property
type OwnershipTransfer struct {
	TokenID        string
	FromOwner      string
	ToOwner        string
	TransferDate   time.Time
	TransactionID  string
	EncryptedData  string
}

// TransferOwnership initiates the ownership transfer process
func TransferOwnership(tokenID, fromOwner, toOwner string) (*OwnershipTransfer, error) {
	// Verify ownership
	currentOwner, err := ledger.GetCurrentOwner(tokenID)
	if err != nil {
		return nil, fmt.Errorf("error verifying current ownership: %v", err)
	}
	if currentOwner != fromOwner {
		return nil, errors.New("current owner does not match fromOwner")
	}

	// Create transfer details
	transfer := &OwnershipTransfer{
		TokenID:      tokenID,
		FromOwner:    fromOwner,
		ToOwner:      toOwner,
		TransferDate: time.Now(),
	}

	// Encrypt transfer details
	encryptedData, err := encryptTransferDetails(transfer)
	if err != nil {
		return nil, fmt.Errorf("error encrypting transfer details: %v", err)
	}
	transfer.EncryptedData = encryptedData

	// Generate transaction ID
	transfer.TransactionID = generateTransactionID(transfer)

	// Update ledger
	if err := ledger.UpdateOwnership(tokenID, toOwner); err != nil {
		return nil, fmt.Errorf("error updating ledger: %v", err)
	}

	// Log transfer event
	if err := logTransferEvent(transfer); err != nil {
		return nil, fmt.Errorf("error logging transfer event: %v", err)
	}

	return transfer, nil
}

// encryptTransferDetails encrypts the transfer details
func encryptTransferDetails(transfer *OwnershipTransfer) (string, error) {
	key := sha256.Sum256([]byte("some-very-secure-key"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	plaintext := fmt.Sprintf("%s|%s|%s|%s", transfer.TokenID, transfer.FromOwner, transfer.ToOwner, transfer.TransferDate)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return hex.EncodeToString(ciphertext), nil
}

// decryptTransferDetails decrypts the transfer details
func decryptTransferDetails(encryptedData string) (*OwnershipTransfer, error) {
	key := sha256.Sum256([]byte("some-very-secure-key"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	ciphertext, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	plaintext := string(ciphertext)
	var tokenID, fromOwner, toOwner string
	var transferDate time.Time
	_, err = fmt.Sscanf(plaintext, "%s|%s|%s|%s", &tokenID, &fromOwner, &toOwner, &transferDate)
	if err != nil {
		return nil, err
	}

	return &OwnershipTransfer{
		TokenID:      tokenID,
		FromOwner:    fromOwner,
		ToOwner:      toOwner,
		TransferDate: transferDate,
	}, nil
}

// generateTransactionID generates a unique transaction ID for the transfer
func generateTransactionID(transfer *OwnershipTransfer) string {
	data := fmt.Sprintf("%s%s%s%s", transfer.TokenID, transfer.FromOwner, transfer.ToOwner, transfer.TransferDate)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// logTransferEvent logs the ownership transfer event
func logTransferEvent(transfer *OwnershipTransfer) error {
	event := fmt.Sprintf("Ownership of token %s transferred from %s to %s on %s", transfer.TokenID, transfer.FromOwner, transfer.ToOwner, transfer.TransferDate)
	return security.LogEvent(event)
}

// OwnershipTransferStatus represents the status of an ownership transfer
type OwnershipTransferStatus struct {
	TokenID      string
	CurrentOwner string
	Status       string
	LastUpdated  time.Time
}

// GetOwnershipTransferStatus retrieves the status of an ownership transfer
func GetOwnershipTransferStatus(tokenID string) (*OwnershipTransferStatus, error) {
	currentOwner, err := ledger.GetCurrentOwner(tokenID)
	if err != nil {
		return nil, fmt.Errorf("error retrieving current owner: %v", err)
	}

	status := &OwnershipTransferStatus{
		TokenID:      tokenID,
		CurrentOwner: currentOwner,
		Status:       "Transfer Completed",
		LastUpdated:  time.Now(),
	}

	return status, nil
}
