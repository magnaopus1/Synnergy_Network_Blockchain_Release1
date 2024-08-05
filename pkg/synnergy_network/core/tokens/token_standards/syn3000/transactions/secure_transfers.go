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

// SecureTransfer represents a secure transfer transaction
type SecureTransfer struct {
	TransactionID  string
	TokenID        string
	FromAddress    string
	ToAddress      string
	TransferDate   time.Time
	Amount         float64
	EncryptedData  string
}

// SecureTransferHandler handles secure transfers of SYN3000 tokens
type SecureTransferHandler struct {
	Transfers []SecureTransfer
}

// AddTransfer adds a new secure transfer to the handler
func (sth *SecureTransferHandler) AddTransfer(tokenID, fromAddress, toAddress string, amount float64) (*SecureTransfer, error) {
	transfer := &SecureTransfer{
		TokenID:       tokenID,
		FromAddress:   fromAddress,
		ToAddress:     toAddress,
		TransferDate:  time.Now(),
		Amount:        amount,
	}

	// Encrypt transfer details
	encryptedData, err := encryptTransferDetails(transfer)
	if err != nil {
		return nil, fmt.Errorf("error encrypting transfer details: %v", err)
	}
	transfer.EncryptedData = encryptedData

	// Generate transaction ID
	transfer.TransactionID = generateTransactionID(transfer)

	// Append transfer to handler
	sth.Transfers = append(sth.Transfers, *transfer)

	// Log transfer event
	if err := logTransferEvent(transfer); err != nil {
		return nil, fmt.Errorf("error logging transfer event: %v", err)
	}

	return transfer, nil
}

// encryptTransferDetails encrypts the transfer details
func encryptTransferDetails(transfer *SecureTransfer) (string, error) {
	key := sha256.Sum256([]byte("some-very-secure-key"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	plaintext := fmt.Sprintf("%s|%s|%s|%s|%f", transfer.TokenID, transfer.FromAddress, transfer.ToAddress, transfer.TransferDate, transfer.Amount)
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
func decryptTransferDetails(encryptedData string) (*SecureTransfer, error) {
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
	var tokenID, fromAddress, toAddress string
	var transferDate time.Time
	var amount float64
	_, err = fmt.Sscanf(plaintext, "%s|%s|%s|%s|%f", &tokenID, &fromAddress, &toAddress, &transferDate, &amount)
	if err != nil {
		return nil, err
	}

	return &SecureTransfer{
		TokenID:       tokenID,
		FromAddress:   fromAddress,
		ToAddress:     toAddress,
		TransferDate:  transferDate,
		Amount:        amount,
	}, nil
}

// generateTransactionID generates a unique transaction ID for the transfer
func generateTransactionID(transfer *SecureTransfer) string {
	data := fmt.Sprintf("%s%s%s%s%f", transfer.TokenID, transfer.FromAddress, transfer.ToAddress, transfer.TransferDate, transfer.Amount)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// logTransferEvent logs the secure transfer event
func logTransferEvent(transfer *SecureTransfer) error {
	event := fmt.Sprintf("Secure transfer %s: token %s transferred from %s to %s on %s for amount %f", transfer.TransactionID, transfer.TokenID, transfer.FromAddress, transfer.ToAddress, transfer.TransferDate, transfer.Amount)
	return security.LogEvent(event)
}

// GetTransferHistory retrieves the transfer history for a given token
func (sth *SecureTransferHandler) GetTransferHistory(tokenID string) ([]SecureTransfer, error) {
	var history []SecureTransfer
	for _, transfer := range sth.Transfers {
		if transfer.TokenID == tokenID {
			history = append(history, transfer)
		}
	}
	if len(history) == 0 {
		return nil, errors.New("no transfers found for the given token ID")
	}
	return history, nil
}

// VerifyTransfer verifies the integrity of a secure transfer
func (sth *SecureTransferHandler) VerifyTransfer(transactionID string) (bool, error) {
	for _, transfer := range sth.Transfers {
		if transfer.TransactionID == transactionID {
			decryptedTransfer, err := decryptTransferDetails(transfer.EncryptedData)
			if err != nil {
				return false, fmt.Errorf("error decrypting transfer details: %v", err)
			}
			expectedID := generateTransactionID(decryptedTransfer)
			return expectedID == transactionID, nil
		}
	}
	return false, errors.New("transfer not found")
}
