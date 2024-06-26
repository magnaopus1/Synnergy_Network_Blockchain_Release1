package financialinstitutions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

// Transaction represents the structure of a financial transaction.
type Transaction struct {
	ID         string  `json:"id"`
	Amount     float64 `json:"amount"`
	Currency   string  `json:"currency"`
	Sender     string  `json:"sender"`
	Receiver   string  `json:"receiver"`
	SecureHash string  `json:"secure_hash"`
}

// TransactionLayer handles the processing and security of transactions.
type TransactionLayer struct {
	EncryptionKey []byte
}

// NewTransactionLayer creates a new transaction processing layer with the specified encryption key.
func NewTransactionLayer(key []byte) *TransactionLayer {
	return &TransactionLayer{
		EncryptionKey: key,
	}
}

// ProcessTransaction encrypts and stores the transaction securely.
func (tl *TransactionLayer) ProcessTransaction(tx Transaction) (string, error) {
	txData, err := json.Marshal(tx)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal transaction")
	}

	encryptedData, err := encryptData(txData, tl.EncryptionKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to encrypt transaction data")
	}

	tx.SecureHash = encodeHex(encryptedData)
	// Here you would typically store the transaction in a secure database
	return tx.ID, nil
}

// ValidateTransaction ensures the transaction data matches the encrypted hash.
func (tl *TransactionLayer) ValidateTransaction(tx Transaction) (bool, error) {
	txData, err := json.Marshal(tx)
	if err != nil {
		return false, errors.Wrap(err, "failed to marshal transaction for validation")
	}

	expectedHash, err := encryptData(txData, tl.EncryptionKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to encrypt transaction data for validation")
	}

	return tx.SecureHash == encodeHex(expectedHash), nil
}

// encryptData is a helper function to encrypt data using AES-GCM.
func encryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// encodeHex converts binary data to a hexadecimal string.
func encodeHex(data []byte) string {
	return fmt.Sprintf("%x", data)
}
