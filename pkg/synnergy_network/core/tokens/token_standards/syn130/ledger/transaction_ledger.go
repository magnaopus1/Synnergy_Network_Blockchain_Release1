package ledger

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

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn130/storage"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn130/utils"
)

type Transaction struct {
	ID              string
	AssetID         string
	FromOwner       string
	ToOwner         string
	Timestamp       time.Time
	TransactionHash string
	Metadata        map[string]string
}

type TransactionLedger struct {
	transactions map[string]Transaction
	cipher       cipher.Block
	storage      storage.Storage
}

// NewTransactionLedger creates a new TransactionLedger instance with AES encryption
func NewTransactionLedger(encryptionKey string, storage storage.Storage) (*TransactionLedger, error) {
	keyHash := sha256.Sum256([]byte(encryptionKey))
	cipherBlock, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	return &TransactionLedger{
		transactions: make(map[string]Transaction),
		cipher:       cipherBlock,
		storage:      storage,
	}, nil
}

// AddTransaction creates and adds a new transaction to the ledger
func (tl *TransactionLedger) AddTransaction(assetID, fromOwner, toOwner string, metadata map[string]string) (Transaction, error) {
	timestamp := time.Now()
	transactionHash, err := tl.generateTransactionHash(assetID, fromOwner, toOwner, timestamp)
	if err != nil {
		return Transaction{}, err
	}

	transaction := Transaction{
		ID:              utils.GenerateUniqueID(),
		AssetID:         assetID,
		FromOwner:       fromOwner,
		ToOwner:         toOwner,
		Timestamp:       timestamp,
		TransactionHash: transactionHash,
		Metadata:        metadata,
	}

	tl.transactions[transaction.ID] = transaction
	if err := tl.saveToStorage(transaction); err != nil {
		return Transaction{}, err
	}

	return transaction, nil
}

// GetTransaction retrieves the transaction record for a given transaction ID
func (tl *TransactionLedger) GetTransaction(transactionID string) (Transaction, error) {
	transaction, exists := tl.transactions[transactionID]
	if !exists {
		return Transaction{}, errors.New("transaction not found")
	}
	return transaction, nil
}

// GetTransactionsByAssetID retrieves all transactions for a given asset ID
func (tl *TransactionLedger) GetTransactionsByAssetID(assetID string) ([]Transaction, error) {
	var transactions []Transaction
	for _, transaction := range tl.transactions {
		if transaction.AssetID == assetID {
			transactions = append(transactions, transaction)
		}
	}
	return transactions, nil
}

// ValidateTransaction verifies the integrity of a transaction
func (tl *TransactionLedger) ValidateTransaction(transactionID string) (bool, error) {
	transaction, err := tl.GetTransaction(transactionID)
	if err != nil {
		return false, err
	}

	generatedHash, err := tl.generateTransactionHash(transaction.AssetID, transaction.FromOwner, transaction.ToOwner, transaction.Timestamp)
	if err != nil {
		return false, err
	}

	return generatedHash == transaction.TransactionHash, nil
}

// generateTransactionHash generates a secure hash for a transaction
func (tl *TransactionLedger) generateTransactionHash(assetID, fromOwner, toOwner string, timestamp time.Time) (string, error) {
	data := fmt.Sprintf("%s:%s:%s:%d", assetID, fromOwner, toOwner, timestamp.Unix())
	encryptedData, err := tl.encrypt([]byte(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encryptedData), nil
}

// encrypt encrypts data using AES encryption
func (tl *TransactionLedger) encrypt(data []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(tl.cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	encryptedData := gcm.Seal(nonce, nonce, data, nil)
	return encryptedData, nil
}

// decrypt decrypts data using AES encryption
func (tl *TransactionLedger) decrypt(data []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(tl.cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return decryptedData, nil
}

// saveToStorage saves the transaction to persistent storage
func (tl *TransactionLedger) saveToStorage(transaction Transaction) error {
	data, err := utils.MarshalJSON(transaction)
	if err != nil {
		return err
	}

	encryptedData, err := tl.encrypt(data)
	if err != nil {
		return err
	}

	return tl.storage.Save(transaction.ID, encryptedData)
}

// loadFromStorage loads a transaction from persistent storage
func (tl *TransactionLedger) loadFromStorage(transactionID string) (Transaction, error) {
	encryptedData, err := tl.storage.Load(transactionID)
	if err != nil {
		return Transaction{}, err
	}

	data, err := tl.decrypt(encryptedData)
	if err != nil {
		return Transaction{}, err
	}

	var transaction Transaction
	if err := utils.UnmarshalJSON(data, &transaction); err != nil {
		return Transaction{}, err
	}

	tl.transactions[transactionID] = transaction
	return transaction, nil
}
