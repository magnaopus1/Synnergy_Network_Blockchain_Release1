package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// TransactionEncryption provides methods for encrypting and decrypting transaction data.
type TransactionEncryption struct{}

// NewTransactionEncryption creates a new instance of TransactionEncryption.
func NewTransactionEncryption() *TransactionEncryption {
	return &TransactionEncryption{}
}

// GenerateKey generates a new encryption key using SHA-256 hash function.
func (te *TransactionEncryption) GenerateKey(passphrase string) ([]byte, error) {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:], nil
}

// EncryptData encrypts the given data using AES encryption.
func (te *TransactionEncryption) EncryptData(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given encrypted data using AES decryption.
func (te *TransactionEncryption) DecryptData(encryptedData string, key []byte) ([]byte, error) {
	ciphertext, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Transaction represents a transaction in the blockchain.
type Transaction struct {
	ID          string
	Sender      string
	Receiver    string
	Amount      float64
	Description string
}

// EncryptTransaction encrypts the details of a transaction.
func (te *TransactionEncryption) EncryptTransaction(tx *Transaction, passphrase string) (*Transaction, error) {
	key, err := te.GenerateKey(passphrase)
	if err != nil {
		return nil, err
	}

	encryptedDescription, err := te.EncryptData([]byte(tx.Description), key)
	if err != nil {
		return nil, err
	}

	encryptedTx := &Transaction{
		ID:          tx.ID,
		Sender:      tx.Sender,
		Receiver:    tx.Receiver,
		Amount:      tx.Amount,
		Description: encryptedDescription,
	}

	return encryptedTx, nil
}

// DecryptTransaction decrypts the details of a transaction.
func (te *TransactionEncryption) DecryptTransaction(encryptedTx *Transaction, passphrase string) (*Transaction, error) {
	key, err := te.GenerateKey(passphrase)
	if err != nil {
		return nil, err
	}

	decryptedDescription, err := te.DecryptData(encryptedTx.Description, key)
	if err != nil {
		return nil, err
	}

	tx := &Transaction{
		ID:          encryptedTx.ID,
		Sender:      encryptedTx.Sender,
		Receiver:    encryptedTx.Receiver,
		Amount:      encryptedTx.Amount,
		Description: string(decryptedDescription),
	}

	return tx, nil
}

// Blockchain represents the entire chain of transactions.
type Blockchain struct {
	transactions []*Transaction
}

// NewBlockchain initializes a new blockchain.
func NewBlockchain() *Blockchain {
	return &Blockchain{
		transactions: []*Transaction{},
	}
}

// AddTransaction adds a new encrypted transaction to the blockchain.
func (bc *Blockchain) AddTransaction(tx *Transaction, passphrase string) error {
	te := NewTransactionEncryption()
	encryptedTx, err := te.EncryptTransaction(tx, passphrase)
	if err != nil {
		return err
	}

	bc.transactions = append(bc.transactions, encryptedTx)
	return nil
}

// GetTransaction returns a decrypted transaction from the blockchain by ID.
func (bc *Blockchain) GetTransaction(id string, passphrase string) (*Transaction, error) {
	for _, tx := range bc.transactions {
		if tx.ID == id {
			te := NewTransactionEncryption()
			return te.DecryptTransaction(tx, passphrase)
		}
	}
	return nil, errors.New("transaction not found")
}

// ListTransactions lists all decrypted transactions in the blockchain.
func (bc *Blockchain) ListTransactions(passphrase string) ([]*Transaction, error) {
	var decryptedTransactions []*Transaction
	te := NewTransactionEncryption()
	for _, tx := range bc.transactions {
		decryptedTx, err := te.DecryptTransaction(tx, passphrase)
		if err != nil {
			return nil, err
		}
		decryptedTransactions = append(decryptedTransactions, decryptedTx)
	}
	return decryptedTransactions, nil
}
