package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"time"
)

// Transaction represents a confidential transaction in the blockchain.
type Transaction struct {
	ID          string
	Timestamp   int64
	Sender      string
	Receiver    string
	Amount      float64
	Description string
	Hash        string
	Signature   string
	Nonce       string
}

// Blockchain represents the entire chain of confidential transactions.
type Blockchain struct {
	transactions []*Transaction
}

// NewBlockchain initializes a new blockchain.
func NewBlockchain() *Blockchain {
	return &Blockchain{
		transactions: []*Transaction{},
	}
}

// AddTransaction adds a new confidential transaction to the blockchain.
func (bc *Blockchain) AddTransaction(sender, receiver string, amount float64, description, key string) error {
	timestamp := time.Now().Unix()
	id := generateTransactionID(sender, receiver, amount, timestamp)
	nonce, encryptedDescription, err := encrypt(description, key)
	if err != nil {
		return err
	}

	transaction := &Transaction{
		ID:          id,
		Timestamp:   timestamp,
		Sender:      sender,
		Receiver:    receiver,
		Amount:      amount,
		Description: encryptedDescription,
		Nonce:       nonce,
	}
	transaction.Hash = calculateHash(transaction)
	transaction.Signature = signTransaction(transaction, key)

	bc.transactions = append(bc.transactions, transaction)
	log.Printf("Transaction %s added to the blockchain.\n", transaction.ID)
	return nil
}

// GetTransactions returns the current transactions in the blockchain.
func (bc *Blockchain) GetTransactions() []*Transaction {
	return bc.transactions
}

// VerifyTransaction verifies the integrity and authenticity of a transaction.
func (bc *Blockchain) VerifyTransaction(transaction *Transaction, key string) bool {
	expectedHash := calculateHash(transaction)
	if transaction.Hash != expectedHash {
		return false
	}
	expectedSignature := signTransaction(transaction, key)
	return transaction.Signature == expectedSignature
}

// generateTransactionID generates a unique ID for a transaction.
func generateTransactionID(sender, receiver string, amount float64, timestamp int64) string {
	record := fmt.Sprintf("%s%s%f%d", sender, receiver, amount, timestamp)
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// calculateHash calculates the hash of a transaction.
func calculateHash(transaction *Transaction) string {
	record := fmt.Sprintf("%s%d%s%s%f%s", transaction.ID, transaction.Timestamp, transaction.Sender, transaction.Receiver, transaction.Amount, transaction.Description)
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// signTransaction generates a signature for a transaction.
func signTransaction(transaction *Transaction, key string) string {
	record := fmt.Sprintf("%s%d%s%s%f%s", transaction.ID, transaction.Timestamp, transaction.Sender, transaction.Receiver, transaction.Amount, transaction.Description)
	hash := sha256.Sum256([]byte(record + key))
	return hex.EncodeToString(hash[:])
}

// encrypt encrypts a message using AES encryption.
func encrypt(plainText, key string) (string, string, error) {
	block, err := aes.NewCipher([]byte(createHash(key)))
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}
	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return hex.EncodeToString(nonce), hex.EncodeToString(cipherText), nil
}

// decrypt decrypts a message using AES decryption.
func decrypt(cipherText, nonce, key string) (string, error) {
	block, err := aes.NewCipher([]byte(createHash(key)))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil {
		return "", err
	}
	cipherTextBytes, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	plainText, err := gcm.Open(nil, nonceBytes, cipherTextBytes, nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

// createHash creates a SHA-256 hash of a given key.
func createHash(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// StoreBlockchain stores the blockchain to a file.
func (bc *Blockchain) StoreBlockchain(filename string) error {
	data := ""
	for _, tx := range bc.transactions {
		data += fmt.Sprintf("%s,%d,%s,%s,%f,%s,%s,%s\n", tx.ID, tx.Timestamp, tx.Sender, tx.Receiver, tx.Amount, tx.Description, tx.Hash, tx.Signature)
	}
	return ioutil.WriteFile(filename, []byte(data), 0644)
}

// LoadBlockchain loads the blockchain from a file.
func (bc *Blockchain) LoadBlockchain(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	bc.transactions = []*Transaction{}
	lines := string(data)
	for _, line := range lines {
		if line != "" {
			tx := parseTransaction(line)
			bc.transactions = append(bc.transactions, tx)
		}
	}
	return nil
}

// parseTransaction parses a transaction from a string.
func parseTransaction(line string) *Transaction {
	var id, sender, receiver, description, hash, signature string
	var timestamp int64
	var amount float64
	fmt.Sscanf(line, "%s,%d,%s,%s,%f,%s,%s,%s", &id, &timestamp, &sender, &receiver, &amount, &description, &hash, &signature)
	return &Transaction{
		ID:          id,
		Timestamp:   timestamp,
		Sender:      sender,
		Receiver:    receiver,
		Amount:      amount,
		Description: description,
		Hash:        hash,
		Signature:   signature,
	}
}
