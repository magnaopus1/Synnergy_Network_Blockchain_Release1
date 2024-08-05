package encryption

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
)

// DataIntegrity provides functionalities to ensure the integrity of data in the blockchain.
type DataIntegrity struct{}

// NewDataIntegrity creates a new DataIntegrity instance.
func NewDataIntegrity() *DataIntegrity {
	return &DataIntegrity{}
}

// HashData computes the SHA-256 hash of the given data.
func (di *DataIntegrity) HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// VerifyDataHash verifies that the hash of the given data matches the provided hash.
func (di *DataIntegrity) VerifyDataHash(data []byte, providedHash string) bool {
	calculatedHash := di.HashData(data)
	return subtle.ConstantTimeCompare([]byte(calculatedHash), []byte(providedHash)) == 1
}

// ValidateTransactionIntegrity validates the integrity of a transaction.
func (di *DataIntegrity) ValidateTransactionIntegrity(transaction *Transaction) bool {
	calculatedHash := calculateHash(transaction)
	return subtle.ConstantTimeCompare([]byte(calculatedHash), []byte(transaction.Hash)) == 1
}

// AuditBlockchain performs a full audit of the blockchain to verify the integrity of all transactions.
func (di *DataIntegrity) AuditBlockchain(blockchain *Blockchain) error {
	for _, tx := range blockchain.GetTransactions() {
		if !di.ValidateTransactionIntegrity(tx) {
			return errors.New("data integrity check failed for transaction: " + tx.ID)
		}
	}
	log.Println("Blockchain data integrity audit successful.")
	return nil
}

// RepairBlockchain attempts to repair the blockchain by recalculating hashes for all transactions.
func (di *DataIntegrity) RepairBlockchain(blockchain *Blockchain) {
	for _, tx := range blockchain.GetTransactions() {
		tx.Hash = calculateHash(tx)
	}
	log.Println("Blockchain data integrity repair completed.")
}

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

// encrypt and other required functions are assumed to be implemented similarly to the ConfidentialTransactions file.
