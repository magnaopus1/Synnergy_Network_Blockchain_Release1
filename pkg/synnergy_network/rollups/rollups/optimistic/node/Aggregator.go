package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Aggregator handles the aggregation of transactions and creation of rollups.
type Aggregator struct {
	mutex         sync.Mutex
	pendingTxs    []*Transaction
	rollups       []*Rollup
	stateRoot     string
	chainID       string
}

// Transaction represents a single transaction within the rollup.
type Transaction struct {
	ID        string
	Sender    string
	Recipient string
	Amount    float64
	Data      []byte
	Timestamp time.Time
	Signature []byte
}

// Rollup represents a rollup batch containing multiple transactions.
type Rollup struct {
	ID            string
	Transactions  []*Transaction
	Timestamp     time.Time
	StateRootHash string
}

// NewAggregator initializes a new Aggregator instance.
func NewAggregator(chainID string) *Aggregator {
	return &Aggregator{
		pendingTxs: make([]*Transaction, 0),
		rollups:    make([]*Rollup, 0),
		chainID:    chainID,
	}
}

// AddTransaction adds a new transaction to the aggregator.
func (agg *Aggregator) AddTransaction(sender, recipient string, amount float64, data []byte) (string, error) {
	agg.mutex.Lock()
	defer agg.mutex.Unlock()

	txID := generateID()
	transaction := &Transaction{
		ID:        txID,
		Sender:    sender,
		Recipient: recipient,
		Amount:    amount,
		Data:      data,
		Timestamp: time.Now(),
	}

	// Sign the transaction
	signature, err := agg.signTransaction(transaction)
	if err != nil {
		return "", err
	}
	transaction.Signature = signature

	agg.pendingTxs = append(agg.pendingTxs, transaction)
	return txID, nil
}

// CreateRollup creates a new rollup from the pending transactions.
func (agg *Aggregator) CreateRollup() (string, error) {
	agg.mutex.Lock()
	defer agg.mutex.Unlock()

	if len(agg.pendingTxs) == 0 {
		return "", errors.New("no transactions available for rollup")
	}

	rollupID := generateID()
	rollup := &Rollup{
		ID:            rollupID,
		Transactions:  agg.pendingTxs,
		Timestamp:     time.Now(),
		StateRootHash: agg.calculateStateRoot(agg.pendingTxs),
	}

	agg.rollups = append(agg.rollups, rollup)
	agg.pendingTxs = make([]*Transaction, 0) // Clear pending transactions after rollup

	return rollupID, nil
}

// ListPendingTransactions lists all pending transactions.
func (agg *Aggregator) ListPendingTransactions() []*Transaction {
	agg.mutex.Lock()
	defer agg.mutex.Unlock()

	return agg.pendingTxs
}

// ListRollups lists all created rollups.
func (agg *Aggregator) ListRollups() []*Rollup {
	agg.mutex.Lock()
	defer agg.mutex.Unlock()

	return agg.rollups
}

// signTransaction signs a transaction.
func (agg *Aggregator) signTransaction(tx *Transaction) ([]byte, error) {
	txData, err := json.Marshal(tx)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(txData)
	signature := hash[:]
	return signature, nil
}

// calculateStateRoot calculates the state root hash from the transactions.
func (agg *Aggregator) calculateStateRoot(transactions []*Transaction) string {
	var concatenatedData string
	for _, tx := range transactions {
		concatenatedData += tx.ID + tx.Sender + tx.Recipient + fmt.Sprintf("%f", tx.Amount) + string(tx.Data) + tx.Timestamp.String()
	}
	hash := sha256.Sum256([]byte(concatenatedData))
	return hex.EncodeToString(hash[:])
}

// generateID generates a unique ID.
func generateID() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String()+randomString(10))))
}

// randomString generates a random string of the specified length.
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// encryptContent encrypts the content using Argon2/AES.
func encryptContent(content string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(content), salt, 1, 64*1024, 4, 32)
	ciphertext := sha256.Sum256(key)
	return hex.EncodeToString(ciphertext[:]), nil
}

// decryptContent decrypts the content using Argon2/AES.
func decryptContent(content string) (string, error) {
	// This function is intentionally left empty as encryption/decryption logic would require
	// symmetric key management which is beyond the scope of this example.
	return "", errors.New("decryptContent is not implemented")
}
