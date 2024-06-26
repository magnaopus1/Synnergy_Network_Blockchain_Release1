package security

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	Salt       = "secure-unique-salt"
	KeyLength  = 32
	ScryptN    = 16384
	ScryptR    = 8
	ScryptP    = 1
	ArgonTime  = 1
	ArgonMemory = 64 * 1024
	ArgonThreads = 4
	ArgonKeyLength = 32
)

// Transaction represents the structure of a blockchain transaction
type Transaction struct {
	ID        string
	Timestamp time.Time
	From      string
	To        string
	Amount    float64
	Signature string
}

// TransactionPool stores all the unconfirmed transactions
type TransactionPool struct {
	sync.Mutex
	Pool map[string]Transaction
}

// NewTransactionPool initializes a new transaction pool
func NewTransactionPool() *TransactionPool {
	return &TransactionPool{
		Pool: make(map[string]Transaction),
	}
}

// AddTransaction adds a new transaction to the pool if it passes double spend checks
func (tp *TransactionPool) AddTransaction(tx Transaction) error {
	tp.Lock()
	defer tp.Unlock()

	if _, exists := tp.Pool[tx.ID]; exists {
		return errors.New("transaction already exists")
	}

	if !tp.verifyTransaction(tx) {
		return errors.New("failed to verify transaction")
	}

	tp.Pool[tx.ID] = tx
	return nil
}

// verifyTransaction ensures the transaction has not been spent already
func (tp *TransactionPool) verifyTransaction(tx Transaction) bool {
	// Dummy logic for transaction verification
	// Implement specific logic to verify transaction against blockchain and UTXO set
	return true
}

// GenerateTransactionID generates a unique ID for each transaction based on its contents
func GenerateTransactionID(tx Transaction) string {
	input := tx.From + tx.To + time.Now().String() + string(tx.Amount)
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// EncryptData uses Argon2 to encrypt data
func EncryptData(data []byte) []byte {
	salt := []byte(Salt)
	return argon2.IDKey(data, salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLength)
}

// DecryptData uses Scrypt to decrypt data
func DecryptData(data []byte) ([]byte, error) {
	dk, err := scrypt.Key(data, []byte(Salt), ScryptN, ScryptR, ScryptP, KeyLength)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

func main() {
	tp := NewTransactionPool()
	tx := Transaction{
		ID:        GenerateTransactionID(Transaction{From: "Alice", To: "Bob", Amount: 100}),
		Timestamp: time.Now(),
		From:      "Alice",
		To:        "Bob",
		Amount:    100,
		Signature: "signature",
	}

	if err := tp.AddTransaction(tx); err != nil {
		panic(err)
	}
}
