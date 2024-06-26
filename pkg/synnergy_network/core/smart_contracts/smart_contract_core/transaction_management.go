package smart_contract_core

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	ID            string
	From          string
	To            string
	Value         int64
	GasPrice      int64
	GasLimit      int64
	Nonce         int
	Data          string
	Signature     string
	Timestamp     time.Time
}

// TransactionPool holds all the transactions waiting to be mined
type TransactionPool struct {
	Transactions map[string]*Transaction
}

// NewTransactionPool initializes a new transaction pool
func NewTransactionPool() *TransactionPool {
	return &TransactionPool{
		Transactions: make(map[string]*Transaction),
	}
}

// AddTransaction adds a new transaction to the pool
func (tp *TransactionPool) AddTransaction(tx *Transaction) error {
	if _, exists := tp.Transactions[tx.ID]; exists {
		return errors.New("transaction already exists in the pool")
	}
	tp.Transactions[tx.ID] = tx
	return nil
}

// RemoveTransaction removes a transaction from the pool
func (tp *TransactionPool) RemoveTransaction(txID string) error {
	if _, exists := tp.Transactions[txID]; !exists {
		return errors.New("transaction not found in the pool")
	}
	delete(tp.Transactions, txID)
	return nil
}

// GetTransaction retrieves a transaction from the pool
func (tp *TransactionPool) GetTransaction(txID string) (*Transaction, error) {
	tx, exists := tp.Transactions[txID]
	if !exists {
		return nil, errors.New("transaction not found in the pool")
	}
	return tx, nil
}

// TransactionProcessor processes transactions
type TransactionProcessor struct {
	Pool *TransactionPool
}

// NewTransactionProcessor initializes a new transaction processor
func NewTransactionProcessor(pool *TransactionPool) *TransactionProcessor {
	return &TransactionProcessor{
		Pool: pool,
	}
}

// ProcessTransaction processes a transaction
func (tp *TransactionProcessor) ProcessTransaction(tx *Transaction) error {
	// Simulate processing by removing the transaction from the pool
	return tp.Pool.RemoveTransaction(tx.ID)
}

// TransactionBuilder helps in building new transactions
type TransactionBuilder struct {
	from      string
	to        string
	value     int64
	gasPrice  int64
	gasLimit  int64
	nonce     int
	data      string
	signature string
}

// NewTransactionBuilder initializes a new transaction builder
func NewTransactionBuilder() *TransactionBuilder {
	return &TransactionBuilder{}
}

// SetFrom sets the sender of the transaction
func (tb *TransactionBuilder) SetFrom(from string) *TransactionBuilder {
	tb.from = from
	return tb
}

// SetTo sets the receiver of the transaction
func (tb *TransactionBuilder) SetTo(to string) *TransactionBuilder {
	tb.to = to
	return tb
}

// SetValue sets the value of the transaction
func (tb *TransactionBuilder) SetValue(value int64) *TransactionBuilder {
	tb.value = value
	return tb
}

// SetGasPrice sets the gas price for the transaction
func (tb *TransactionBuilder) SetGasPrice(gasPrice int64) *TransactionBuilder {
	tb.gasPrice = gasPrice
	return tb
}

// SetGasLimit sets the gas limit for the transaction
func (tb *TransactionBuilder) SetGasLimit(gasLimit int64) *TransactionBuilder {
	tb.gasLimit = gasLimit
	return tb
}

// SetNonce sets the nonce for the transaction
func (tb *TransactionBuilder) SetNonce(nonce int) *TransactionBuilder {
	tb.nonce = nonce
	return tb
}

// SetData sets the data for the transaction
func (tb *TransactionBuilder) SetData(data string) *TransactionBuilder {
	tb.data = data
	return tb
}

// SetSignature sets the signature for the transaction
func (tb *TransactionBuilder) SetSignature(signature string) *TransactionBuilder {
	tb.signature = signature
	return tb
}

// Build builds the transaction
func (tb *TransactionBuilder) Build() *Transaction {
	txID := generateTransactionID(tb.from, tb.to, tb.value, tb.nonce)
	return &Transaction{
		ID:        txID,
		From:      tb.from,
		To:        tb.to,
		Value:     tb.value,
		GasPrice:  tb.gasPrice,
		GasLimit:  tb.gasLimit,
		Nonce:     tb.nonce,
		Data:      tb.data,
		Signature: tb.signature,
		Timestamp: time.Now(),
	}
}

// generateTransactionID generates a unique ID for the transaction
func generateTransactionID(from string, to string, value int64, nonce int) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s%s%d%d", from, to, value, nonce)))
	return hex.EncodeToString(hash.Sum(nil))
}

// SignTransaction signs the transaction
func SignTransaction(tx *Transaction, privateKey string) error {
	signature, err := signData(tx.ID, privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}
	tx.Signature = signature
	return nil
}

// signData signs the data with the provided private key
func signData(data string, privateKey string) (string, error) {
	// Simplified signing function, replace with actual cryptographic signing
	hash := sha256.New()
	hash.Write([]byte(data + privateKey))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// VerifyTransaction verifies the transaction signature
func VerifyTransaction(tx *Transaction, publicKey string) bool {
	expectedSignature, err := signData(tx.ID, publicKey)
	if err != nil {
		return false
	}
	return tx.Signature == expectedSignature
}

// SerializeTransaction serializes the transaction to JSON
func SerializeTransaction(tx *Transaction) (string, error) {
	data, err := json.Marshal(tx)
	if err != nil {
		return "", fmt.Errorf("failed to serialize transaction: %v", err)
	}
	return string(data), nil
}

// DeserializeTransaction deserializes the transaction from JSON
func DeserializeTransaction(data string) (*Transaction, error) {
	var tx Transaction
	if err := json.Unmarshal([]byte(data), &tx); err != nil {
		return nil, fmt.Errorf("failed to deserialize transaction: %v", err)
	}
	return &tx, nil
}
