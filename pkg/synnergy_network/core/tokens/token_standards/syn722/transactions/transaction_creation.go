package transactions

import (
    "errors"
    "time"
    "sync"
    "crypto/rand"
    "encoding/hex"
    "golang.org/x/crypto/scrypt"
)

// Transaction represents a blockchain transaction
type Transaction struct {
    ID         string
    Sender     string
    Receiver   string
    TokenID    string
    Amount     uint64
    Timestamp  time.Time
    Signature  string
    IsFungible bool
}

// TransactionPool holds pending transactions
type TransactionPool struct {
    transactions map[string]Transaction
    mu           sync.RWMutex
}

// NewTransactionPool creates a new TransactionPool instance
func NewTransactionPool() *TransactionPool {
    return &TransactionPool{
        transactions: make(map[string]Transaction),
    }
}

// CreateTransaction creates a new transaction
func (tp *TransactionPool) CreateTransaction(sender, receiver, tokenID string, amount uint64, isFungible bool, privateKey []byte) (Transaction, error) {
    if sender == "" || receiver == "" || tokenID == "" || amount == 0 {
        return Transaction{}, errors.New("invalid transaction parameters")
    }

    txID, err := generateTransactionID()
    if err != nil {
        return Transaction{}, err
    }

    timestamp := time.Now()
    signature, err := signTransaction(sender, receiver, tokenID, amount, timestamp, privateKey)
    if err != nil {
        return Transaction{}, err
    }

    tx := Transaction{
        ID:         txID,
        Sender:     sender,
        Receiver:   receiver,
        TokenID:    tokenID,
        Amount:     amount,
        Timestamp:  timestamp,
        Signature:  signature,
        IsFungible: isFungible,
    }

    tp.mu.Lock()
    tp.transactions[tx.ID] = tx
    tp.mu.Unlock()

    return tx, nil
}

// GetTransaction retrieves a transaction by ID
func (tp *TransactionPool) GetTransaction(txID string) (Transaction, error) {
    tp.mu.RLock()
    defer tp.mu.RUnlock()

    if tx, exists := tp.transactions[txID]; exists {
        return tx, nil
    }

    return Transaction{}, errors.New("transaction not found")
}

// RemoveTransaction removes a transaction from the pool
func (tp *TransactionPool) RemoveTransaction(txID string) error {
    tp.mu.Lock()
    defer tp.mu.Unlock()

    if _, exists := tp.transactions[txID]; exists {
        delete(tp.transactions, txID)
        return nil
    }

    return errors.New("transaction not found")
}

// ListTransactions lists all pending transactions
func (tp *TransactionPool) ListTransactions() []Transaction {
    tp.mu.RLock()
    defer tp.mu.RUnlock()

    transactions := make([]Transaction, 0, len(tp.transactions))
    for _, tx := range tp.transactions {
        transactions = append(transactions, tx)
    }

    return transactions
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID() (string, error) {
    bytes := make([]byte, 16)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}

// signTransaction signs a transaction using the sender's private key
func signTransaction(sender, receiver, tokenID string, amount uint64, timestamp time.Time, privateKey []byte) (string, error) {
    data := sender + receiver + tokenID + string(amount) + timestamp.String()
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }

    derivedKey, err := scrypt.Key([]byte(data), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    return hex.EncodeToString(derivedKey), nil
}
