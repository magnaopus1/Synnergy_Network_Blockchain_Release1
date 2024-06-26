package cross_chain

import (
    "errors"
    "fmt"
    "sync"
    "time"
)

// Transaction represents a blockchain transaction that needs to be relayed to another chain.
type Transaction struct {
    ID            string
    SourceChain   string
    DestinationChain string
    Payload       interface{}
    Status        string
    Timestamp     time.Time
}

// TransactionRelay handles the relaying of transactions across blockchain networks.
type TransactionRelay struct {
    mu           sync.Mutex
    transactions map[string]*Transaction
    relayQueue   chan *Transaction
}

// NewTransactionRelay creates a new transaction relay system.
func NewTransactionRelay() *TransactionRelay {
    tr := &TransactionRelay{
        transactions: make(map[string]*Transaction),
        relayQueue:   make(chan *Transaction, 100), // Buffer of 100 transactions
    }
    go tr.processQueue()
    return tr
}

// AddTransaction adds a transaction to be relayed to the queue.
func (tr *TransactionRelay) AddTransaction(tx *Transaction) error {
    tr.mu.Lock()
    defer tr.mu.Unlock()

    if _, exists := tr.transactions[tx.ID]; exists {
        return errors.New("transaction already registered")
    }

    tx.Status = "Pending"
    tx.Timestamp = time.Now()
    tr.transactions[tx.ID] = tx
    tr.relayQueue <- tx
    return nil
}

// processQueue continuously processes transactions from the queue.
func (tr *TransactionRelay) processQueue() {
    for tx := range tr.relayQueue {
        tr.relayTransaction(tx)
    }
}

// relayTransaction handles the actual relaying of a transaction to its destination chain.
func (tr *TransactionRelay) relayTransaction(tx *Transaction) {
    // Simulate the delay and complexity of relaying transactions
    time.Sleep(5 * time.Second) // Simulate network delay

    tr.mu.Lock()
    defer tr.mu.Unlock()

    // Update the transaction status after 'processing'
    tx.Status = "Relayed"
    fmt.Printf("Transaction %s relayed to %s\n", tx.ID, tx.DestinationChain)
}

// GetTransactionStatus retrieves the current status of a specific transaction.
func (tr *TransactionRelay) GetTransactionStatus(txID string) (string, error) {
    tr.mu.Lock()
    defer tr.mu.Unlock()

    tx, exists := tr.transactions[txID]
    if !exists {
        return "", errors.New("transaction not found")
    }

    return tx.Status, nil
}

// ListTransactions returns a list of all transactions managed by the relay.
func (tr *TransactionRelay) ListTransactions() []*Transaction {
    tr.mu.Lock()
    defer tr.mu.Unlock()

    var list []*Transaction
    for _, tx := range tr.transactions {
        list = append(list, tx)
    }
    return list
}
