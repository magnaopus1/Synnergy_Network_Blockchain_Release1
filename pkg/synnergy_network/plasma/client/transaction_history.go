package client

import (
    "errors"
    "fmt"
    "sync"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

// TransactionHistory represents the transaction history for a client
type TransactionHistory struct {
    Address      string
    Transactions []child_chain.Transaction
    mu           sync.Mutex
    Blockchain   *child_chain.Blockchain
}

// NewTransactionHistory creates a new TransactionHistory for a given address
func NewTransactionHistory(address string, blockchain *child_chain.Blockchain) *TransactionHistory {
    return &TransactionHistory{
        Address:    address,
        Blockchain: blockchain,
    }
}

// fetchTransactionHistory fetches the transaction history for the client from the blockchain
func (th *TransactionHistory) fetchTransactionHistory() error {
    th.mu.Lock()
    defer th.mu.Unlock()

    history, err := th.Blockchain.GetTransactionHistory(th.Address)
    if err != nil {
        return err
    }

    th.Transactions = history
    return nil
}

// addTransaction adds a new transaction to the history
func (th *TransactionHistory) addTransaction(tx child_chain.Transaction) {
    th.mu.Lock()
    defer th.mu.Unlock()

    th.Transactions = append(th.Transactions, tx)
}

// getTransactionHistory retrieves the stored transaction history
func (th *TransactionHistory) getTransactionHistory() []child_chain.Transaction {
    th.mu.Lock()
    defer th.mu.Unlock()

    return th.Transactions
}

// displayTransactionHistory prints the transaction history for the client
func (th *TransactionHistory) displayTransactionHistory() {
    th.mu.Lock()
    defer th.mu.Unlock()

    fmt.Printf("Transaction History for %s:\n", th.Address)
    for _, tx := range th.Transactions {
        fmt.Printf("From: %s, To: %s, Amount: %d, Fee: %d, Hash: %s\n", tx.From, tx.To, tx.Amount, tx.Fee, tx.Hash)
    }
}

// getTransaction retrieves a specific transaction from the history by hash
func (th *TransactionHistory) getTransaction(hash string) (*child_chain.Transaction, error) {
    th.mu.Lock()
    defer th.mu.Unlock()

    for _, tx := range th.Transactions {
        if tx.Hash == hash {
            return &tx, nil
        }
    }
    return nil, errors.New("transaction not found")
}

// removeTransaction removes a transaction from the history by hash
func (th *TransactionHistory) removeTransaction(hash string) error {
    th.mu.Lock()
    defer th.mu.Unlock()

    for i, tx := range th.Transactions {
        if tx.Hash == hash {
            th.Transactions = append(th.Transactions[:i], th.Transactions[i+1:]...)
            return nil
        }
    }
    return errors.New("transaction not found")
}

// countTransactions returns the total number of transactions in the history
func (th *TransactionHistory) countTransactions() int {
    th.mu.Lock()
    defer th.mu.Unlock()

    return len(th.Transactions)
}

// filterTransactionsByAmount filters transactions by a minimum amount
func (th *TransactionHistory) filterTransactionsByAmount(minAmount int) []child_chain.Transaction {
    th.mu.Lock()
    defer th.mu.Unlock()

    var filtered []child_chain.Transaction
    for _, tx := range th.Transactions {
        if tx.Amount >= minAmount {
            filtered = append(filtered, tx)
        }
    }
    return filtered
}
