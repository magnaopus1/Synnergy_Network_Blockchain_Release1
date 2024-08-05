package client

import (
    "errors"
    "fmt"
    "sync"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

// TransactionSubmission handles the submission and management of transactions for a client
type TransactionSubmission struct {
    Client        *Client
    PendingTxs    map[string]child_chain.Transaction
    mu            sync.Mutex
    Blockchain    *child_chain.Blockchain
    PendingTxChan chan child_chain.Transaction
}

// NewTransactionSubmission creates a new TransactionSubmission for a client
func NewTransactionSubmission(client *Client, blockchain *child_chain.Blockchain) *TransactionSubmission {
    ts := &TransactionSubmission{
        Client:        client,
        Blockchain:    blockchain,
        PendingTxs:    make(map[string]child_chain.Transaction),
        PendingTxChan: make(chan child_chain.Transaction, 100),
    }
    go ts.processPendingTransactions()
    return ts
}

// SubmitTransaction creates and submits a transaction from the client
func (ts *TransactionSubmission) SubmitTransaction(to string, amount, fee int) (string, error) {
    ts.mu.Lock()
    defer ts.mu.Unlock()

    if ts.Client.Balance < amount+fee {
        return "", errors.New("insufficient balance")
    }

    nonce := len(ts.Blockchain.GetPendingTransactions()) + 1
    tx, err := child_chain.CreateTransaction(ts.Client.Address, to, amount, fee, nonce)
    if err != nil {
        return "", err
    }

    signature, err := signTransaction(tx, ts.Client.PrivateKey)
    if err != nil {
        return "", err
    }

    if !verifyTransactionSignature(tx, signature, ts.Client.PublicKey) {
        return "", errors.New("transaction signature verification failed")
    }

    ts.PendingTxs[tx.Hash] = tx
    ts.PendingTxChan <- tx

    ts.Client.Balance -= amount + fee
    return tx.Hash, nil
}

// processPendingTransactions processes transactions in the PendingTxChan
func (ts *TransactionSubmission) processPendingTransactions() {
    for tx := range ts.PendingTxChan {
        if err := ts.Blockchain.ProcessTransaction(tx); err != nil {
            fmt.Println("Failed to process transaction:", err)
            continue
        }
        ts.mu.Lock()
        delete(ts.PendingTxs, tx.Hash)
        ts.mu.Unlock()
    }
}

// CancelPendingTransaction cancels a pending transaction
func (ts *TransactionSubmission) CancelPendingTransaction(txHash string) error {
    ts.mu.Lock()
    defer ts.mu.Unlock()

    tx, exists := ts.PendingTxs[txHash]
    if !exists {
        return errors.New("transaction not found")
    }

    delete(ts.PendingTxs, txHash)
    ts.Client.Balance += tx.Amount + tx.Fee
    return nil
}

// GetPendingTransactions retrieves all pending transactions
func (ts *TransactionSubmission) GetPendingTransactions() []child_chain.Transaction {
    ts.mu.Lock()
    defer ts.mu.Unlock()

    var pendingTxs []child_chain.Transaction
    for _, tx := range ts.PendingTxs {
        pendingTxs = append(pendingTxs, tx)
    }
    return pendingTxs
}

// signTransaction signs a transaction using a private key
func signTransaction(tx child_chain.Transaction, privateKey string) (string, error) {
    record := tx.Hash + privateKey
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil)), nil
}

// verifyTransactionSignature verifies the transaction signature using a public key
func verifyTransactionSignature(tx child_chain.Transaction, signature, publicKey string) bool {
    record := tx.Hash + publicKey
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil)) == signature
}
