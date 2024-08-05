package client

import (
    "errors"
    "fmt"
    "sync"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

// Client represents a blockchain client
type Client struct {
    Address string
    Balance int
    mu      sync.Mutex
    bc      *child_chain.Blockchain
}

// NewClient creates a new client with an initial balance and blockchain reference
func NewClient(address string, initialBalance int, blockchain *child_chain.Blockchain) *Client {
    return &Client{
        Address: address,
        Balance: initialBalance,
        bc:      blockchain,
    }
}

// getBalance retrieves the client's balance from the blockchain
func (c *Client) getBalance() int {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.Balance = c.bc.GetBalance(c.Address)
    return c.Balance
}

// sendTransaction creates and processes a transaction from the client
func (c *Client) sendTransaction(to string, amount int, fee int) (string, error) {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.Balance < amount+fee {
        return "", errors.New("insufficient balance")
    }

    nonce := len(c.bc.GetPendingTransactions()) + 1
    tx, err := child_chain.CreateTransaction(c.Address, to, amount, fee, nonce)
    if err != nil {
        return "", err
    }

    if err := c.bc.ProcessTransaction(tx); err != nil {
        return "", err
    }

    c.Balance -= amount + fee
    return tx.Hash, nil
}

// receiveTransaction processes a received transaction for the client
func (c *Client) receiveTransaction(tx child_chain.Transaction) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    if tx.To != c.Address {
        return errors.New("transaction not addressed to this client")
    }

    c.Balance += tx.Amount
    return nil
}

// displayBalance prints the client's balance
func (c *Client) displayBalance() {
    balance := c.getBalance()
    fmt.Printf("Balance for %s: %d\n", c.Address, balance)
}

// addFunds adds funds to the client's balance
func (c *Client) addFunds(amount int) {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.Balance += amount
    fmt.Printf("Added %d to %s's balance\n", amount, c.Address)
}

// withdrawFunds withdraws funds from the client's balance
func (c *Client) withdrawFunds(amount int) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.Balance < amount {
        return errors.New("insufficient balance")
    }

    c.Balance -= amount
    fmt.Printf("Withdrew %d from %s's balance\n", amount, c.Address)
    return nil
}

// getTransactionHistory retrieves the client's transaction history from the blockchain
func (c *Client) getTransactionHistory() ([]child_chain.Transaction, error) {
    return c.bc.GetTransactionHistory(c.Address)
}
