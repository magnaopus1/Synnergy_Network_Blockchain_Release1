package client

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"

    "golang.org/x/crypto/scrypt"
    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

// Client represents a blockchain client
type Client struct {
    Address    string
    PrivateKey string
    PublicKey  string
    Balance    int
    mu         sync.Mutex
    bc         *child_chain.Blockchain
}

// NewClient creates a new client with a generated wallet and initial balance
func NewClient(password string, initialBalance int, blockchain *child_chain.Blockchain) (*Client, error) {
    privateKey, publicKey, err := createWallet(password)
    if err != nil {
        return nil, err
    }
    address := publicKey // Simplified, normally you'd derive an address from the public key

    return &Client{
        Address:    address,
        PrivateKey: privateKey,
        PublicKey:  publicKey,
        Balance:    initialBalance,
        bc:         blockchain,
    }, nil
}

// createWallet creates a new wallet with a private and public key
func createWallet(password string) (string, string, error) {
    salt := make([]byte, 16)
    if _, err := time.Read(salt); err != nil {
        return "", "", err
    }

    dk, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", "", err
    }

    privateKey := hex.EncodeToString(dk)
    publicKey := hex.EncodeToString(dk[:16]) // Simplified public key generation

    return privateKey, publicKey, nil
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

    // Sign the transaction
    signature, err := signTransaction(tx, c.PrivateKey)
    if err != nil {
        return "", err
    }

    // Verify the transaction signature
    if !verifyTransactionSignature(tx, signature, c.PublicKey) {
        return "", errors.New("transaction signature verification failed")
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

// signTransaction signs a transaction using a private key
func signTransaction(tx child_chain.Transaction, privateKey string) (string, error) {
    // Simplified signing logic
    record := tx.Hash + privateKey
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil)), nil
}

// verifyTransactionSignature verifies the transaction signature using a public key
func verifyTransactionSignature(tx child_chain.Transaction, signature, publicKey string) bool {
    // Simplified verification logic
    record := tx.Hash + publicKey
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil)) == signature
}

// getTransactionHistory retrieves the client's transaction history from the blockchain
func (c *Client) getTransactionHistory() ([]child_chain.Transaction, error) {
    return c.bc.GetTransactionHistory(c.Address)
}
