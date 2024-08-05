package performance_tests

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "log"
    "math/big"
    "sync"
    "time"
    "github.com/synnergy_network/encryption"
)

// Transaction represents a basic transaction structure
type Transaction struct {
    ID        string
    Timestamp int64
    Data      string
    Hash      string
}

// Blockchain represents a chain of transactions
type Blockchain struct {
    transactions []Transaction
    mu           sync.Mutex
}

// NewTransaction creates a new transaction
func NewTransaction(data string) Transaction {
    timestamp := time.Now().Unix()
    id := generateTransactionID()
    transaction := Transaction{ID: id, Timestamp: timestamp, Data: data}
    transaction.Hash = calculateHash(transaction)
    return transaction
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID() string {
    id, err := rand.Int(rand.Reader, big.NewInt(1000000000))
    if err != nil {
        log.Fatalf("Failed to generate transaction ID: %v", err)
    }
    return id.String()
}

// calculateHash generates a SHA-256 hash for a transaction
func calculateHash(transaction Transaction) string {
    record := transaction.ID + string(transaction.Timestamp) + transaction.Data
    h := sha256.New()
    h.Write([]byte(record))
    hashed := h.Sum(nil)
    return hex.EncodeToString(hashed)
}

// AddTransaction adds a new transaction to the blockchain
func (bc *Blockchain) AddTransaction(data string) {
    bc.mu.Lock()
    defer bc.mu.Unlock()
    transaction := NewTransaction(data)
    bc.transactions = append(bc.transactions, transaction)
}

// GetTransactions returns all transactions in the blockchain
func (bc *Blockchain) GetTransactions() []Transaction {
    bc.mu.Lock()
    defer bc.mu.Unlock()
    return bc.transactions
}

// InitializeBlockchain initializes a new blockchain
func InitializeBlockchain() *Blockchain {
    return &Blockchain{transactions: []Transaction{}}
}

// MonitorTransactionThroughput monitors and logs the transaction throughput
func MonitorTransactionThroughput(blockchain *Blockchain, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for range ticker.C {
        transactions := blockchain.GetTransactions()
        throughput := float64(len(transactions)) / interval.Seconds()
        log.Printf("Transaction Throughput: %.2f transactions per second", throughput)
    }
}

// SimulateTransactions simulates the creation of transactions at a specified rate
func SimulateTransactions(blockchain *Blockchain, rate int, duration time.Duration) {
    ticker := time.NewTicker(time.Second / time.Duration(rate))
    defer ticker.Stop()

    end := time.Now().Add(duration)
    for now := range ticker.C {
        if now.After(end) {
            break
        }
        data := generateRandomData()
        blockchain.AddTransaction(data)
    }
}

// generateRandomData generates random data for a transaction
func generateRandomData() string {
    n, err := rand.Int(rand.Reader, big.NewInt(1000000))
    if err != nil {
        log.Fatalf("Failed to generate random data: %v", err)
    }
    return n.String()
}

// EncryptTransactionData encrypts the transaction data using AES
func EncryptTransactionData(data string, key []byte) (string, error) {
    ciphertext, err := encryption.AESEncrypt([]byte(data), key)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(ciphertext), nil
}

// DecryptTransactionData decrypts the transaction data using AES
func DecryptTransactionData(data string, key []byte) (string, error) {
    ciphertext, err := hex.DecodeString(data)
    if err != nil {
        return "", err
    }
    plaintext, err := encryption.AESDecrypt(ciphertext, key)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

// RunTransactionThroughputTest runs the transaction throughput test
func RunTransactionThroughputTest(rate int, duration, monitoringInterval time.Duration, encryptionKey []byte) {
    blockchain := InitializeBlockchain()

    go SimulateTransactions(blockchain, rate, duration)
    go MonitorTransactionThroughput(blockchain, monitoringInterval)

    time.Sleep(duration + monitoringInterval)
}

func main() {
    encryptionKey := []byte("example key 1234")
    RunTransactionThroughputTest(100, 1*time.Minute, 10*time.Second, encryptionKey)
}
