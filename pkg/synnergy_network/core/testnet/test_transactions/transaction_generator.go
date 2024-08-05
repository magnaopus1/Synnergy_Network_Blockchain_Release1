package test_transactions

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "log"
    "math/big"
    "time"

    "github.com/synnergy_network_blockchain/pkg/synnergy_network/core/testnet/common"
)

// Transaction represents a basic structure of a blockchain transaction
type Transaction struct {
    From      string
    To        string
    Value     *big.Int
    Gas       uint64
    GasPrice  *big.Int
    Nonce     uint64
    Data      []byte
    Timestamp time.Time
    Signature []byte
}

// TransactionGenerator is responsible for generating test transactions
type TransactionGenerator struct {
    transactions []Transaction
}

// NewTransactionGenerator initializes a new TransactionGenerator
func NewTransactionGenerator() *TransactionGenerator {
    return &TransactionGenerator{
        transactions: make([]Transaction, 0),
    }
}

// GenerateTransaction creates a new test transaction with random data
func (tg *TransactionGenerator) GenerateTransaction(from, to string, value *big.Int, gas uint64, gasPrice *big.Int, nonce uint64, data []byte) Transaction {
    txn := Transaction{
        From:      from,
        To:        to,
        Value:     value,
        Gas:       gas,
        GasPrice:  gasPrice,
        Nonce:     nonce,
        Data:      data,
        Timestamp: time.Now(),
    }

    // Simulate a signature (In real implementation, cryptographic signing would be done here)
    txn.Signature = common.GenerateSignature(txn)

    tg.transactions = append(tg.transactions, txn)
    return txn
}

// GetTransactions returns the list of generated transactions
func (tg *TransactionGenerator) GetTransactions() []Transaction {
    return tg.transactions
}

// GenerateRandomTransaction generates a transaction with random values for testing
func (tg *TransactionGenerator) GenerateRandomTransaction() Transaction {
    from := common.GenerateRandomAddress()
    to := common.GenerateRandomAddress()
    value := big.NewInt(rand.Int63())
    gas := uint64(rand.Int63() % 21000)
    gasPrice := big.NewInt(rand.Int63() % 1000)
    nonce := uint64(rand.Int63())
    data := common.GenerateRandomData()

    return tg.GenerateTransaction(from, to, value, gas, gasPrice, nonce, data)
}

// Encryption and decryption functions using AES

// generateKey creates a new SHA-256 hash key based on the given password
func generateKey(password string) []byte {
    hash := sha256.Sum256([]byte(password))
    return hash[:]
}

// encrypt encrypts the given data using AES and the provided passphrase
func encrypt(data, passphrase string) (string, error) {
    block, err := aes.NewCipher(generateKey(passphrase))
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return hex.EncodeToString(ciphertext), nil
}

// decrypt decrypts the given encrypted data using AES and the provided passphrase
func decrypt(data, passphrase string) (string, error) {
    block, err := aes.NewCipher(generateKey(passphrase))
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    enc, err := hex.DecodeString(data)
    if err != nil {
        return "", err
    }
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

// common package functions for simulating transaction details
package common

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "encoding/hex"
    "math/big"
)

// GenerateRandomAddress creates a random blockchain address
func GenerateRandomAddress() string {
    key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    address := key.PublicKey.X.Bytes()
    return hex.EncodeToString(address)
}

// GenerateRandomData creates random byte array data for transactions
func GenerateRandomData() []byte {
    data := make([]byte, 256)
    rand.Read(data)
    return data
}

// GenerateSignature simulates the generation of a digital signature for a transaction
func GenerateSignature(txn Transaction) []byte {
    hash := sha256.New()
    hash.Write([]byte(txn.From))
    hash.Write([]byte(txn.To))
    hash.Write(txn.Value.Bytes())
    hash.Write(txn.GasPrice.Bytes())
    hash.Write(txn.Data)
    return hash.Sum(nil)
}
