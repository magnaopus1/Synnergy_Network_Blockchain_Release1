package logs

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
	"os"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/testnet/common"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/testnet/ai_powered_anomaly_detection"
)

// Transaction represents the structure of a blockchain transaction
type Transaction struct {
	ID        string
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

// TransactionLogger manages the logging of transactions
type TransactionLogger struct {
	mu               sync.Mutex
	logFile          *os.File
	anomalyDetector  ai_powered_anomaly_detection.AnomalyDetector
	encryptionKey    string
}

// NewTransactionLogger initializes a new TransactionLogger
func NewTransactionLogger(filePath, encryptionKey string, ad ai_powered_anomaly_detection.AnomalyDetector) (*TransactionLogger, error) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &TransactionLogger{
		logFile:         file,
		anomalyDetector: ad,
		encryptionKey:   encryptionKey,
	}, nil
}

// LogTransaction logs a transaction to the file
func (tl *TransactionLogger) LogTransaction(txn Transaction) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	txnID := tl.generateTransactionID(txn)
	entry := fmt.Sprintf("%s,%s,%s,%s,%d,%d,%d,%s,%s,%s\n",
		txnID,
		txn.From,
		txn.To,
		txn.Value.String(),
		txn.Gas,
		txn.GasPrice.Uint64(),
		txn.Nonce,
		hex.EncodeToString(txn.Data),
		txn.Timestamp.Format(time.RFC3339),
		hex.EncodeToString(txn.Signature))

	encryptedEntry, err := tl.encrypt(entry, tl.encryptionKey)
	if err != nil {
		return err
	}

	if _, err := tl.logFile.WriteString(encryptedEntry + "\n"); err != nil {
		return err
	}

	if tl.anomalyDetector != nil && tl.anomalyDetector.DetectAnomaly(txn) {
		log.Printf("Anomaly detected in transaction logging: %v", txn)
	}

	return nil
}

// generateTransactionID generates a unique ID for a transaction
func (tl *TransactionLogger) generateTransactionID(txn Transaction) string {
	hash := sha256.New()
	hash.Write([]byte(txn.From))
	hash.Write([]byte(txn.To))
	hash.Write(txn.Value.Bytes())
	hash.Write(txn.GasPrice.Bytes())
	hash.Write(txn.Data)
	return hex.EncodeToString(hash.Sum(nil))
}

// encrypt encrypts the given data using AES and the provided passphrase
func (tl *TransactionLogger) encrypt(data, passphrase string) (string, error) {
	block, err := aes.NewCipher(tl.generateKey(passphrase))
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
func (tl *TransactionLogger) decrypt(data, passphrase string) (string, error) {
	block, err := aes.NewCipher(tl.generateKey(passphrase))
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

// generateKey creates a new SHA-256 hash key based on the given password
func (tl *TransactionLogger) generateKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// ReadLogs reads and decrypts the transaction logs from the file
func (tl *TransactionLogger) ReadLogs() ([]string, error) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	_, err := tl.logFile.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	var logs []string
	scanner := bufio.NewScanner(tl.logFile)
	for scanner.Scan() {
		encryptedEntry := scanner.Text()
		decryptedEntry, err := tl.decrypt(encryptedEntry, tl.encryptionKey)
		if err != nil {
			return nil, err
		}
		logs = append(logs, decryptedEntry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return logs, nil
}

// Close closes the log file
func (tl *TransactionLogger) Close() error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	return tl.logFile.Close()
}

// common package functions for simulating transaction details
package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

// ai_powered_anomaly_detection package for anomaly detection
package ai_powered_anomaly_detection

// AnomalyDetector interface for detecting anomalies
type AnomalyDetector interface {
	DetectAnomaly(txn Transaction) bool
}

// DetectAnomaly simulates AI-based anomaly detection
func DetectAnomaly(txn Transaction) bool {
	// In real implementation, AI models would be used to detect anomalies
	// For simulation, we assume no anomalies detected
	return false
}
