package fraud_detection

import (
	"crypto/sha256"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
	"log"
	"sync"
)

// RealTimeMonitoring handles real-time fraud detection monitoring
type RealTimeMonitoring struct {
	secretKey []byte
	transactions chan Transaction
	alerts chan Alert
	wg sync.WaitGroup
}

// NewRealTimeMonitoring creates a new instance of RealTimeMonitoring
func NewRealTimeMonitoring(secret string) (*RealTimeMonitoring, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret key cannot be empty")
	}
	hashedKey := sha256.Sum256([]byte(secret))
	rtm := &RealTimeMonitoring{
		secretKey: hashedKey[:],
		transactions: make(chan Transaction, 100),
		alerts: make(chan Alert, 10),
	}
	rtm.wg.Add(1)
	go rtm.startMonitoring()
	return rtm, nil
}

// Transaction represents a transaction in the blockchain
type Transaction struct {
	ID          string
	Sender      string
	Receiver    string
	Amount      float64
	Description string
	Timestamp   time.Time
}

// Alert represents an alert generated for potential fraud
type Alert struct {
	TransactionID string
	Message       string
	Timestamp     time.Time
}

// AddTransaction adds a new transaction for monitoring
func (rtm *RealTimeMonitoring) AddTransaction(tx Transaction) {
	rtm.transactions <- tx
}

// GetAlerts returns a channel for receiving alerts
func (rtm *RealTimeMonitoring) GetAlerts() <-chan Alert {
	return rtm.alerts
}

// startMonitoring starts the monitoring process
func (rtm *RealTimeMonitoring) startMonitoring() {
	defer rtm.wg.Done()
	for tx := range rtm.transactions {
		rtm.wg.Add(1)
		go rtm.monitorTransaction(tx)
	}
}

// monitorTransaction monitors a single transaction for anomalies
func (rtm *RealTimeMonitoring) monitorTransaction(tx Transaction) {
	defer rtm.wg.Done()
	// Simulate anomaly detection logic
	isFraudulent := rtm.isAnomalous(tx)

	if isFraudulent {
		alert := Alert{
			TransactionID: tx.ID,
			Message:       fmt.Sprintf("Potential fraud detected in transaction %s", tx.ID),
			Timestamp:     time.Now(),
		}
		rtm.alerts <- alert
	}
}

// isAnomalous performs the anomaly detection logic
func (rtm *RealTimeMonitoring) isAnomalous(tx Transaction) bool {
	// Placeholder for complex ML-based anomaly detection logic
	// Here we simply flag transactions over a certain amount as anomalous for demo purposes
	return tx.Amount > 10000
}

// Encrypt encrypts a string using AES
func (rtm *RealTimeMonitoring) Encrypt(data string) (string, error) {
	block, err := aes.NewCipher(rtm.secretKey)
	if err != nil {
		return "", err
	}

	plaintext := []byte(data)
	cfb := cipher.NewCFBEncrypter(block, rtm.secretKey[:block.BlockSize()])
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a string using AES
func (rtm *RealTimeMonitoring) Decrypt(encryptedData string) (string, error) {
	block, err := aes.NewCipher(rtm.secretKey)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	cfb := cipher.NewCFBDecrypter(block, rtm.secretKey[:block.BlockSize()])
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}

// Close gracefully shuts down the monitoring process
func (rtm *RealTimeMonitoring) Close() {
	close(rtm.transactions)
	rtm.wg.Wait()
	close(rtm.alerts)
}

// Usage example (for demonstration purposes, not part of the package)
/*
func main() {
	rtm, err := NewRealTimeMonitoring("super-secret-key")
	if err != nil {
		log.Fatal(err)
	}

	tx := Transaction{
		ID:          "tx1",
		Sender:      "Alice",
		Receiver:    "Bob",
		Amount:      15000,
		Description: "Payment for services",
		Timestamp:   time.Now(),
	}

	rtm.AddTransaction(tx)

	for alert := range rtm.GetAlerts() {
		fmt.Printf("Alert: %s - %s\n", alert.TransactionID, alert.Message)
	}

	rtm.Close()
}
*/
