package verifiers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/scrypt"
)

type VerificationStatus int

const (
	Unverified VerificationStatus = iota
	Verified
	Failed
)

// Transaction represents a blockchain transaction.
type Transaction struct {
	ID        string
	Timestamp int64
	Sender    string
	Receiver  string
	Amount    float64
	Data      string
	Status    VerificationStatus
}

// AutomatedVerification handles automated transaction verification.
type AutomatedVerification struct {
	mu               sync.Mutex
	transactions     map[string]*Transaction
	verificationLog  []string
}

// NewAutomatedVerification initializes a new AutomatedVerification instance.
func NewAutomatedVerification() *AutomatedVerification {
	return &AutomatedVerification{
		transactions: make(map[string]*Transaction),
	}
}

// AddTransaction adds a transaction for verification.
func (av *AutomatedVerification) AddTransaction(sender, receiver string, amount float64, data string, timestamp int64) (string, error) {
	av.mu.Lock()
	defer av.mu.Unlock()

	tx := &Transaction{
		ID:        av.generateTransactionID(sender, receiver, amount, data),
		Timestamp: timestamp,
		Sender:    sender,
		Receiver:  receiver,
		Amount:    amount,
		Data:      data,
		Status:    Unverified,
	}

	if _, exists := av.transactions[tx.ID]; exists {
		return "", errors.New("transaction already exists")
	}

	av.transactions[tx.ID] = tx
	av.verificationLog = append(av.verificationLog, fmt.Sprintf("Transaction Added: %+v", tx))

	return tx.ID, nil
}

// VerifyTransaction verifies a transaction based on its ID.
func (av *AutomatedVerification) VerifyTransaction(txID string) error {
	av.mu.Lock()
	defer av.mu.Unlock()

	tx, exists := av.transactions[txID]
	if !exists {
		return errors.New("transaction not found")
	}

	// Simulated verification logic (extend with real-world checks)
	if tx.Amount <= 0 {
		tx.Status = Failed
		av.verificationLog = append(av.verificationLog, fmt.Sprintf("Transaction Verification Failed: %+v", tx))
		return errors.New("invalid transaction amount")
	}

	tx.Status = Verified
	av.verificationLog = append(av.verificationLog, fmt.Sprintf("Transaction Verified: %+v", tx))
	return nil
}

// GetTransactionStatus retrieves the verification status of a transaction.
func (av *AutomatedVerification) GetTransactionStatus(txID string) (VerificationStatus, error) {
	av.mu.Lock()
	defer av.mu.Unlock()

	tx, exists := av.transactions[txID]
	if !exists {
		return Unverified, errors.New("transaction not found")
	}

	return tx.Status, nil
}

// generateTransactionID generates a unique transaction ID using scrypt.
func (av *AutomatedVerification) generateTransactionID(sender, receiver string, amount float64, data string) string {
	salt := []byte(sender + receiver + fmt.Sprintf("%f", amount) + data)
	dk, _ := scrypt.Key([]byte(fmt.Sprintf("%d", time.Now().UnixNano())), salt, 16384, 8, 1, 32)
	return hex.EncodeToString(dk)
}

// EncryptTransactionData encrypts transaction data using SHA-256.
func (av *AutomatedVerification) EncryptTransactionData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// PrintVerificationLog prints the verification log.
func (av *AutomatedVerification) PrintVerificationLog() {
	av.mu.Lock()
	defer av.mu.Unlock()

	fmt.Println("Verification Log:")
	for _, log := range av.verificationLog {
		fmt.Println(log)
	}
}

// ExportVerificationMetrics exports verification metrics for monitoring tools.
func (av *AutomatedVerification) ExportVerificationMetrics() map[string]interface{} {
	av.mu.Lock()
	defer av.mu.Unlock()

	verifiedCount := 0
	failedCount := 0
	for _, tx := range av.transactions {
		if tx.Status == Verified {
			verifiedCount++
		} else if tx.Status == Failed {
			failedCount++
		}
	}

	metrics := map[string]interface{}{
		"totalTransactions": len(av.transactions),
		"verifiedCount":     verifiedCount,
		"failedCount":       failedCount,
	}

	return metrics
}
