package performance

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// LowLatencyTransaction represents a low latency transaction
type LowLatencyTransaction struct {
	TransactionID string
	NodeID        string
	Latency       int64
	Status        string
	Timestamp     time.Time
	lock          sync.RWMutex
}

const (
	TransactionPending   = "PENDING"
	TransactionCompleted = "COMPLETED"
	TransactionFailed    = "FAILED"
)

// NewLowLatencyTransaction initializes a new LowLatencyTransaction instance
func NewLowLatencyTransaction(transactionID, nodeID string, latency int64) *LowLatencyTransaction {
	return &LowLatencyTransaction{
		TransactionID: transactionID,
		NodeID:        nodeID,
		Latency:       latency,
		Status:        TransactionPending,
		Timestamp:     time.Now(),
	}
}

// ExecuteTransaction executes the low latency transaction
func (llt *LowLatencyTransaction) ExecuteTransaction() error {
	llt.lock.Lock()
	defer llt.lock.Unlock()

	if llt.Status != TransactionPending {
		return errors.New("transaction is not pending")
	}

	// Simulate transaction execution logic
	if llt.Latency <= 0 {
		llt.Status = TransactionFailed
		return errors.New("invalid transaction latency")
	}

	llt.Status = TransactionCompleted
	llt.Timestamp = time.Now()
	return nil
}

// EncryptTransaction encrypts the transaction details
func (llt *LowLatencyTransaction) EncryptTransaction(key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	data := fmt.Sprintf("%s|%s|%d|%s",
		llt.TransactionID, llt.NodeID, llt.Latency, llt.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptTransaction decrypts the transaction details
func (llt *LowLatencyTransaction) DecryptTransaction(encryptedData string, key []byte) error {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	parts := utils.Split(string(data), '|')
	if len(parts) != 4 {
		return errors.New("invalid encrypted data format")
	}

	llt.TransactionID = parts[0]
	llt.NodeID = parts[1]
	llt.Latency = utils.ParseInt64(parts[2])
	llt.Status = parts[3]
	return nil
}

// GetTransactionDetails returns the details of the transaction
func (llt *LowLatencyTransaction) GetTransactionDetails() (string, string, int64, string) {
	llt.lock.RLock()
	defer llt.lock.RUnlock()
	return llt.TransactionID, llt.NodeID, llt.Latency, llt.Status
}

// ValidateTransaction validates the transaction details
func (llt *LowLatencyTransaction) ValidateTransaction() error {
	llt.lock.RLock()
	defer llt.lock.RUnlock()

	if llt.TransactionID == "" || llt.NodeID == "" {
		return errors.New("transaction ID and node ID cannot be empty")
	}

	if llt.Latency <= 0 {
		return errors.New("latency must be greater than zero")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the transaction
func (llt *LowLatencyTransaction) UpdateTimestamp() {
	llt.lock.Lock()
	defer llt.lock.Unlock()
	llt.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the transaction
func (llt *LowLatencyTransaction) GetTimestamp() time.Time {
	llt.lock.RLock()
	defer llt.lock.RUnlock()
	return llt.Timestamp
}

// GenerateKey generates a cryptographic key using Argon2
func GenerateKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// GenerateSalt generates a cryptographic salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// HashData hashes the data using SHA-256
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (llt *LowLatencyTransaction) String() string {
	return fmt.Sprintf("TransactionID: %s, Status: %s, Timestamp: %s", llt.TransactionID, llt.Status, llt.Timestamp)
}
