package smart_contracts

import (
    "errors"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/hex"
    "io"
    "fmt"
    "crypto/sha256"
    "github.com/synnergy_network/utils"
)

// ConditionalPayment represents a conditional payment in the smart contracts module
type ConditionalPayment struct {
    PaymentID     string
    ContractID    string
    Status        string
    Condition     string
    Details       string
    Timestamp     time.Time
    lock          sync.RWMutex
}

const (
    PayPending   = "PENDING"
    PayCompleted = "COMPLETED"
    PayFailed    = "FAILED"
)

// NewConditionalPayment initializes a new ConditionalPayment instance
func NewConditionalPayment(paymentID, contractID, condition string) *ConditionalPayment {
    return &ConditionalPayment{
        PaymentID:  paymentID,
        ContractID: contractID,
        Condition:  condition,
        Status:     PayPending,
        Timestamp:  time.Now(),
    }
}

// CompletePayment completes the payment
func (cp *ConditionalPayment) CompletePayment(details string) error {
    cp.lock.Lock()
    defer cp.lock.Unlock()

    if cp.Status != PayPending {
        return errors.New("payment is not pending")
    }

    cp.Details = details
    cp.Status = PayCompleted
    cp.Timestamp = time.Now()
    return nil
}

// FailPayment marks the payment as failed
func (cp *ConditionalPayment) FailPayment() error {
    cp.lock.Lock()
    defer cp.lock.Unlock()

    if cp.Status != PayPending {
        return errors.New("payment is not pending")
    }

    cp.Status = PayFailed
    cp.Timestamp = time.Now()
    return nil
}

// EncryptPayment encrypts the payment details
func (cp *ConditionalPayment) EncryptPayment(key []byte) (string, error) {
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

    data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
        cp.PaymentID, cp.ContractID, cp.Status, cp.Condition, cp.Details, cp.Timestamp)
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptPayment decrypts the payment details
func (cp *ConditionalPayment) DecryptPayment(encryptedData string, key []byte) error {
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
    if len(parts) != 6 {
        return errors.New("invalid encrypted data format")
    }

    cp.PaymentID = parts[0]
    cp.ContractID = parts[1]
    cp.Status = parts[2]
    cp.Condition = parts[3]
    cp.Details = parts[4]
    cp.Timestamp = utils.ParseTime(parts[5])
    return nil
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

func (cp *ConditionalPayment) String() string {
    return fmt.Sprintf("PaymentID: %s, ContractID: %s, Status: %s, Condition: %s, Details: %s, Timestamp: %s",
        cp.PaymentID, cp.ContractID, cp.Status, cp.Condition, cp.Details, cp.Timestamp)
}
