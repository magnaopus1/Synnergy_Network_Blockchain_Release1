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

// AutomatedSettlement represents an automated settlement in the smart contracts module
type AutomatedSettlement struct {
    SettlementID  string
    ContractID    string
    Status        string
    Details       string
    Timestamp     time.Time
    lock          sync.RWMutex
}

const (
    SetPending   = "PENDING"
    SetCompleted = "COMPLETED"
    SetFailed    = "FAILED"
)

// NewAutomatedSettlement initializes a new AutomatedSettlement instance
func NewAutomatedSettlement(settlementID, contractID string) *AutomatedSettlement {
    return &AutomatedSettlement{
        SettlementID: settlementID,
        ContractID:   contractID,
        Status:       SetPending,
        Timestamp:    time.Now(),
    }
}

// CompleteSettlement completes the settlement
func (as *AutomatedSettlement) CompleteSettlement(details string) error {
    as.lock.Lock()
    defer as.lock.Unlock()

    if as.Status != SetPending {
        return errors.New("settlement is not pending")
    }

    as.Details = details
    as.Status = SetCompleted
    as.Timestamp = time.Now()
    return nil
}

// FailSettlement marks the settlement as failed
func (as *AutomatedSettlement) FailSettlement() error {
    as.lock.Lock()
    defer as.lock.Unlock()

    if as.Status != SetPending {
        return errors.New("settlement is not pending")
    }

    as.Status = SetFailed
    as.Timestamp = time.Now()
    return nil
}

// EncryptSettlement encrypts the settlement details
func (as *AutomatedSettlement) EncryptSettlement(key []byte) (string, error) {
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

    data := fmt.Sprintf("%s|%s|%s|%s|%s",
        as.SettlementID, as.ContractID, as.Status, as.Details, as.Timestamp)
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSettlement decrypts the settlement details
func (as *AutomatedSettlement) DecryptSettlement(encryptedData string, key []byte) error {
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
    if len(parts) != 5 {
        return errors.New("invalid encrypted data format")
    }

    as.SettlementID = parts[0]
    as.ContractID = parts[1]
    as.Status = parts[2]
    as.Details = parts[3]
    as.Timestamp = utils.ParseTime(parts[4])
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

func (as *AutomatedSettlement) String() string {
    return fmt.Sprintf("SettlementID: %s, ContractID: %s, Status: %s, Details: %s, Timestamp: %s",
        as.SettlementID, as.ContractID, as.Status, as.Details, as.Timestamp)
}
