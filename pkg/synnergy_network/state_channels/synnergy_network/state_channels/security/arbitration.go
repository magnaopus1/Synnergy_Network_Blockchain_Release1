package security

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

// Arbitration represents the arbitration process in the security module
type Arbitration struct {
    CaseID      string
    ArbitratorID string
    Status      string
    Decision    string
    Timestamp   time.Time
    lock        sync.RWMutex
}

const (
    ArbPending   = "PENDING"
    ArbReviewed  = "REVIEWED"
    ArbResolved  = "RESOLVED"
    ArbFailed    = "FAILED"
)

// NewArbitration initializes a new Arbitration instance
func NewArbitration(caseID, arbitratorID string) *Arbitration {
    return &Arbitration{
        CaseID:      caseID,
        ArbitratorID: arbitratorID,
        Status:      ArbPending,
        Timestamp:   time.Now(),
    }
}

// ReviewCase sets the case status to reviewed
func (a *Arbitration) ReviewCase() error {
    a.lock.Lock()
    defer a.lock.Unlock()

    if a.Status != ArbPending {
        return errors.New("case is not pending")
    }

    a.Status = ArbReviewed
    a.Timestamp = time.Now()
    return nil
}

// ResolveCase resolves the case with a decision
func (a *Arbitration) ResolveCase(decision string) error {
    a.lock.Lock()
    defer a.lock.Unlock()

    if a.Status != ArbReviewed {
        return errors.New("case is not reviewed")
    }

    a.Decision = decision
    a.Status = ArbResolved
    a.Timestamp = time.now()
    return nil
}

// FailCase marks the case as failed
func (a *Arbitration) FailCase() error {
    a.lock.Lock()
    defer a.lock.Unlock()

    if a.Status != ArbPending && a.Status != ArbReviewed {
        return errors.New("case is not pending or reviewed")
    }

    a.Status = ArbFailed
    a.Timestamp = time.now()
    return nil
}

// EncryptCase encrypts the case details
func (a *Arbitration) EncryptCase(key []byte) (string, error) {
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
        a.CaseID, a.ArbitratorID, a.Status, a.Decision, a.Timestamp)
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptCase decrypts the case details
func (a *Arbitration) DecryptCase(encryptedData string, key []byte) error {
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

    a.CaseID = parts[0]
    a.ArbitratorID = parts[1]
    a.Status = parts[2]
    a.Decision = parts[3]
    a.Timestamp = utils.ParseTime(parts[4])
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

func (a *Arbitration) String() string {
    return fmt.Sprintf("CaseID: %s, ArbitratorID: %s, Status: %s, Decision: %s, Timestamp: %s",
        a.CaseID, a.ArbitratorID, a.Status, a.Decision, a.Timestamp)
}
