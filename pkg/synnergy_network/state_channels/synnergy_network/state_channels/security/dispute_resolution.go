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

// DisputeResolution represents dispute resolution in the security module
type DisputeResolution struct {
    DisputeID    string
    ResolvedBy   string
    Status       string
    Resolution   string
    Timestamp    time.Time
    lock         sync.RWMutex
}

const (
    DispPending   = "PENDING"
    DispReviewed  = "REVIEWED"
    DispResolved  = "RESOLVED"
    DispFailed    = "FAILED"
)

// NewDisputeResolution initializes a new DisputeResolution instance
func NewDisputeResolution(disputeID, resolvedBy string) *DisputeResolution {
    return &DisputeResolution{
        DisputeID:   disputeID,
        ResolvedBy:  resolvedBy,
        Status:      DispPending,
        Timestamp:   time.Now(),
    }
}

// ReviewDispute sets the dispute status to reviewed
func (dr *DisputeResolution) ReviewDispute() error {
    dr.lock.Lock()
    defer dr.lock.Unlock()

    if dr.Status != DispPending {
        return errors.New("dispute is not pending")
    }

    dr.Status = DispReviewed
    dr.Timestamp = time.Now()
    return nil
}

// ResolveDispute resolves the dispute with a resolution
func (dr *DisputeResolution) ResolveDispute(resolution string) error {
    dr.lock.Lock()
    defer dr.lock.Unlock()

    if dr.Status != DispReviewed {
        return errors.New("dispute is not reviewed")
    }

    dr.Resolution = resolution
    dr.Status = DispResolved
    dr.Timestamp = time.Now()
    return nil
}

// FailDispute marks the dispute as failed
func (dr *DisputeResolution) FailDispute() error {
    dr.lock.Lock()
    defer dr.lock.Unlock()

    if dr.Status != DispPending && dr.Status != DispReviewed {
        return errors.New("dispute is not pending or reviewed")
    }

    dr.Status = DispFailed
    dr.Timestamp = time.Now()
    return nil
}

// EncryptDispute encrypts the dispute details
func (dr *DisputeResolution) EncryptDispute(key []byte) (string, error) {
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
        dr.DisputeID, dr.ResolvedBy, dr.Status, dr.Resolution, dr.Timestamp)
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptDispute decrypts the dispute details
func (dr *DisputeResolution) DecryptDispute(encryptedData string, key []byte) error {
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

    dr.DisputeID = parts[0]
    dr.ResolvedBy = parts[1]
    dr.Status = parts[2]
    dr.Resolution = parts[3]
    dr.Timestamp = utils.ParseTime(parts[4])
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

func (dr *DisputeResolution) String() string {
    return fmt.Sprintf("DisputeID: %s, ResolvedBy: %s, Status: %s, Resolution: %s, Timestamp: %s",
        dr.DisputeID, dr.ResolvedBy, dr.Status, dr.Resolution, dr.Timestamp)
}
