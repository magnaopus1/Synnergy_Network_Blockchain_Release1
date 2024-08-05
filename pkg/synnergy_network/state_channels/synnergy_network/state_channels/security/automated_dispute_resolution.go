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

// AutomatedDisputeResolution represents automated dispute resolution in the security module
type AutomatedDisputeResolution struct {
    DisputeID    string
    PartyA       string
    PartyB       string
    Resolution   string
    Status       string
    Timestamp    time.Time
    lock         sync.RWMutex
}

const (
    DisputePending   = "PENDING"
    DisputeResolved  = "RESOLVED"
    DisputeFailed    = "FAILED"
)

// NewAutomatedDisputeResolution initializes a new AutomatedDisputeResolution instance
func NewAutomatedDisputeResolution(disputeID, partyA, partyB string) *AutomatedDisputeResolution {
    return &AutomatedDisputeResolution{
        DisputeID:   disputeID,
        PartyA:      partyA,
        PartyB:      partyB,
        Status:      DisputePending,
        Timestamp:   time.Now(),
    }
}

// ResolveDispute resolves the dispute with a resolution
func (adr *AutomatedDisputeResolution) ResolveDispute(resolution string) error {
    adr.lock.Lock()
    defer adr.lock.Unlock()

    if adr.Status != DisputePending {
        return errors.New("dispute is not pending")
    }

    adr.Resolution = resolution
    adr.Status = DisputeResolved
    adr.Timestamp = time.Now()
    return nil
}

// FailDispute marks the dispute as failed
func (adr *AutomatedDisputeResolution) FailDispute() error {
    adr.lock.Lock()
    defer adr.lock.Unlock()

    if adr.Status != DisputePending {
        return errors.New("dispute is not pending")
    }

    adr.Status = DisputeFailed
    adr.Timestamp = time.Now()
    return nil
}

// EncryptDispute encrypts the dispute details
func (adr *AutomatedDisputeResolution) EncryptDispute(key []byte) (string, error) {
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
        adr.DisputeID, adr.PartyA, adr.PartyB, adr.Resolution, adr.Status, adr.Timestamp)
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptDispute decrypts the dispute details
func (adr *AutomatedDisputeResolution) DecryptDispute(encryptedData string, key []byte) error {
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

    adr.DisputeID = parts[0]
    adr.PartyA = parts[1]
    adr.PartyB = parts[2]
    adr.Resolution = parts[3]
    adr.Status = parts[4]
    adr.Timestamp = utils.ParseTime(parts[5])
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

func (adr *AutomatedDisputeResolution) String() string {
    return fmt.Sprintf("DisputeID: %s, PartyA: %s, PartyB: %s, Resolution: %s, Status: %s, Timestamp: %s",
        adr.DisputeID, adr.PartyA, adr.PartyB, adr.Resolution, adr.Status, adr.Timestamp)
}
