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

// DecentralizedArbitration represents the decentralized arbitration process in the security module
type DecentralizedArbitration struct {
    ArbitrationID string
    NodeID        string
    Status        string
    Decision      string
    Timestamp     time.Time
    lock          sync.RWMutex
}

const (
    DecArbPending   = "PENDING"
    DecArbReviewed  = "REVIEWED"
    DecArbResolved  = "RESOLVED"
    DecArbFailed    = "FAILED"
)

// NewDecentralizedArbitration initializes a new DecentralizedArbitration instance
func NewDecentralizedArbitration(arbitrationID, nodeID string) *DecentralizedArbitration {
    return &DecentralizedArbitration{
        ArbitrationID: arbitrationID,
        NodeID:        nodeID,
        Status:        DecArbPending,
        Timestamp:     time.Now(),
    }
}

// ReviewArbitration sets the arbitration status to reviewed
func (da *DecentralizedArbitration) ReviewArbitration() error {
    da.lock.Lock()
    defer da.lock.Unlock()

    if da.Status != DecArbPending {
        return errors.New("arbitration is not pending")
    }

    da.Status = DecArbReviewed
    da.Timestamp = time.Now()
    return nil
}

// ResolveArbitration resolves the arbitration with a decision
func (da *DecentralizedArbitration) ResolveArbitration(decision string) error {
    da.lock.Lock()
    defer da.lock.Unlock()

    if da.Status != DecArbReviewed {
        return errors.New("arbitration is not reviewed")
    }

    da.Decision = decision
    da.Status = DecArbResolved
    da.Timestamp = time.Now()
    return nil
}

// FailArbitration marks the arbitration as failed
func (da *DecentralizedArbitration) FailArbitration() error {
    da.lock.Lock()
    defer da.lock.Unlock()

    if da.Status != DecArbPending && da.Status != DecArbReviewed {
        return errors.New("arbitration is not pending or reviewed")
    }

    da.Status = DecArbFailed
    da.Timestamp = time.Now()
    return nil
}

// EncryptArbitration encrypts the arbitration details
func (da *DecentralizedArbitration) EncryptArbitration(key []byte) (string, error) {
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
        da.ArbitrationID, da.NodeID, da.Status, da.Decision, da.Timestamp)
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptArbitration decrypts the arbitration details
func (da *DecentralizedArbitration) DecryptArbitration(encryptedData string, key []byte) error {
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

    da.ArbitrationID = parts[0]
    da.NodeID = parts[1]
    da.Status = parts[2]
    da.Decision = parts[3]
    da.Timestamp = utils.ParseTime(parts[4])
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

func (da *DecentralizedArbitration) String() string {
    return fmt.Sprintf("ArbitrationID: %s, NodeID: %s, Status: %s, Decision: %s, Timestamp: %s",
        da.ArbitrationID, da.NodeID, da.Status, da.Decision, da.Timestamp)
}
