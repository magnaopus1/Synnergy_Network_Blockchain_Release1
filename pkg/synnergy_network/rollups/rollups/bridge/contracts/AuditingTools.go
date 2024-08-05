package contracts

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/argon2"
)

// AuditEntry represents an entry in the audit log
type AuditEntry struct {
    ID          string
    Action      string
    User        string
    Timestamp   time.Time
    Details     string
    Encrypted   string
}

// AuditingTools provides tools for auditing blockchain actions
type AuditingTools struct {
    Logs map[string]AuditEntry
}

// NewAuditingTools initializes a new AuditingTools
func NewAuditingTools() *AuditingTools {
    return &AuditingTools{
        Logs: make(map[string]AuditEntry),
    }
}

// CreateAuditEntry creates a new audit entry with encryption
func (at *AuditingTools) CreateAuditEntry(action, user, details, secret string) (string, error) {
    id := uuid.New().String()
    encryptedDetails, err := encryptData(secret, details)
    if err != nil {
        return "", err
    }
    entry := AuditEntry{
        ID:        id,
        Action:    action,
        User:      user,
        Timestamp: time.Now(),
        Details:   details,
        Encrypted: encryptedDetails,
    }
    at.Logs[id] = entry
    return id, nil
}

// GetAuditEntry retrieves an audit entry by ID and decrypts it
func (at *AuditingTools) GetAuditEntry(id, secret string) (AuditEntry, error) {
    entry, exists := at.Logs[id]
    if !exists {
        return AuditEntry{}, errors.New("audit entry does not exist")
    }
    decryptedDetails, err := decryptData(secret, entry.Encrypted)
    if err != nil {
        return AuditEntry{}, err
    }
    entry.Details = decryptedDetails
    return entry, nil
}

// ListAuditEntries lists all audit entries
func (at *AuditingTools) ListAuditEntries() []AuditEntry {
    entries := []AuditEntry{}
    for _, entry := range at.Logs {
        entries = append(entries, entry)
    }
    return entries
}

// EncryptData encrypts the given data using AES
func encryptData(secret, data string) (string, error) {
    block, err := aes.NewCipher([]byte(createHash(secret)))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    encrypted := aesGCM.Seal(nonce, nonce, []byte(data), nil)
    return hex.EncodeToString(encrypted), nil
}

// DecryptData decrypts the given data using AES
func decryptData(secret, encryptedData string) (string, error) {
    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher([]byte(createHash(secret)))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonceSize := aesGCM.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("ciphertext too short")
    }
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(decrypted), nil
}

// CreateHash creates a hash from the secret key
func createHash(key string) string {
    hasher := sha256.New()
    hasher.Write([]byte(key))
    return hex.EncodeToString(hasher.Sum(nil))
}

// GenerateSignature generates a signature for the audit entry using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
