package compliance

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "time"

    "golang.org/x/crypto/scrypt"
)

const (
    auditLogFile        = "audit_log.json"
    keyLength           = 32
    saltSize            = 16
    scryptN             = 1 << 15
    scryptR             = 8
    scryptP             = 1
    encryptionKeyEnvVar = "AUDIT_LOG_ENCRYPTION_KEY"
)

// AuditLogEntry represents an entry in the audit log
type AuditLogEntry struct {
    Timestamp   time.Time `json:"timestamp"`
    UserID      string    `json:"user_id"`
    Action      string    `json:"action"`
    Details     string    `json:"details"`
    IPAddress   string    `json:"ip_address"`
    Encrypted   bool      `json:"encrypted"`
}

// AuditLogger handles logging of audit entries
type AuditLogger struct {
    encryptionKey []byte
}

// NewAuditLogger initializes a new AuditLogger
func NewAuditLogger() (*AuditLogger, error) {
    key, err := getEncryptionKey()
    if err != nil {
        return nil, err
    }
    return &AuditLogger{encryptionKey: key}, nil
}

// LogEntry logs an audit entry
func (a *AuditLogger) LogEntry(entry AuditLogEntry) error {
    entry.Timestamp = time.Now()

    if a.encryptionKey != nil {
        encryptedDetails, err := encrypt(entry.Details, a.encryptionKey)
        if err != nil {
            return err
        }
        entry.Details = encryptedDetails
        entry.Encrypted = true
    }

    logData, err := json.Marshal(entry)
    if err != nil {
        return err
    }

    f, err := os.OpenFile(auditLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    defer f.Close()

    _, err = f.Write(logData)
    if err != nil {
        return err
    }

    _, err = f.WriteString("\n")
    return err
}

// ReadLog reads and decrypts the audit log entries
func (a *AuditLogger) ReadLog() ([]AuditLogEntry, error) {
    f, err := os.Open(auditLogFile)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var entries []AuditLogEntry
    decoder := json.NewDecoder(f)
    for {
        var entry AuditLogEntry
        if err := decoder.Decode(&entry); err == io.EOF {
            break
        } else if err != nil {
            return nil, err
        }

        if entry.Encrypted && a.encryptionKey != nil {
            decryptedDetails, err := decrypt(entry.Details, a.encryptionKey)
            if err != nil {
                return nil, err
            }
            entry.Details = decryptedDetails
        }

        entries = append(entries, entry)
    }

    return entries, nil
}

// encrypt encrypts data using AES-GCM
func encrypt(data string, key []byte) (string, error) {
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

    encrypted := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(encrypted), nil
}

// decrypt decrypts data using AES-GCM
func decrypt(encryptedData string, key []byte) (string, error) {
    data, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("ciphertext too short")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

// getEncryptionKey retrieves the encryption key from the environment or generates a new one
func getEncryptionKey() ([]byte, error) {
    key := os.Getenv(encryptionKeyEnvVar)
    if key == "" {
        return nil, errors.New("encryption key not set in environment")
    }

    salt := make([]byte, saltSize)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, err
    }

    derivedKey, err := scrypt.Key([]byte(key), salt, scryptN, scryptR, scryptP, keyLength)
    if err != nil {
        return nil, err
    }

    return derivedKey, nil
}

// Hash creates a SHA256 hash of a given string
func Hash(data string) string {
    hash := sha256.Sum256([]byte(data))
    return fmt.Sprintf("%x", hash)
}
