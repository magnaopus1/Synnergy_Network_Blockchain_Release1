package management

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

// AuditLogEntry represents a single entry in the audit log.
type AuditLogEntry struct {
	Timestamp time.Time
	Event     string
	UserID    string
	Details   string
}

// AuditLog stores a list of audit log entries.
type AuditLog struct {
	entries []AuditLogEntry
	key     []byte
}

// NewAuditLog initializes a new AuditLog with a specified encryption key.
func NewAuditLog(encryptionKey string) *AuditLog {
	hashedKey := sha256.Sum256([]byte(encryptionKey))
	return &AuditLog{
		entries: []AuditLogEntry{},
		key:     hashedKey[:],
	}
}

// EncryptData encrypts the given data using AES encryption.
func (log *AuditLog) EncryptData(data string) (string, error) {
	block, err := aes.NewCipher(log.key)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given data using AES encryption.
func (log *AuditLog) DecryptData(encryptedData string) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(log.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// LogEvent adds a new entry to the audit log.
func (log *AuditLog) LogEvent(event, userID, details string) error {
	timestamp := time.Now()
	encryptedDetails, err := log.EncryptData(details)
	if err != nil {
		return err
	}

	entry := AuditLogEntry{
		Timestamp: timestamp,
		Event:     event,
		UserID:    userID,
		Details:   encryptedDetails,
	}
	log.entries = append(log.entries, entry)
	return nil
}

// RetrieveLog retrieves and decrypts all log entries, optionally filtering by userID.
func (log *AuditLog) RetrieveLog(userID string) ([]AuditLogEntry, error) {
	var result []AuditLogEntry
	for _, entry := range log.entries {
		if userID == "" || entry.UserID == userID {
			decryptedDetails, err := log.DecryptData(entry.Details)
			if err != nil {
				return nil, err
			}
			entry.Details = decryptedDetails
			result = append(result, entry)
		}
	}
	return result, nil
}

// GenerateAuditReport generates a detailed audit report based on the log entries.
func (log *AuditLog) GenerateAuditReport() (string, error) {
	entries, err := log.RetrieveLog("")
	if err != nil {
		return "", err
	}

	report := "Audit Report\n"
	report += "====================\n"
	for _, entry := range entries {
		report += "Timestamp: " + entry.Timestamp.String() + "\n"
		report += "Event: " + entry.Event + "\n"
		report += "UserID: " + entry.UserID + "\n"
		report += "Details: " + entry.Details + "\n"
		report += "--------------------\n"
	}

	return report, nil
}

// ClearAuditLog clears all entries from the audit log. This should be used with caution.
func (log *AuditLog) ClearAuditLog() {
	log.entries = []AuditLogEntry{}
}
