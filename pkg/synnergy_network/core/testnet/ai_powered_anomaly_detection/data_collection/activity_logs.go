package data_collection

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"golang.org/x/crypto/scrypt"
)

// LogEntry represents a single log entry in the activity log
type LogEntry struct {
	Timestamp time.Time
	Activity  string
	Details   string
}

// ActivityLogger handles logging of network activities
type ActivityLogger struct {
	LogFilePath   string
	EncryptionKey []byte
}

// NewActivityLogger creates a new ActivityLogger
func NewActivityLogger(logFilePath string, encryptionKey []byte) *ActivityLogger {
	return &ActivityLogger{
		LogFilePath:   logFilePath,
		EncryptionKey: encryptionKey,
	}
}

// LogActivity logs a new activity to the activity log
func (logger *ActivityLogger) LogActivity(activity, details string) error {
	entry := LogEntry{
		Timestamp: time.Now(),
		Activity:  activity,
		Details:   details,
	}
	data, err := encryptLogEntry(entry, logger.EncryptionKey)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(logger.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(data + "\n")
	return err
}

// GetLogs retrieves and decrypts all logs
func (logger *ActivityLogger) GetLogs() ([]LogEntry, error) {
	data, err := ioutil.ReadFile(logger.LogFilePath)
	if err != nil {
		return nil, err
	}

	lines := string(data)
	var entries []LogEntry
	for _, line := range strings.Split(lines, "\n") {
		if len(line) > 0 {
			entry, err := decryptLogEntry(line, logger.EncryptionKey)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// encryptLogEntry encrypts a log entry using AES
func encryptLogEntry(entry LogEntry, key []byte) (string, error) {
	plaintext, err := json.Marshal(entry)
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
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptLogEntry decrypts a log entry using AES
func decryptLogEntry(ciphertext string, key []byte) (LogEntry, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return LogEntry{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return LogEntry{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return LogEntry{}, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return LogEntry{}, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return LogEntry{}, err
	}

	var entry LogEntry
	err = json.Unmarshal(plaintext, &entry)
	if err != nil {
		return LogEntry{}, err
	}
	return entry, nil
}

// deriveKey derives an encryption key from a password using scrypt
func deriveKey(password []byte) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}
