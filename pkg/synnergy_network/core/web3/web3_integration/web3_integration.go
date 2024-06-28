package authentication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/scrypt"
)

// AuthLog defines the structure for logging authentication events.
type AuthLog struct {
	Timestamp   time.Time
	UserID      string
	Event       string
	Description string
	IPAddress   string
}

// AuthLogger manages the logging of authentication events to a secure store.
type AuthLogger struct {
	file    *os.File
	aesGCM  cipher.AEAD
}

// NewAuthLogger creates a new AuthLogger with encrypted storage.
func NewAuthLogger(filepath, passphrase string) (*AuthLogger, error) {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	key, salt, err := deriveKey(passphrase)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AuthLogger{
		file:   file,
		aesGCM: aesGCM,
	}, nil
}

// deriveKey generates a key from a passphrase using Scrypt.
func deriveKey(passphrase string) ([]byte, []byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

// EncryptLogEntry encrypts a log entry for secure storage.
func (l *AuthLogger) EncryptLogEntry(logEntry AuthLog) (string, error) {
	plaintext, err := json.Marshal(logEntry)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, l.aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := l.aesGCM.Seal(nil, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), nil
}

// LogEntry logs a new authentication event securely.
func (l *AuthLogger) LogEntry(logEntry AuthLog) error {
	encryptedLog, err := l.EncryptLogEntry(logEntry)
	if err != nil {
		return err
	}

	if _, err := l.file.WriteString(encryptedLog + "\n"); err != nil {
		return err
	}

	return nil
}

// Close cleans up any resources used by the AuthLogger.
func (l *AuthLogger) Close() error {
	return l.file.Close()
}
