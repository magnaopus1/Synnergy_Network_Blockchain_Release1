package centralized_control_tokens

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"time"

	"github.com/pkg/errors"
)

// ComplianceAuditRecord defines the structure for compliance data.
type ComplianceAuditRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	UserID      string    `json:"user_id"`
	TransactionID string  `json:"transaction_id"`
	Action      string    `json:"action"`
	Result      string    `json:"result"`
	Details     string    `json:"details"`
}

// Auditor provides an interface for compliance audit functionalities.
type Auditor interface {
	LogCompliance(record ComplianceAuditRecord) error
	EncryptRecord(data []byte, key []byte) ([]byte, error)
	DecryptRecord(data []byte, key []byte) ([]byte, error)
}

// TokenAuditor implements the Auditor interface with AES encryption.
type TokenAuditor struct {
	encryptionKey []byte
}

// NewTokenAuditor creates a new TokenAuditor with the provided encryption key.
func NewTokenAuditor(key []byte) *TokenAuditor {
	return &TokenAuditor{
		encryptionKey: key,
	}
}

// LogCompliance logs a compliance record in JSON format and encrypts it.
func (ta *TokenAuditor) LogCompliance(record ComplianceAuditRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return errors.Wrap(err, "failed to marshal compliance record")
	}

	encryptedData, err := ta.EncryptRecord(data, ta.encryptionKey)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt compliance record")
	}

	log.Println("Compliance Record Encrypted: ", encryptedData)
	return nil
}

// EncryptRecord encrypts data using AES-256-GCM.
func (ta *TokenAuditor) EncryptRecord(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// DecryptRecord decrypts data using AES-256-GCM.
func (ta *TokenAuditor) DecryptRecord(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data")
	}

	return decrypted, nil
}
