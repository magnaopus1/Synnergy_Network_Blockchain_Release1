package financialinstitutions

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

// AuditRecord defines the structure for an audit trail record.
type AuditRecord struct {
	Timestamp     time.Time `json:"timestamp"`
	TransactionID string    `json:"transaction_id"`
	UserID        string    `json:"user_id"`
	Operation     string    `json:"operation"`
	Data          string    `json:"data"`
}

// AuditTrail manages the list of audit records.
type AuditTrail struct {
	Records      []AuditRecord
	EncryptionKey []byte
}

// NewAuditTrail initializes a new audit trail with an encryption key.
func NewAuditTrail(key []byte) *AuditTrail {
	return &AuditTrail{
		Records:      make([]AuditRecord, 0),
		EncryptionKey: key,
	}
}

// AddRecord adds a new record to the audit trail, encrypting it before storage.
func (at *AuditTrail) AddRecord(record AuditRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return errors.Wrap(err, "failed to marshal audit record")
	}

	encryptedData, err := encryptData(data, at.EncryptionKey)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt audit record")
	}

	log.Printf("Audit record for transaction %s added successfully", record.TransactionID)
	at.Records = append(at.Records, record)
	return nil
}

// encryptData encrypts data using AES-GCM with the provided key.
func encryptData(data []byte, key []byte) ([]byte, error) {
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

	encrypted := gcm.Seal(nil, nonce, data, nil)
	return encrypted, nil
}

// RetrieveRecords decrypts and returns all audit records.
func (at *AuditTrail) RetrieveRecords() ([]AuditRecord, error) {
	var records []AuditRecord
	for _, encryptedRecord := range at.Records {
		decryptedData, err := decryptData(encryptedRecord.Data, at.EncryptionKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decrypt audit record")
		}

		var record AuditRecord
		err = json.Unmarshal(decryptedData, &record)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal audit record")
		}
		records = append(records, record)
	}
	return records, nil
}

// decryptData decrypts data using AES-GCM with the provided key.
func decryptData(encrypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce, ciphertext := encrypted[:gcm.NonceSize()], encrypted[gcm.NonceSize():]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data")
	}
	return decrypted, nil
}
