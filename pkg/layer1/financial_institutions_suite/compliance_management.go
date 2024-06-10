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

// ComplianceRecord defines the structure for a compliance data record.
type ComplianceRecord struct {
	ID           string    `json:"id"`
	Document     string    `json:"document"`
	Status       string    `json:"status"`
	LastReviewed time.Time `json:"last_reviewed"`
}

// ComplianceManager handles the compliance of various financial regulations.
type ComplianceManager struct {
	Records       []ComplianceRecord
	EncryptionKey []byte
}

// NewComplianceManager creates a new manager with the specified encryption key.
func NewComplianceManager(key []byte) *ComplianceManager {
	return &ComplianceManager{
		Records:       make([]ComplianceRecord, 0),
		EncryptionKey: key,
	}
}

// AddRecord adds a new compliance record, encrypting the document content before storage.
func (cm *ComplianceManager) AddRecord(record ComplianceRecord) error {
	encryptedDocument, err := encryptData([]byte(record.Document), cm.EncryptionKey)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt compliance document")
	}
	record.Document = string(encryptedDocument)
	cm.Records = append(cm.Records, record)
	log.Printf("Compliance record added: %s", record.ID)
	return nil
}

// UpdateComplianceStatus updates the compliance status for a given record.
func (cm *ComplianceManager) UpdateComplianceStatus(recordID, status string) error {
	for i, record := range cm.Records {
		if record.ID == recordID {
			cm.Records[i].Status = status
			cm.Records[i].LastReviewed = time.Now()
			log.Printf("Compliance status updated for record %s: %s", recordID, status)
			return nil
		}
	}
	return errors.New("compliance record not found")
}

// EncryptData encrypts data using AES-GCM with the provided key.
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

// RetrieveRecords decrypts and returns all compliance records for review.
func (cm *ComplianceManager) RetrieveRecords() ([]ComplianceRecord, error) {
	var decryptedRecords []ComplianceRecord
	for _, record := range cm.Records {
		decryptedData, err := decryptData([]byte(record.Document), cm.EncryptionKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decrypt compliance document")
		}
		record.Document = string(decryptedData)
		decryptedRecords = append(decryptedRecords, record)
	}
	return decryptedRecords, nil
}

// DecryptData decrypts data using AES-GCM with the provided key.
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
