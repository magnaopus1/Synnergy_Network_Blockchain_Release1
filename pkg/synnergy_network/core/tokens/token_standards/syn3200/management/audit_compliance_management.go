// Package management provides functionalities for managing audit and compliance for SYN3200 tokens.
package management

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"golang.org/x/crypto/scrypt"
)

// AuditRecord represents a record of audit or compliance check.
type AuditRecord struct {
	RecordID     string    `json:"record_id"`
	Timestamp    time.Time `json:"timestamp"`
	TransactionID string   `json:"transaction_id"`
	Details      string    `json:"details"`
	Verified     bool      `json:"verified"`
}

// ComplianceManager manages the audit and compliance records.
type ComplianceManager struct {
	DB *leveldb.DB
}

// NewComplianceManager creates a new instance of ComplianceManager.
func NewComplianceManager(dbPath string) (*ComplianceManager, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &ComplianceManager{DB: db}, nil
}

// CloseDB closes the database connection.
func (cm *ComplianceManager) CloseDB() error {
	return cm.DB.Close()
}

// AddAuditRecord adds a new audit record to the compliance manager.
func (cm *ComplianceManager) AddAuditRecord(record AuditRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return cm.DB.Put([]byte("audit_"+record.RecordID), data, nil)
}

// GetAuditRecord retrieves an audit record by its record ID.
func (cm *ComplianceManager) GetAuditRecord(recordID string) (*AuditRecord, error) {
	data, err := cm.DB.Get([]byte("audit_"+recordID), nil)
	if err != nil {
		return nil, err
	}
	var record AuditRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// GetAllAuditRecords retrieves all audit records from the compliance manager.
func (cm *ComplianceManager) GetAllAuditRecords() ([]AuditRecord, error) {
	var records []AuditRecord
	iter := cm.DB.NewIterator(util.BytesPrefix([]byte("audit_")), nil)
	defer iter.Release()
	for iter.Next() {
		var record AuditRecord
		if err := json.Unmarshal(iter.Value(), &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return records, nil
}

// ValidateAuditRecord ensures the audit record is valid before adding it to the manager.
func (cm *ComplianceManager) ValidateAuditRecord(record AuditRecord) error {
	if record.RecordID == "" {
		return errors.New("record ID must be provided")
	}
	if record.Timestamp.IsZero() {
		return errors.New("timestamp must be provided")
	}
	if record.TransactionID == "" {
		return errors.New("transaction ID must be provided")
	}
	if record.Details == "" {
		return errors.New("details must be provided")
	}
	// Add more validation rules as necessary
	return nil
}

// DeleteAuditRecord removes an audit record from the compliance manager.
func (cm *ComplianceManager) DeleteAuditRecord(recordID string) error {
	return cm.DB.Delete([]byte("audit_"+recordID), nil)
}

// UpdateAuditRecord updates an existing audit record in the compliance manager.
func (cm *ComplianceManager) UpdateAuditRecord(record AuditRecord) error {
	existingRecord, err := cm.GetAuditRecord(record.RecordID)
	if err != nil {
		return err
	}
	if existingRecord == nil {
		return errors.New("audit record not found")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return cm.DB.Put([]byte("audit_"+record.RecordID), data, nil)
}

// EncryptAuditRecord encrypts an audit record's details using AES encryption.
func EncryptAuditRecord(record *AuditRecord, passphrase string) error {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
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

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}

	encrypted := gcm.Seal(nonce, nonce, []byte(record.Details), nil)
	record.Details = fmt.Sprintf("%x", encrypted)
	return nil
}

// DecryptAuditRecord decrypts an audit record's details using AES decryption.
func DecryptAuditRecord(record *AuditRecord, passphrase string) error {
	salt := make([]byte, 16)
	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
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

	data, err := hex.DecodeString(record.Details)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	record.Details = string(plaintext)
	return nil
}
