package compliance_tracking

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"log"
	"time"

	"github.com/pkg/errors"
)

// ComplianceRecord defines the structure for compliance data.
type ComplianceRecord struct {
	EntityID       string    `json:"entity_id"`
	ComplianceData string    `json:"compliance_data"`
	Timestamp      time.Time `json:"timestamp"`
}

// ComplianceManager handles the compliance records of blockchain entities.
type ComplianceManager struct {
	records      map[string]ComplianceRecord
	encryptionKey []byte
}

// NewComplianceManager creates a new instance of ComplianceManager with a given encryption key.
func NewComplianceManager(key []byte) *ComplianceManager {
	return &ComplianceManager{
		records:      make(map[string]ComplianceRecord),
		encryptionKey: key,
	}
}

// AddComplianceRecord adds a new compliance record for a blockchain entity.
func (cm *ComplianceManager) AddComplianceRecord(entityID, data string) error {
	record := ComplianceRecord{
		EntityID:       entityID,
		ComplianceData: data,
		Timestamp:      time.Now(),
	}
	encryptedData, err := cm.encryptData(json.Marshal(record))
	if err != nil {
		return errors.Wrap(err, "failed to encrypt compliance data")
	}
	cm.records[entityID] = ComplianceRecord{
		EntityID:       entityID,
		ComplianceData: encryptedData,
		Timestamp:      record.Timestamp,
	}
	log.Printf("Compliance record added for entity: %s", entityID)
	return nil
}

// GetComplianceRecord retrieves a compliance record for a specified entity.
func (cm *ComplianceManager) GetComplianceRecord(entityID string) (ComplianceRecord, error) {
	record, exists := cm.records[entityID]
	if !exists {
		return ComplianceRecord{}, errors.New("compliance record not found")
	}
	decryptedData, err := cm.decryptData(record.ComplianceData)
	if err != nil {
		return ComplianceRecord{}, errors.Wrap(err, "failed to decrypt compliance data")
	}
	record.ComplianceData = decryptedData
	return record, nil
}

// encryptData encrypts data using AES encryption with the manager's key.
func (cm *ComplianceManager) encryptData(data []byte) (string, error) {
	block, err := aes.NewCipher(cm.encryptionKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to create cipher block")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "failed to create GCM")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrap(err, "failed to generate nonce")
	}
	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return string(encrypted), nil
}

// decryptData decrypts data using AES decryption.
func (cm *ComplianceManager) decryptData(data string) (string, error) {
	byteData := []byte(data)
	block, err := aes.NewCipher(cm.encryptionKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to create cipher block")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "failed to create GCM")
	}
	nonceSize := gcm.NonceSize()
	if len(byteData) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := byteData[:nonceSize], byteData[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to decrypt data")
	}
	return string(decrypted), nil
}

