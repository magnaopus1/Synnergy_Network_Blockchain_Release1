package audits

import (
	"encoding/json"
	"log"
	"time"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSize = 16
	KeyLength = 32
	ArgonTime = 1
	ArgonMemory = 64 * 1024
	ArgonThreads = 4
)

type AuditRecord struct {
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	Actor       string    `json:"actor"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
}

type AuditTrailManager struct {
	Salt []byte
}

func NewAuditTrailManager() *AuditTrailManager {
	salt, err := GenerateSalt()
	if err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}
	return &AuditTrailManager{Salt: salt}
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func (atm *AuditTrailManager) LogEvent(actor, action, description string) (*AuditRecord, error) {
	record := &AuditRecord{
		EventID:     generateUUID(),
		Timestamp:   time.Now(),
		Actor:       actor,
		Action:      action,
		Description: description,
	}
	encryptedData, err := atm.EncryptData(record)
	if err != nil {
		return nil, err
	}
	log.Printf("Logged and encrypted event: %x", encryptedData)
	return record, nil
}

func (atm *AuditTrailManager) EncryptData(record *AuditRecord) ([]byte, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return argon2.IDKey(data, atm.Salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength), nil
}

func (atm *AuditTrailManager) DecryptData(encryptedData []byte) (*AuditRecord, error) {
	// Decryption is simulated as Argon2 is primarily a hashing function
	data, err := argon2.IDKey(encryptedData, atm.Salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength)
	if err != nil {
		return nil, err
	}
	var record AuditRecord
	err = json.Unmarshal(data, &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func generateUUID() string {
	// This is a placeholder function. Replace it with actual UUID generation logic.
	return "UUID-1234-5678-91011"
}

func main() {
	manager := NewAuditTrailManager()
	record, err := manager.LogEvent("admin", "modify", "Changed access level of user X.")
	if err != nil {
		log.Fatalf("Error logging event: %v", err)
	}
	log.Println("Audit record created:", record)
}
