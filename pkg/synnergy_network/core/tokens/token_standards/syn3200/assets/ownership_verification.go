// Package assets provides functionalities related to bill linking, metadata, and ownership verification for the SYN3200 Token Standard.
package assets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
)

// OwnershipRecord represents an ownership record with details about the bill and its owner.
type OwnershipRecord struct {
	BillID    string
	Owner     string
	Timestamp time.Time
}

// OwnershipLedger represents an immutable ledger for storing ownership records.
type OwnershipLedger struct {
	ownershipRecords map[string]OwnershipRecord
}

// NewOwnershipLedger creates a new OwnershipLedger.
func NewOwnershipLedger() *OwnershipLedger {
	return &OwnershipLedger{
		ownershipRecords: make(map[string]OwnershipRecord),
	}
}

// AddOwnershipRecord adds a new ownership record to the ledger.
func (ol *OwnershipLedger) AddOwnershipRecord(record OwnershipRecord) {
	ol.ownershipRecords[record.BillID] = record
}

// GetOwnershipRecord retrieves an ownership record by BillID.
func (ol *OwnershipLedger) GetOwnershipRecord(billID string) (OwnershipRecord, error) {
	record, exists := ol.ownershipRecords[billID]
	if !exists {
		return OwnershipRecord{}, errors.New("ownership record not found")
	}
	return record, nil
}

// UpdateOwnershipRecord updates the ownership record for an existing bill.
func (ol *OwnershipLedger) UpdateOwnershipRecord(record OwnershipRecord) error {
	_, exists := ol.ownershipRecords[record.BillID]
	if !exists {
		return errors.New("ownership record not found")
	}
	ol.ownershipRecords[record.BillID] = record
	return nil
}

// OwnershipVerification handles the verification of bill ownership.
type OwnershipVerification struct {
	ownershipLedger *OwnershipLedger
}

// NewOwnershipVerification creates a new OwnershipVerification.
func NewOwnershipVerification() *OwnershipVerification {
	return &OwnershipVerification{
		ownershipLedger: NewOwnershipLedger(),
	}
}

// VerifyOwnership verifies the ownership of a bill.
func (ov *OwnershipVerification) VerifyOwnership(billID, owner string) bool {
	record, err := ov.ownershipLedger.GetOwnershipRecord(billID)
	if err != nil {
		return false
	}
	return record.Owner == owner
}

// TransferOwnership transfers ownership of a bill to a new owner.
func (ov *OwnershipVerification) TransferOwnership(billID, newOwner string) error {
	record, err := ov.ownershipLedger.GetOwnershipRecord(billID)
	if err != nil {
		return err
	}
	record.Owner = newOwner
	record.Timestamp = time.Now()
	return ov.ownershipLedger.UpdateOwnershipRecord(record)
}

// Securely hash data using SHA-256 and return the hexadecimal string.
func hashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Encrypt data using AES with a key derived from the password and salt.
func encryptData(password, data string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(append(salt, ciphertext...)), nil
}

// Decrypt data using AES with a key derived from the password and salt.
func decryptData(password, encryptedData string) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	salt := data[:16]
	ciphertext := data[16:]

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
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
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// OwnershipManager manages operations related to ownership verification and transfer.
type OwnershipManager struct {
	ownershipVerification *OwnershipVerification
}

// NewOwnershipManager creates a new OwnershipManager.
func NewOwnershipManager() *OwnershipManager {
	return &OwnershipManager{
		ownershipVerification: NewOwnershipVerification(),
	}
}

// CreateOwnershipRecord creates and stores a new ownership record.
func (om *OwnershipManager) CreateOwnershipRecord(billID, owner string) {
	record := OwnershipRecord{
		BillID:    billID,
		Owner:     owner,
		Timestamp: time.Now(),
	}
	om.ownershipVerification.ownershipLedger.AddOwnershipRecord(record)
}

// VerifyBillOwnership verifies the ownership of a bill.
func (om *OwnershipManager) VerifyBillOwnership(billID, owner string) bool {
	return om.ownershipVerification.VerifyOwnership(billID, owner)
}

// TransferBillOwnership transfers the ownership of a bill to a new owner.
func (om *OwnershipManager) TransferBillOwnership(billID, newOwner string) error {
	return om.ownershipVerification.TransferOwnership(billID, newOwner)
}

// SecureOwnershipRecord securely hashes and encrypts ownership records for storage.
func (om *OwnershipManager) SecureOwnershipRecord(password string, record OwnershipRecord) (string, error) {
	recordString := fmt.Sprintf("%s|%s|%s", record.BillID, record.Owner, record.Timestamp.String())
	hashedData := hashData(recordString)
	return encryptData(password, hashedData)
}

// RetrieveSecuredOwnershipRecord retrieves and decrypts secured ownership records.
func (om *OwnershipManager) RetrieveSecuredOwnershipRecord(password, encryptedData string) (OwnershipRecord, error) {
	decryptedData, err := decryptData(password, encryptedData)
	if err != nil {
		return OwnershipRecord{}, err
	}

	dataParts := strings.Split(decryptedData, "|")
	if len(dataParts) != 3 {
		return OwnershipRecord{}, errors.New("invalid decrypted data format")
	}

	timestamp, err := time.Parse(time.RFC3339, dataParts[2])
	if err != nil {
		return OwnershipRecord{}, err
	}

	return OwnershipRecord{
		BillID:    dataParts[0],
		Owner:     dataParts[1],
		Timestamp: timestamp,
	}, nil
}
