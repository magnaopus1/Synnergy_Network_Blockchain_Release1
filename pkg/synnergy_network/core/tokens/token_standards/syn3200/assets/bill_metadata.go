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

// BillMetadata represents the detailed metadata associated with a bill token.
type BillMetadata struct {
	BillID          string
	Issuer          string
	Payer           string
	OriginalAmount  float64
	RemainingAmount float64
	DueDate         time.Time
	PaidStatus      bool
	TermsConditions string
	Timestamp       time.Time
}

// MetadataLedger represents an immutable ledger for storing bill metadata.
type MetadataLedger struct {
	metadataRecords map[string]BillMetadata
}

// NewMetadataLedger creates a new MetadataLedger.
func NewMetadataLedger() *MetadataLedger {
	return &MetadataLedger{
		metadataRecords: make(map[string]BillMetadata),
	}
}

// AddMetadata adds new metadata to the ledger.
func (ml *MetadataLedger) AddMetadata(metadata BillMetadata) {
	ml.metadataRecords[metadata.BillID] = metadata
}

// GetMetadata retrieves metadata by BillID.
func (ml *MetadataLedger) GetMetadata(billID string) (BillMetadata, error) {
	metadata, exists := ml.metadataRecords[billID]
	if !exists {
		return BillMetadata{}, errors.New("metadata not found")
	}
	return metadata, nil
}

// UpdateMetadata updates the metadata for an existing bill.
func (ml *MetadataLedger) UpdateMetadata(metadata BillMetadata) error {
	_, exists := ml.metadataRecords[metadata.BillID]
	if !exists {
		return errors.New("metadata not found")
	}
	ml.metadataRecords[metadata.BillID] = metadata
	return nil
}

// HashData securely hashes data using SHA-256 and returns the hexadecimal string.
func HashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// EncryptData encrypts data using AES with a key derived from the password and salt.
func EncryptData(password, data string) (string, error) {
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

// DecryptData decrypts data using AES with a key derived from the password and salt.
func DecryptData(password, encryptedData string) (string, error) {
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

// BillMetadataManager handles operations related to bill metadata.
type BillMetadataManager struct {
	metadataLedger *MetadataLedger
}

// NewBillMetadataManager creates a new BillMetadataManager.
func NewBillMetadataManager() *BillMetadataManager {
	return &BillMetadataManager{
		metadataLedger: NewMetadataLedger(),
	}
}

// CreateBillMetadata creates and stores new bill metadata.
func (bmm *BillMetadataManager) CreateBillMetadata(billID, issuer, payer string, originalAmount, remainingAmount float64, dueDate time.Time, paidStatus bool, termsConditions string) {
	metadata := BillMetadata{
		BillID:          billID,
		Issuer:          issuer,
		Payer:           payer,
		OriginalAmount:  originalAmount,
		RemainingAmount: remainingAmount,
		DueDate:         dueDate,
		PaidStatus:      paidStatus,
		TermsConditions: termsConditions,
		Timestamp:       time.Now(),
	}
	bmm.metadataLedger.AddMetadata(metadata)
}

// GetBillMetadata retrieves the metadata for a specific bill.
func (bmm *BillMetadataManager) GetBillMetadata(billID string) (BillMetadata, error) {
	return bmm.metadataLedger.GetMetadata(billID)
}

// UpdateBillMetadata updates the metadata for a specific bill.
func (bmm *BillMetadataManager) UpdateBillMetadata(metadata BillMetadata) error {
	return bmm.metadataLedger.UpdateMetadata(metadata)
}

// SecureBillMetadata securely hashes and encrypts bill metadata for storage.
func (bmm *BillMetadataManager) SecureBillMetadata(password string, metadata BillMetadata) (string, error) {
	metadataString := fmt.Sprintf("%s|%s|%s|%f|%f|%s|%t|%s|%s",
		metadata.BillID, metadata.Issuer, metadata.Payer, metadata.OriginalAmount, metadata.RemainingAmount,
		metadata.DueDate.String(), metadata.PaidStatus, metadata.TermsConditions, metadata.Timestamp.String())
	hashedData := HashData(metadataString)
	return EncryptData(password, hashedData)
}

// RetrieveSecuredBillMetadata retrieves and decrypts secured bill metadata.
func (bmm *BillMetadataManager) RetrieveSecuredBillMetadata(password, encryptedData string) (BillMetadata, error) {
	decryptedData, err := DecryptData(password, encryptedData)
	if err != nil {
		return BillMetadata{}, err
	}

	dataParts := strings.Split(decryptedData, "|")
	if len(dataParts) != 9 {
		return BillMetadata{}, errors.New("invalid decrypted data format")
	}

	originalAmount, err := strconv.ParseFloat(dataParts[3], 64)
	if err != nil {
		return BillMetadata{}, err
	}

	remainingAmount, err := strconv.ParseFloat(dataParts[4], 64)
	if err != nil {
		return BillMetadata{}, err
	}

	dueDate, err := time.Parse(time.RFC3339, dataParts[5])
	if err != nil {
		return BillMetadata{}, err
	}

	paidStatus, err := strconv.ParseBool(dataParts[6])
	if err != nil {
		return BillMetadata{}, err
	}

	timestamp, err := time.Parse(time.RFC3339, dataParts[8])
	if err != nil {
		return BillMetadata{}, err
	}

	return BillMetadata{
		BillID:          dataParts[0],
		Issuer:          dataParts[1],
		Payer:           dataParts[2],
		OriginalAmount:  originalAmount,
		RemainingAmount: remainingAmount,
		DueDate:         dueDate,
		PaidStatus:      paidStatus,
		TermsConditions: dataParts[7],
		Timestamp:       timestamp,
	}, nil
}
