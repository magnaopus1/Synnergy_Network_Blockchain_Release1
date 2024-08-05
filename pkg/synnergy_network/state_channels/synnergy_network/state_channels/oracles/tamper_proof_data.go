package oracles

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// TamperProofData represents tamper-proof data for decentralized oracles
type TamperProofData struct {
	DataID         string
	Data           map[string]interface{}
	Hash           string
	Timestamp      time.Time
	Status         string
	lock           sync.RWMutex
}

const (
	DataActive   = "ACTIVE"
	DataInactive = "INACTIVE"
	DataTampered = "TAMPERED"
)

// NewTamperProofData initializes a new TamperProofData instance
func NewTamperProofData(dataID string, data map[string]interface{}) *TamperProofData {
	hash := hashData(data)
	return &TamperProofData{
		DataID:    dataID,
		Data:      data,
		Hash:      hash,
		Timestamp: time.Now(),
		Status:    DataActive,
	}
}

// UpdateData updates the data and re-computes the hash
func (tpd *TamperProofData) UpdateData(newData map[string]interface{}) error {
	tpd.lock.Lock()
	defer tpd.lock.Unlock()

	if tpd.Status != DataActive {
		return errors.New("data is not active")
	}

	tpd.Data = newData
	tpd.Hash = hashData(newData)
	tpd.Timestamp = time.Now()
	return nil
}

// DeactivateData deactivates the tamper-proof data
func (tpd *TamperProofData) DeactivateData() error {
	tpd.lock.Lock()
	defer tpd.lock.Unlock()

	if tpd.Status != DataActive {
		return errors.New("data is not active")
	}

	tpd.Status = DataInactive
	tpd.Timestamp = time.Now()
	return nil
}

// EncryptData encrypts the tamper-proof data details
func (tpd *TamperProofData) EncryptData(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%s",
		tpd.DataID, tpd.Data, tpd.Hash, tpd.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the tamper-proof data details
func (tpd *TamperProofData) DecryptData(encryptedData string, key []byte) error {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
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

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	parts := utils.Split(string(data), '|')
	if len(parts) != 4 {
		return errors.New("invalid encrypted data format")
	}

	tpd.DataID = parts[0]
	tpd.Data = utils.ParseData(parts[1])
	tpd.Hash = parts[2]
	tpd.Status = parts[3]
	return nil
}

// GetDataDetails returns the details of the tamper-proof data
func (tpd *TamperProofData) GetDataDetails() (string, map[string]interface{}, string, string) {
	tpd.lock.RLock()
	defer tpd.lock.RUnlock()
	return tpd.DataID, tpd.Data, tpd.Hash, tpd.Status
}

// ValidateData validates the tamper-proof data details
func (tpd *TamperProofData) ValidateData() error {
	tpd.lock.RLock()
	defer tpd.lock.RUnlock()

	if tpd.DataID == "" {
		return errors.New("data ID cannot be empty")
	}

	if len(tpd.Data) == 0 {
		return errors.New("data cannot be empty")
	}

	if tpd.Hash == "" {
		return errors.New("hash cannot be empty")
	}

	return nil
}

// VerifyData verifies the data integrity by comparing the hashes
func (tpd *TamperProofData) VerifyData() error {
	tpd.lock.RLock()
	defer tpd.lock.RUnlock()

	currentHash := hashData(tpd.Data)
	if currentHash != tpd.Hash {
		tpd.Status = DataTampered
		tpd.Timestamp = time.Now()
		return errors.New("data integrity check failed")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the tamper-proof data
func (tpd *TamperProofData) UpdateTimestamp() {
	tpd.lock.Lock()
	defer tpd.lock.Unlock()
	tpd.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the tamper-proof data
func (tpd *TamperProofData) GetTimestamp() time.Time {
	tpd.lock.RLock()
	defer tpd.lock.RUnlock()
	return tpd.Timestamp
}

// GenerateKey generates a cryptographic key using Argon2
func GenerateKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// GenerateSalt generates a cryptographic salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// HashData hashes the data using SHA-256
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func hashData(data map[string]interface{}) string {
	serializedData := fmt.Sprintf("%v", data)
	hash := sha256.Sum256([]byte(serializedData))
	return fmt.Sprintf("%x", hash)
}

func (tpd *TamperProofData) String() string {
	return fmt.Sprintf("DataID: %s, Hash: %s, Status: %s, Timestamp: %s", tpd.DataID, tpd.Hash, tpd.Status, tpd.Timestamp)
}
