package management

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
)

// FeeManager handles fee-related tasks in the blockchain
type FeeManager struct {
	mutex         sync.Mutex
	feeStructure  map[string]float64
	encryptionKey []byte
}

// NewFeeManager creates a new FeeManager
func NewFeeManager(encryptionKey string) *FeeManager {
	return &FeeManager{
		feeStructure: make(map[string]float64),
		encryptionKey: []byte(encryptionKey),
	}
}

// SetFee sets the fee for a specific transaction type
func (fm *FeeManager) SetFee(transactionType string, fee float64) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	fm.feeStructure[transactionType] = fee
}

// GetFee retrieves the fee for a specific transaction type
func (fm *FeeManager) GetFee(transactionType string) (float64, error) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	fee, exists := fm.feeStructure[transactionType]
	if !exists {
		return 0, errors.New("transaction type not found")
	}
	return fee, nil
}

// AdjustFee adjusts the fee for a specific transaction type
func (fm *FeeManager) AdjustFee(transactionType string, adjustment float64) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	fee, exists := fm.feeStructure[transactionType]
	if !exists {
		return errors.New("transaction type not found")
	}
	fm.feeStructure[transactionType] = fee + adjustment
	return nil
}

// CalculateTotalFee calculates the total fee for a batch of transactions
func (fm *FeeManager) CalculateTotalFee(transactionTypes []string) (float64, error) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	var totalFee float64
	for _, transactionType := range transactionTypes {
		fee, exists := fm.feeStructure[transactionType]
		if !exists {
			return 0, fmt.Errorf("transaction type %s not found", transactionType)
		}
		totalFee += fee
	}
	return totalFee, nil
}

// EncryptFeeStructure encrypts the fee structure using AES-GCM
func (fm *FeeManager) EncryptFeeStructure() (string, error) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	data, err := serializeFeeStructure(fm.feeStructure)
	if err != nil {
		return "", err
	}
	encryptedData, err := fm.encrypt(data)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptFeeStructure decrypts the fee structure using AES-GCM
func (fm *FeeManager) DecryptFeeStructure(encryptedData string) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	data, err := fm.decrypt(encryptedData)
	if err != nil {
		return err
	}
	feeStructure, err := deserializeFeeStructure(data)
	if err != nil {
		return err
	}
	fm.feeStructure = feeStructure
	return nil
}

// Helper function to encrypt data using AES-GCM
func (fm *FeeManager) encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(fm.encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Helper function to decrypt data using AES-GCM
func (fm *FeeManager) decrypt(encryptedData string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(fm.encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Helper function to serialize fee structure
func serializeFeeStructure(feeStructure map[string]float64) ([]byte, error) {
	return json.Marshal(feeStructure)
}

// Helper function to deserialize fee structure
func deserializeFeeStructure(data []byte) (map[string]float64, error) {
	var feeStructure map[string]float64
	err := json.Unmarshal(data, &feeStructure)
	return feeStructure, err
}
