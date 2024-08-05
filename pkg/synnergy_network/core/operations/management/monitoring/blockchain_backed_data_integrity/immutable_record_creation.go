package blockchain_backed_data_integrity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
	"github.com/synnergy-network/crypto"
	"github.com/synnergy-network/storage"
)

// DataRetrievalAnalysis handles the retrieval and analysis of data from the blockchain.
type DataRetrievalAnalysis struct {
	Storage      storage.Storage
	Crypto       crypto.Cryptography
	DataValidity map[string]bool
}

// NewDataRetrievalAnalysis creates a new instance of DataRetrievalAnalysis.
func NewDataRetrievalAnalysis(storage storage.Storage, crypto crypto.Cryptography) *DataRetrievalAnalysis {
	return &DataRetrievalAnalysis{
		Storage:      storage,
		Crypto:       crypto,
		DataValidity: make(map[string]bool),
	}
}

// RetrieveData retrieves data from the blockchain based on a given key.
func (dra *DataRetrievalAnalysis) RetrieveData(key string) (string, error) {
	data, err := dra.Storage.Get(key)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve data: %v", err)
	}
	return data, nil
}

// AnalyzeData verifies the integrity of the retrieved data.
func (dra *DataRetrievalAnalysis) AnalyzeData(data string, expectedHash string) bool {
	hashedData := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hashedData) == expectedHash
}

// LogDataIntegrity logs the integrity status of the data.
func (dra *DataRetrievalAnalysis) LogDataIntegrity(key string, status bool) {
	dra.DataValidity[key] = status
}

// GetIntegrityStatus retrieves the integrity status of the data.
func (dra *DataRetrievalAnalysis) GetIntegrityStatus(key string) (bool, error) {
	status, exists := dra.DataValidity[key]
	if !exists {
		return false, fmt.Errorf("no integrity status found for key: %s", key)
	}
	return status, nil
}

// EncryptData encrypts the data before storing it.
func (dra *DataRetrievalAnalysis) EncryptData(data string, passphrase string) (string, error) {
	encryptedData, err := dra.Crypto.Encrypt([]byte(data), passphrase)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %v", err)
	}
	return string(encryptedData), nil
}

// DecryptData decrypts the data after retrieving it.
func (dra *DataRetrievalAnalysis) DecryptData(encryptedData string, passphrase string) (string, error) {
	decryptedData, err := dra.Crypto.Decrypt([]byte(encryptedData), passphrase)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %v", err)
	}
	return string(decryptedData), nil
}

// LogRetrieval logs the retrieval event in the blockchain.
func (dra *DataRetrievalAnalysis) LogRetrieval(key string, timestamp time.Time) error {
	retrievalLog := map[string]interface{}{
		"key":       key,
		"timestamp": timestamp,
	}
	logData, err := json.Marshal(retrievalLog)
	if err != nil {
		return fmt.Errorf("failed to marshal retrieval log: %v", err)
	}

	err = dra.Storage.Put(fmt.Sprintf("log:%s", key), string(logData))
	if err != nil {
		return fmt.Errorf("failed to store retrieval log: %v", err)
	}
	return nil
}
