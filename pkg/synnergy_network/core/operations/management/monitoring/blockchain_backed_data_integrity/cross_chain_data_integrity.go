package blockchain_backed_data_integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/core/operations/management/monitoring/utils"
	"github.com/synnergy_network/pkg/synnergy_network/core/operations/management/monitoring/blockchain"
)

// DataRecord represents a record of data backed by the blockchain.
type DataRecord struct {
	ID        string
	Data      string
	Timestamp time.Time
	Hash      string
	Signature string
}

// BlockchainBackedDataIntegrity provides methods for ensuring data integrity using blockchain technology.
type BlockchainBackedDataIntegrity struct {
	blockchainClient blockchain.Client
	encryptionUtil   utils.EncryptionUtils
}

// NewBlockchainBackedDataIntegrity creates a new instance of BlockchainBackedDataIntegrity.
func NewBlockchainBackedDataIntegrity(client blockchain.Client, encryptionUtil utils.EncryptionUtils) *BlockchainBackedDataIntegrity {
	return &BlockchainBackedDataIntegrity{
		blockchainClient: client,
		encryptionUtil:   encryptionUtil,
	}
}

// CreateDataRecord creates a new data record and stores it on the blockchain.
func (bdi *BlockchainBackedDataIntegrity) CreateDataRecord(data string) (*DataRecord, error) {
	timestamp := time.Now()
	hash := sha256.Sum256([]byte(data + timestamp.String()))
	hashStr := hex.EncodeToString(hash[:])
	signature, err := bdi.encryptionUtil.Sign(hashStr)
	if err != nil {
		return nil, err
	}

	record := &DataRecord{
		ID:        generateID(),
		Data:      data,
		Timestamp: timestamp,
		Hash:      hashStr,
		Signature: signature,
	}

	err = bdi.blockchainClient.StoreRecord(record)
	if err != nil {
		return nil, err
	}

	return record, nil
}

// VerifyDataRecord verifies the integrity of a data record using the blockchain.
func (bdi *BlockchainBackedDataIntegrity) VerifyDataRecord(record *DataRecord) (bool, error) {
	storedRecord, err := bdi.blockchainClient.GetRecord(record.ID)
	if err != nil {
		return false, err
	}

	if storedRecord.Hash != record.Hash {
		return false, errors.New("data integrity check failed: hash mismatch")
	}

	if !bdi.encryptionUtil.Verify(storedRecord.Hash, storedRecord.Signature) {
		return false, errors.New("data integrity check failed: signature mismatch")
	}

	return true, nil
}

// generateID generates a unique ID for a data record.
func generateID() string {
	hash := sha256.Sum256([]byte(time.Now().String()))
	return hex.EncodeToString(hash[:])
}
