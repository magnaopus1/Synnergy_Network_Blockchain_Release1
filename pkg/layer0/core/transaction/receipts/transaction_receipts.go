package transaction

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"synthron_blockchain_final/pkg/layer0/core/blockchain"
	"synthron_blockchain_final/pkg/layer0/core/security"
)

// TransactionReceipt stores metadata about the results of a transaction processing.
type TransactionReceipt struct {
	TransactionID string
	Status        string
	BlockHash     string
	Timestamp     time.Time
	GasUsed       uint64
	ErrorMessage  string
}

// ReceiptManager handles creating and storing transaction receipts.
type ReceiptManager struct {
	sync.Mutex
	Blockchain *blockchain.Blockchain
	ReceiptsDB map[string]*TransactionReceipt
}

// NewReceiptManager initializes a new manager for transaction receipts.
func NewReceiptManager(bc *blockchain.Blockchain) *ReceiptManager {
	return &ReceiptManager{
		Blockchain: bc,
		ReceiptsDB: make(map[string]*TransactionReceipt),
	}
}

// CreateReceipt generates a receipt following the execution of a transaction.
func (rm *ReceiptManager) CreateReceipt(txID string, status string, blockHash string, gasUsed uint64, errMessage string) *TransactionReceipt {
	receipt := &TransactionTransactionReceipt{
		TransactionID: txID,
		Status:        status,
		BlockHash:     blockHash,
		Timestamp:     time.Now(),
		GasUsed:       gasUsed,
		ErrorMessage:  errMessage,
	}

	rm.Lock()
	defer rm.Unlock()
	rm.ReceiptsDB[txID] = receipt
	return receipt
}

// GetReceipt retrieves a transaction receipt by transaction ID.
func (rm *ReceiptManager) GetReceipt(txID string) (*TransactionReceipt, error) {
	rm.Lock()
	defer rmUnlock()

	receipt, exists := rm.ReceiptsDB[txID]
	if !exists {
		return nil, errors.New("receipt not found")
	}
	return receipt, nil
}

// AuditTransaction verifies the integrity and authenticity of a transaction receipt.
func (rm *ReceiptManager) AuditTransaction(receipt *TransactionReceipt) bool {
	tx, exists := rm.Blockchain.FindTransactionByID(receipt.TransactionID)
	if !exists {
		return false
	}

	expectedHash := sha256.Sum256([]byte(tx.String() + receipt.Status))
	return hex.EncodeToString(expectedHash[:]) == receipt.BlockHash
}

// init sets up cryptographic modules used in generating and verifying receipts.
func init() {
	security.SetupCryptography("AES", "Scrypt", "Argon2") // Configure cryptographic algorithms used throughout the blockchain
}
