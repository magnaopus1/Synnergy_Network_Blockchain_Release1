package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
)

// BatchTransfer represents a batch transfer of SYN131 tokens.
type BatchTransfer struct {
	ID          string                   `json:"id"`
	Sender      string                   `json:"sender"`
	Recipients  []string                 `json:"recipients"`
	Amounts     []float64                `json:"amounts"`
	AssetID     string                   `json:"asset_id"`
	Timestamp   time.Time                `json:"timestamp"`
	Status      string                   `json:"status"`
	Transactions []ledger.Transaction    `json:"transactions"`
}

// BatchTransferService provides services for batch transfers.
type BatchTransferService struct {
	ledger *ledger.TransactionLedger
}

// NewBatchTransferService creates a new BatchTransferService.
func NewBatchTransferService(ledger *ledger.TransactionLedger) *BatchTransferService {
	return &BatchTransferService{ledger: ledger}
}

// CreateBatchTransfer creates a new batch transfer.
func (service *BatchTransferService) CreateBatchTransfer(sender string, recipients []string, amounts []float64, assetID string) (*BatchTransfer, error) {
	if len(recipients) != len(amounts) {
		return nil, errors.New("recipients and amounts arrays must be of the same length")
	}

	// Generate a unique ID for the batch transfer
	hash := sha256.New()
	hash.Write([]byte(sender + assetID + time.Now().String()))
	id := hex.EncodeToString(hash.Sum(nil))

	// Create the batch transfer object
	batchTransfer := &BatchTransfer{
		ID:         id,
		Sender:     sender,
		Recipients: recipients,
		Amounts:    amounts,
		AssetID:    assetID,
		Timestamp:  time.Now(),
		Status:     "pending",
	}

	return batchTransfer, nil
}

// ExecuteBatchTransfer executes the batch transfer and records transactions in the ledger.
func (service *BatchTransferService) ExecuteBatchTransfer(batchTransfer *BatchTransfer) error {
	for i, recipient := range batchTransfer.Recipients {
		transaction := ledger.Transaction{
			ID:        generateTransactionID(batchTransfer.ID, i),
			Sender:    batchTransfer.Sender,
			Recipient: recipient,
			Amount:    batchTransfer.Amounts[i],
			AssetID:   batchTransfer.AssetID,
			Timestamp: time.Now(),
			Status:    "completed",
		}

		err := service.ledger.RecordTransaction(&transaction)
		if err != nil {
			return err
		}

		batchTransfer.Transactions = append(batchTransfer.Transactions, transaction)
	}

	batchTransfer.Status = "completed"
	return nil
}

// GetBatchTransfer retrieves a batch transfer by ID.
func (service *BatchTransferService) GetBatchTransfer(id string) (*BatchTransfer, error) {
	// This is a placeholder function and should be implemented to retrieve batch transfers from the storage.
	return nil, errors.New("not implemented")
}

// generateTransactionID generates a unique transaction ID for each transfer within the batch.
func generateTransactionID(batchID string, index int) string {
	hash := sha256.New()
	hash.Write([]byte(batchID + string(index)))
	return hex.EncodeToString(hash.Sum(nil))
}
