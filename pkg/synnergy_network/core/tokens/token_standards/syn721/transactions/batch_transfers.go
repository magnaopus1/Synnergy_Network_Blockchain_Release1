package transactions

import (
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/ledger"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/security"
)

// BatchTransfer represents a batch transfer of SYN721 tokens
type BatchTransfer struct {
	TokenIDs  []string
	NewOwner  string
	Timestamp time.Time
	Status    string
}

// BatchTransferManager manages batch transfers for SYN721 tokens
type BatchTransferManager struct {
	ledger          *ledger.Ledger
	securityManager *security.SecurityManager
	transfers       map[string]BatchTransfer
	mutex           sync.Mutex
}

// NewBatchTransferManager initializes a new BatchTransferManager
func NewBatchTransferManager(ledger *ledger.Ledger, securityManager *security.SecurityManager) *BatchTransferManager {
	return &BatchTransferManager{
		ledger:          ledger,
		securityManager: securityManager,
		transfers:       make(map[string]BatchTransfer),
	}
}

// CreateBatchTransfer creates a new batch transfer
func (btm *BatchTransferManager) CreateBatchTransfer(tokenIDs []string, newOwner string) (string, error) {
	btm.mutex.Lock()
	defer btm.mutex.Unlock()

	transferID := fmt.Sprintf("%d", time.Now().UnixNano())
	transfer := BatchTransfer{
		TokenIDs:  tokenIDs,
		NewOwner:  newOwner,
		Timestamp: time.Now(),
		Status:    "pending",
	}

	btm.transfers[transferID] = transfer
	return transferID, nil
}

// ExecuteBatchTransfer executes a batch transfer of SYN721 tokens
func (btm *BatchTransferManager) ExecuteBatchTransfer(transferID string) error {
	btm.mutex.Lock()
	defer btm.mutex.Unlock()

	transfer, exists := btm.transfers[transferID]
	if !exists {
		return fmt.Errorf("batch transfer with ID %s not found", transferID)
	}

	for _, tokenID := range transfer.TokenIDs {
		token, err := btm.ledger.GetToken(tokenID)
		if err != nil {
			return fmt.Errorf("failed to get token %s: %v", tokenID, err)
		}

		err = btm.ledger.TransferOwnership(tokenID, transfer.NewOwner)
		if err != nil {
			return fmt.Errorf("failed to transfer token %s to %s: %v", tokenID, transfer.NewOwner, err)
		}
	}

	transfer.Status = "completed"
	btm.transfers[transferID] = transfer
	return nil
}

// CancelBatchTransfer cancels a batch transfer of SYN721 tokens
func (btm *BatchTransferManager) CancelBatchTransfer(transferID string) error {
	btm.mutex.Lock()
	defer btm.mutex.Unlock()

	transfer, exists := btm.transfers[transferID]
	if !exists {
		return fmt.Errorf("batch transfer with ID %s not found", transferID)
	}

	transfer.Status = "cancelled"
	btm.transfers[transferID] = transfer
	return nil
}

// GetBatchTransfer retrieves a batch transfer by its ID
func (btm *BatchTransferManager) GetBatchTransfer(transferID string) (BatchTransfer, error) {
	btm.mutex.Lock()
	defer btm.mutex.Unlock()

	transfer, exists := btm.transfers[transferID]
	if !exists {
		return BatchTransfer{}, fmt.Errorf("batch transfer with ID %s not found", transferID)
	}

	return transfer, nil
}

// ListBatchTransfers lists all batch transfers
func (btm *BatchTransferManager) ListBatchTransfers() []BatchTransfer {
	btm.mutex.Lock()
	defer btm.mutex.Unlock()

	var transfers []BatchTransfer
	for _, transfer := range btm.transfers {
		transfers = append(transfers, transfer)
	}

	return transfers
}
