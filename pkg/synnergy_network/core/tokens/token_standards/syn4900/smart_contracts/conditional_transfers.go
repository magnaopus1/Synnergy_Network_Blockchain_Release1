// Package smart_contracts provides functionality for managing smart contracts
// related to agricultural tokens in the SYN4900 Token Standard.
package smart_contracts

import (
	"errors"
	"fmt"
	"time"
	"sync"

	"github.com/synnergy_network/ledger"
	"github.com/synnergy_network/transactions"
)

// ConditionalTransfer represents a conditional transfer within the SYN4900 token ecosystem.
type ConditionalTransfer struct {
	TransferID    string
	TokenID       string
	From          string
	To            string
	Quantity      float64
	Conditions    []TransferCondition
	Status        string
	CreationDate  time.Time
	CompletionDate time.Time
	mutex         sync.Mutex
}

// TransferCondition represents a condition that must be met for a transfer to be completed.
type TransferCondition struct {
	Description string
	Met         bool
}

// ConditionalTransferManager manages conditional transfers for SYN4900 tokens.
type ConditionalTransferManager struct {
	transfers map[string]ConditionalTransfer
	mutex     sync.Mutex
}

// NewConditionalTransferManager initializes a new ConditionalTransferManager.
func NewConditionalTransferManager() *ConditionalTransferManager {
	return &ConditionalTransferManager{
		transfers: make(map[string]ConditionalTransfer),
	}
}

// CreateTransfer initiates a new conditional transfer.
func (ctm *ConditionalTransferManager) CreateTransfer(tokenID, from, to string, quantity float64, conditions []TransferCondition) (ConditionalTransfer, error) {
	ctm.mutex.Lock()
	defer ctm.mutex.Unlock()

	if tokenID == "" || from == "" || to == "" || quantity <= 0 || len(conditions) == 0 {
		return ConditionalTransfer{}, errors.New("invalid transfer details")
	}

	transferID := generateTransferID(tokenID, from, to, time.Now())
	transfer := ConditionalTransfer{
		TransferID:   transferID,
		TokenID:      tokenID,
		From:         from,
		To:           to,
		Quantity:     quantity,
		Conditions:   conditions,
		Status:       "Pending",
		CreationDate: time.Now(),
	}

	ctm.transfers[transferID] = transfer
	return transfer, nil
}

// UpdateCondition updates a specific condition of a conditional transfer.
func (ctm *ConditionalTransferManager) UpdateCondition(transferID string, conditionIndex int, met bool) (ConditionalTransfer, error) {
	ctm.mutex.Lock()
	defer ctm.mutex.Unlock()

	transfer, exists := ctm.transfers[transferID]
	if !exists {
		return ConditionalTransfer{}, errors.New("transfer not found")
	}

	if conditionIndex < 0 || conditionIndex >= len(transfer.Conditions) {
		return ConditionalTransfer{}, errors.New("invalid condition index")
	}

	transfer.Conditions[conditionIndex].Met = met
	ctm.transfers[transferID] = transfer

	return transfer, nil
}

// CompleteTransfer completes a conditional transfer if all conditions are met.
func (ctm *ConditionalTransferManager) CompleteTransfer(transferID string) (ConditionalTransfer, error) {
	ctm.mutex.Lock()
	defer ctm.mutex.Unlock()

	transfer, exists := ctm.transfers[transferID]
	if !exists {
		return ConditionalTransfer{}, errors.New("transfer not found")
	}

	for _, condition := range transfer.Conditions {
		if !condition.Met {
			return ConditionalTransfer{}, errors.New("not all conditions are met")
		}
	}

	// Update the ledger and transaction records accordingly.
	err := ledger.RecordTransaction(transfer.TokenID, transfer.From, transfer.To, transfer.Quantity)
	if err != nil {
		return ConditionalTransfer{}, err
	}

	transfer.Status = "Completed"
	transfer.CompletionDate = time.Now()
	ctm.transfers[transferID] = transfer

	return transfer, nil
}

// GetTransfer retrieves the details of a specific conditional transfer by its ID.
func (ctm *ConditionalTransferManager) GetTransfer(transferID string) (ConditionalTransfer, error) {
	ctm.mutex.Lock()
	defer ctm.mutex.Unlock()

	transfer, exists := ctm.transfers[transferID]
	if !exists {
		return ConditionalTransfer{}, errors.New("transfer not found")
	}

	return transfer, nil
}

// ListTransfers returns all conditional transfers managed by the system.
func (ctm *ConditionalTransferManager) ListTransfers() []ConditionalTransfer {
	ctm.mutex.Lock()
	defer ctm.mutex.Unlock()

	transfers := make([]ConditionalTransfer, 0)
	for _, transfer := range ctm.transfers {
		transfers = append(transfers, transfer)
	}

	return transfers
}

// generateTransferID generates a unique ID for a conditional transfer.
func generateTransferID(tokenID, from, to string, createdAt time.Time) string {
	return fmt.Sprintf("CT-%s-%s-%s-%d", tokenID, from, to, createdAt.Unix())
}
