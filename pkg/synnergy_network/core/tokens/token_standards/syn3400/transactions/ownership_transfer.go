package transactions

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
)

// OwnershipTransfer represents a transfer of ownership of a Forex token
type OwnershipTransfer struct {
	TransferID    string
	TokenID       string
	From          string
	To            string
	Timestamp     time.Time
	TransactionID string
}

// OwnershipTransferManager manages the ownership transfers
type OwnershipTransferManager struct {
	transfers           []OwnershipTransfer
	mutex               sync.Mutex
	ledgerManager       *ledger.LedgerManager
	tokenManager        *assets.TokenManager
	eventLogger         *events.EventLogger
	transferChannel     chan OwnershipTransfer
	verificationChannel chan OwnershipTransfer
}

// NewOwnershipTransferManager initializes a new OwnershipTransferManager instance
func NewOwnershipTransferManager(ledgerMgr *ledger.LedgerManager, tokenMgr *assets.TokenManager, eventLogger *events.EventLogger) (*OwnershipTransferManager, error) {
	return &OwnershipTransferManager{
		transfers:           []OwnershipTransfer{},
		ledgerManager:       ledgerMgr,
		tokenManager:        tokenMgr,
		eventLogger:         eventLogger,
		transferChannel:     make(chan OwnershipTransfer, 100),
		verificationChannel: make(chan OwnershipTransfer, 100),
	}, nil
}

// StartProcessing starts processing ownership transfers
func (otm *OwnershipTransferManager) StartProcessing() {
	go func() {
		for transfer := range otm.transferChannel {
			otm.mutex.Lock()
			otm.transfers = append(otm.transfers, transfer)
			otm.mutex.Unlock()
			otm.verifyOwnershipTransfer(transfer)
			otm.recordTransfer(transfer)
			otm.logEvent(transfer)
		}
	}()
}

// generateTransferID generates a unique ID for a transfer
func generateTransferID() (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	hash := sha256.Sum256(id)
	return hex.EncodeToString(hash[:]), nil
}

// TransferOwnership transfers ownership of a Forex token
func (otm *OwnershipTransferManager) TransferOwnership(tokenID, from, to string) error {
	otm.mutex.Lock()
	defer otm.mutex.Unlock()

	// Verify token ownership
	currentOwner, err := otm.tokenManager.GetOwner(tokenID)
	if err != nil {
		return err
	}
	if currentOwner != from {
		return errors.New("the from address does not own the token")
	}

	// Generate transfer ID
	transferID, err := generateTransferID()
	if err != nil {
		return err
	}

	// Create a new transfer
	transfer := OwnershipTransfer{
		TransferID:    transferID,
		TokenID:       tokenID,
		From:          from,
		To:            to,
		Timestamp:     time.Now(),
		TransactionID: "", // Generate or retrieve the transaction ID as needed
	}

	// Add transfer to the channel for processing
	otm.transferChannel <- transfer

	return nil
}

// verifyOwnershipTransfer verifies the ownership transfer
func (otm *OwnershipTransferManager) verifyOwnershipTransfer(transfer OwnershipTransfer) {
	// Here, you can add logic to verify the transfer, such as checking digital signatures or other validation methods
	// For now, we'll assume the transfer is valid
	otm.verificationChannel <- transfer
}

// recordTransfer records the ownership transfer in the ledger
func (otm *OwnershipTransferManager) recordTransfer(transfer OwnershipTransfer) error {
	return otm.ledgerManager.RecordTransfer(transfer.TransferID, transfer.TokenID, transfer.From, transfer.To, transfer.Timestamp)
}

// logEvent logs the ownership transfer event
func (otm *OwnershipTransferManager) logEvent(transfer OwnershipTransfer) {
	event := events.Event{
		Type:      "OwnershipTransfer",
		Timestamp: transfer.Timestamp,
		Data: map[string]interface{}{
			"transferID": transfer.TransferID,
			"tokenID":    transfer.TokenID,
			"from":       transfer.From,
			"to":         transfer.To,
		},
	}
	otm.eventLogger.LogEvent(event)
}
