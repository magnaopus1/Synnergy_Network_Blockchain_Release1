package transactions

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn722/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/storage"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/events"
)

// OwnershipTransferService struct handles ownership transfer transactions for SYN722 tokens
type OwnershipTransferService struct {
	ledger  *ledger.Ledger
	storage *storage.Storage
	mutex   sync.Mutex
}

// NewOwnershipTransferService initializes and returns a new OwnershipTransferService instance
func NewOwnershipTransferService(ledger *ledger.Ledger, storage *storage.Storage) *OwnershipTransferService {
	return &OwnershipTransferService{
		ledger:  ledger,
		storage: storage,
	}
}

// TransferRequest struct defines the structure of an ownership transfer request
type TransferRequest struct {
	TokenID   string `json:"token_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Amount    uint64 `json:"amount"`
	Signature string `json:"signature"`
}

// ValidateTransferRequest validates an ownership transfer request
func (ots *OwnershipTransferService) ValidateTransferRequest(req TransferRequest) error {
	// Verify signature
	if !security.VerifySignature(req.From, req.Signature, req.TokenID+req.To) {
		return errors.New("invalid signature")
	}

	// Check if the token exists
	token, err := ots.ledger.GetToken(req.TokenID)
	if err != nil {
		return err
	}

	// Check if the 'from' address has enough balance
	if token.Balance[req.From] < req.Amount {
		return errors.New("insufficient balance")
	}

	return nil
}

// TransferOwnership transfers ownership of tokens
func (ots *OwnershipTransferService) TransferOwnership(req TransferRequest) error {
	ots.mutex.Lock()
	defer ots.mutex.Unlock()

	if err := ots.ValidateTransferRequest(req); err != nil {
		return err
	}

	// Deduct the amount from the sender's balance
	token, err := ots.ledger.GetToken(req.TokenID)
	if err != nil {
		return err
	}
	token.Balance[req.From] -= req.Amount

	// Add the amount to the recipient's balance
	if _, exists := token.Balance[req.To]; !exists {
		token.Balance[req.To] = 0
	}
	token.Balance[req.To] += req.Amount

	// Update the ownership record
	ownershipRecord := map[string]interface{}{
		"token_id":  req.TokenID,
		"from":      req.From,
		"to":        req.To,
		"amount":    req.Amount,
		"timestamp": security.GetCurrentTimestamp(),
	}
	if err := ots.storage.Put("ownership_transfer_"+security.GenerateUUID(), ownershipRecord); err != nil {
		return err
	}

	// Log the transfer event
	event := events.Event{
		Type:      "ownership_transfer",
		Timestamp: security.GetCurrentTimestamp(),
		Details:   ownershipRecord,
	}
	events.LogEvent(event)

	return nil
}

// LogOwnershipTransfer logs the details of an ownership transfer transaction
func (ots *OwnershipTransferService) LogOwnershipTransfer(req TransferRequest) error {
	logRecord := map[string]interface{}{
		"token_id":  req.TokenID,
		"from":      req.From,
		"to":        req.To,
		"amount":    req.Amount,
		"timestamp": security.GetCurrentTimestamp(),
	}

	return ots.storage.Put("ownership_transfer_log_"+security.GenerateUUID(), logRecord)
}

// OwnershipHistory returns the history of ownership transfers for a token
func (ots *OwnershipTransferService) OwnershipHistory(tokenID string) ([]map[string]interface{}, error) {
	ots.mutex.Lock()
	defer ots.mutex.Unlock()

	records, err := ots.storage.GetAll("ownership_transfer_" + tokenID)
	if err != nil {
		return nil, err
	}

	var history []map[string]interface{}
	for _, record := range records {
		var details map[string]interface{}
		if err := json.Unmarshal([]byte(record), &details); err != nil {
			return nil, err
		}
		history = append(history, details)
	}

	return history, nil
}
