package transactions

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn722/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/storage"
)

// EscrowService struct handles escrow transactions for SYN722 tokens
type EscrowService struct {
	ledger  *ledger.Ledger
	storage *storage.Storage
	mutex   sync.Mutex
}

// NewEscrowService initializes and returns a new EscrowService instance
func NewEscrowService(ledger *ledger.Ledger, storage *storage.Storage) *EscrowService {
	return &EscrowService{
		ledger:  ledger,
		storage: storage,
	}
}

// EscrowRequest struct defines the structure of an escrow request
type EscrowRequest struct {
	TokenID     string    `json:"token_id"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	Amount      uint64    `json:"amount"`
	ReleaseDate time.Time `json:"release_date"`
	Signature   string    `json:"signature"`
}

// ValidateEscrowRequest validates an escrow request
func (es *EscrowService) ValidateEscrowRequest(req EscrowRequest) error {
	// Verify signature
	if !security.VerifySignature(req.From, req.Signature, req.TokenID+req.To) {
		return errors.New("invalid signature")
	}

	// Check if the token exists
	token, err := es.ledger.GetToken(req.TokenID)
	if err != nil {
		return err
	}

	// Check if the 'from' address has enough balance
	if token.Balance[req.From] < req.Amount {
		return errors.New("insufficient balance")
	}

	return nil
}

// CreateEscrow creates an escrow transaction
func (es *EscrowService) CreateEscrow(req EscrowRequest) error {
	es.mutex.Lock()
	defer es.mutex.Unlock()

	if err := es.ValidateEscrowRequest(req); err != nil {
		return err
	}

	// Deduct the amount from the sender's balance
	token, err := es.ledger.GetToken(req.TokenID)
	if err != nil {
		return err
	}
	token.Balance[req.From] -= req.Amount

	// Store the escrow details in the storage
	escrowID := security.GenerateUUID()
	escrowDetails := map[string]interface{}{
		"token_id":     req.TokenID,
		"from":         req.From,
		"to":           req.To,
		"amount":       req.Amount,
		"release_date": req.ReleaseDate,
		"timestamp":    security.GetCurrentTimestamp(),
	}
	if err := es.storage.Put("escrow_"+escrowID, escrowDetails); err != nil {
		return err
	}

	return nil
}

// ReleaseEscrow releases the tokens held in escrow after the release date
func (es *EscrowService) ReleaseEscrow(escrowID string) error {
	es.mutex.Lock()
	defer es.mutex.Unlock()

	escrowDetails, err := es.storage.Get("escrow_" + escrowID)
	if err != nil {
		return err
	}

	// Parse the escrow details
	var details map[string]interface{}
	if err := json.Unmarshal([]byte(escrowDetails), &details); err != nil {
		return err
	}

	// Check if the release date has passed
	releaseDate, err := time.Parse(time.RFC3339, details["release_date"].(string))
	if err != nil {
		return err
	}
	if time.Now().Before(releaseDate) {
		return errors.New("release date not reached")
	}

	// Add the amount to the recipient's balance
	token, err := es.ledger.GetToken(details["token_id"].(string))
	if err != nil {
		return err
	}
	token.Balance[details["to"].(string)] += uint64(details["amount"].(float64))

	// Remove the escrow details from the storage
	if err := es.storage.Delete("escrow_" + escrowID); err != nil {
		return err
	}

	return nil
}

// CancelEscrow cancels the escrow and returns the tokens to the sender
func (es *EscrowService) CancelEscrow(escrowID string, sender string, signature string) error {
	es.mutex.Lock()
	defer es.mutex.Unlock()

	escrowDetails, err := es.storage.Get("escrow_" + escrowID)
	if err != nil {
		return err
	}

	// Parse the escrow details
	var details map[string]interface{}
	if err := json.Unmarshal([]byte(escrowDetails), &details); err != nil {
		return err
	}

	// Verify the signature of the sender
	if !security.VerifySignature(sender, signature, escrowID) {
		return errors.New("invalid signature")
	}

	// Check if the sender is the same as the 'from' address in the escrow details
	if details["from"].(string) != sender {
		return errors.New("unauthorized cancellation")
	}

	// Return the amount to the sender's balance
	token, err := es.ledger.GetToken(details["token_id"].(string))
	if err != nil {
		return err
	}
	token.Balance[details["from"].(string)] += uint64(details["amount"].(float64))

	// Remove the escrow details from the storage
	if err := es.storage.Delete("escrow_" + escrowID); err != nil {
		return err
	}

	return nil
}

// LogEscrow logs the details of an escrow transaction
func (es *EscrowService) LogEscrow(req EscrowRequest) error {
	logRecord := map[string]interface{}{
		"token_id":     req.TokenID,
		"from":         req.From,
		"to":           req.To,
		"amount":       req.Amount,
		"release_date": req.ReleaseDate,
		"timestamp":    security.GetCurrentTimestamp(),
	}

	return es.storage.Put("escrow_log_"+security.GenerateUUID(), logRecord)
}
