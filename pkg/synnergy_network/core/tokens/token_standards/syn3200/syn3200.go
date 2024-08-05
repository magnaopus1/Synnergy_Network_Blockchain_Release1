package syn3200

import (
	"errors"
	"time"

	"github.com/you/yourproject/pkg/cryptography"
	"github.com/you/yourproject/pkg/synnergy_network/core/tokens/token_standards/syn3200/assets"
	"github.com/you/yourproject/pkg/synnergy_network/core/tokens/token_standards/syn3200/ledger"
	"github.com/you/yourproject/pkg/synnergy_network/core/tokens/token_standards/syn3200/transactions"
)

// SYN3200Token represents a bill token in the SYN3200 standard
type SYN3200Token struct {
	TokenID         string    `json:"token_id"`
	BillID          string    `json:"bill_id"`
	Issuer          string    `json:"issuer"`
	Payer           string    `json:"payer"`
	OriginalAmount  float64   `json:"original_amount"`
	RemainingAmount float64   `json:"remaining_amount"`
	DueDate         time.Time `json:"due_date"`
	PaidStatus      bool      `json:"paid_status"`
	Metadata        string    `json:"metadata"`
}

// TokenManager manages SYN3200 tokens
type TokenManager struct {
	ledgerManager       *ledger.LedgerManager
	billOwnershipVerif  *assets.BillOwnershipVerification
	transactionManager  *transactions.TransactionManager
}

// NewTokenManager initializes a new TokenManager
func NewTokenManager(ledgerManager *ledger.LedgerManager, billOwnershipVerif *assets.BillOwnershipVerification, transactionManager *transactions.TransactionManager) *TokenManager {
	return &TokenManager{
		ledgerManager:       ledgerManager,
		billOwnershipVerif:  billOwnershipVerif,
		transactionManager:  transactionManager,
	}
}

// CreateToken creates a new SYN3200 token
func (tm *TokenManager) CreateToken(token *SYN3200Token) error {
	if !tm.billOwnershipVerif.VerifyOwnership(token.BillID, token.Issuer) {
		return errors.New("ownership verification failed")
	}

	tokenID, err := generateTokenID(token)
	if err != nil {
		return err
	}
	token.TokenID = tokenID

	err = tm.ledgerManager.RecordToken(token)
	if err != nil {
		return err
	}

	return nil
}

// TransferToken transfers a SYN3200 token to a new owner
func (tm *TokenManager) TransferToken(tokenID, from, to string, amount float64) error {
	token, err := tm.ledgerManager.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Payer != from {
		return errors.New("transfer not authorized by current owner")
	}

	if token.RemainingAmount < amount {
		return errors.New("insufficient remaining amount for transfer")
	}

	transaction := &transactions.Transaction{
		BillID:   token.BillID,
		From:     from,
		To:       to,
		Amount:   amount,
		Status:   "pending",
	}

	err = tm.transactionManager.CreateTransaction(transaction)
	if err != nil {
		return err
	}

	token.Payer = to
	token.RemainingAmount -= amount
	if token.RemainingAmount == 0 {
		token.PaidStatus = true
	}

	err = tm.ledgerManager.UpdateToken(token)
	if err != nil {
		return err
	}

	err = tm.ledgerManager.UpdateTransactionStatus(transaction.TransactionID, "completed")
	if err != nil {
		return err
	}

	return nil
}

// AdjustAmount adjusts the remaining amount on a SYN3200 token
func (tm *TokenManager) AdjustAmount(tokenID string, newAmount float64) error {
	token, err := tm.ledgerManager.GetToken(tokenID)
	if err != nil {
		return err
	}

	if newAmount < 0 {
		return errors.New("new amount cannot be negative")
	}

	token.RemainingAmount = newAmount
	if token.RemainingAmount == 0 {
		token.PaidStatus = true
	} else {
		token.PaidStatus = false
	}

	err = tm.ledgerManager.UpdateToken(token)
	if err != nil {
		return err
	}

	return nil
}

// generateTokenID generates a unique token ID
func generateTokenID(token *SYN3200Token) (string, error) {
	data, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return string(hash[:]), nil
}

// validateToken ensures the token's integrity
func validateToken(token *SYN3200Token) error {
	if token.TokenID == "" || token.BillID == "" || token.Issuer == "" || token.Payer == "" {
		return errors.New("invalid token data")
	}
	return nil
}
