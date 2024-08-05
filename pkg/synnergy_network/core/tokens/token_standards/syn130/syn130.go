package syn130

import (
	"time"
	"errors"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/transactions"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/utils"
)



// SYN130Manager manages SYN130 tokens.
type SYN130Manager struct {
	ledger   *ledger.TransactionLedger
	security *security.SecurityManager
}

// NewSYN130Manager initializes a new SYN130Manager.
func NewSYN130Manager(ledger *ledger.TransactionLedger, security *security.SecurityManager) *SYN130Manager {
	return &SYN130Manager{
		ledger:   ledger,
		security: security,
	}
}

// CreateToken creates a new SYN130 token.
func (sm *SYN130Manager) CreateToken(owner string, asset assets.Asset, metadata string, privateKey string) (*SYN130Token, error) {
	if owner == "" || asset.AssetID == "" {
		return nil, errors.New("invalid token details")
	}

	token := &SYN130Token{
		TokenID:      utils.GenerateUUID(),
		Owner:        owner,
		AssetDetails: asset,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Metadata:     metadata,
	}

	// Record creation transaction in the ledger
	transaction := &transactions.Transaction{
		ID:             utils.GenerateUUID(),
		TokenID:        token.TokenID,
		Type:           transactions.Create,
		Timestamp:      time.Now(),
	}

	// Sign and encrypt transaction
	transactionHash, err := utils.GenerateTransactionHash(transaction)
	if err != nil {
		return nil, err
	}

	signature, err := sm.security.SignData(transactionHash, privateKey)
	if err != nil {
		return nil, err
	}
	transaction.Signature = signature

	encryptedData, err := sm.security.EncryptData([]byte(utils.ToJSON(transaction)))
	if err != nil {
		return nil, err
	}
	transaction.EncryptedData = encryptedData

	err = sm.ledger.RecordTransaction(transaction.ID, "TokenCreation", transaction)
	if err != nil {
		return nil, err
	}

	token.TransactionHistory = append(token.TransactionHistory, *transaction)

	return token, nil
}

// TransferToken transfers ownership of a SYN130 token.
func (sm *SYN130Manager) TransferToken(tokenID string, newOwner string, privateKey string) (*SYN130Token, error) {
	token, err := sm.GetToken(tokenID)
	if err != nil {
		return nil, err
	}

	if token.Owner == newOwner {
		return nil, errors.New("new owner is the same as current owner")
	}

	// Record transfer transaction in the ledger
	transaction := &transactions.Transaction{
		ID:             utils.GenerateUUID(),
		TokenID:        tokenID,
		Type:           transactions.Transfer,
		Timestamp:      time.Now(),
	}

	transactionHash, err := utils.GenerateTransactionHash(transaction)
	if err != nil {
		return nil, err
	}

	signature, err := sm.security.SignData(transactionHash, privateKey)
	if err != nil {
		return nil, err
	}
	transaction.Signature = signature

	encryptedData, err := sm.security.EncryptData([]byte(utils.ToJSON(transaction)))
	if err != nil {
		return nil, err
	}
	transaction.EncryptedData = encryptedData

	err = sm.ledger.RecordTransaction(transaction.ID, "TokenTransfer", transaction)
	if err != nil {
		return nil, err
	}

	// Update token details
	token.Owner = newOwner
	token.UpdatedAt = time.Now()
	token.TransactionHistory = append(token.TransactionHistory, *transaction)

	return token, nil
}

// UpdateMetadata updates the metadata of a SYN130 token.
func (sm *SYN130Manager) UpdateMetadata(tokenID string, metadata string, privateKey string) (*SYN130Token, error) {
	token, err := sm.GetToken(tokenID)
	if err != nil {
		return nil, err
	}

	// Record metadata update transaction in the ledger
	transaction := &transactions.Transaction{
		ID:             utils.GenerateUUID(),
		TokenID:        tokenID,
		Type:           transactions.UpdateMetadata,
		Timestamp:      time.Now(),
	}

	transactionHash, err := utils.GenerateTransactionHash(transaction)
	if err != nil {
		return nil, err
	}

	signature, err := sm.security.SignData(transactionHash, privateKey)
	if err != nil {
		return nil, err
	}
	transaction.Signature = signature

	encryptedData, err := sm.security.EncryptData([]byte(utils.ToJSON(transaction)))
	if err != nil {
		return nil, err
	}
	transaction.EncryptedData = encryptedData

	err = sm.ledger.RecordTransaction(transaction.ID, "MetadataUpdate", transaction)
	if err != nil {
		return nil, err
	}

	// Update token details
	token.Metadata = metadata
	token.UpdatedAt = time.Now()
	token.TransactionHistory = append(token.TransactionHistory, *transaction)

	return token, nil
}

// GetToken retrieves a SYN130 token by its ID.
func (sm *SYN130Manager) GetToken(tokenID string) (*SYN130Token, error) {
	var token SYN130Token
	err := sm.ledger.GetTransaction(tokenID, &token)
	if err != nil {
		return nil, err
	}

	// Decrypt token data
	decryptedData, err := sm.security.DecryptData(token.AssetDetails.EncryptedData)
	if err != nil {
		return nil, err
	}
	err = utils.FromJSON(decryptedData, &token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

// GetTransactionHistory retrieves the transaction history of a SYN130 token.
func (sm *SYN130Manager) GetTransactionHistory(tokenID string) ([]transactions.Transaction, error) {
	token, err := sm.GetToken(tokenID)
	if err != nil {
		return nil, err
	}

	return token.TransactionHistory, nil
}
