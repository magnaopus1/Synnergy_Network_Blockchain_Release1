package management

import (
	"errors"
	"fmt"
	"sync"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/transactions"
)

// UserInterface manages interactions with users for SYN722 tokens.
type UserInterface struct {
	ledger           *ledger.Ledger
	transactionManager *transactions.TransactionManager
	metadataManager  *MetadataManager
	royaltyManager   *RoyaltyManager
	mu               sync.Mutex
}

// NewUserInterface creates a new instance of UserInterface.
func NewUserInterface(ledger *ledger.Ledger, transactionManager *transactions.TransactionManager, metadataManager *MetadataManager, royaltyManager *RoyaltyManager) *UserInterface {
	return &UserInterface{
		ledger:            ledger,
		transactionManager: transactionManager,
		metadataManager:   metadataManager,
		royaltyManager:    royaltyManager,
	}
}

// CreateToken creates a new SYN722 token.
func (ui *UserInterface) CreateToken(owner, mode string, quantity int, metadata map[string]string) (string, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	tokenID, err := ui.ledger.GenerateTokenID()
	if err != nil {
		return "", err
	}

	err = ui.ledger.AddToken(tokenID, owner, quantity)
	if err != nil {
		return "", err
	}

	err = ui.metadataManager.AddMetadata(tokenID, owner, mode, quantity, metadata)
	if err != nil {
		return "", err
	}

	return tokenID, nil
}

// TransferToken transfers a SYN722 token from one user to another.
func (ui *UserInterface) TransferToken(tokenID, from, to string, quantity int) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	token, err := ui.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Quantity < quantity {
		return errors.New("insufficient token quantity")
	}

	err = ui.ledger.UpdateToken(tokenID, to, token.Quantity-quantity)
	if err != nil {
		return err
	}

	return ui.transactionManager.CreateTransaction(tokenID, from, to, quantity)
}

// ViewTokenDetails provides a detailed view of a SYN722 token.
func (ui *UserInterface) ViewTokenDetails(tokenID string) (string, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	token, err := ui.ledger.GetToken(tokenID)
	if err != nil {
		return "", err
	}

	metadata, err := ui.metadataManager.GetMetadata(tokenID)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("Token ID: %s\nOwner: %s\nMode: %s\nQuantity: %d\nMetadata: %v\nHistory: %v",
		token.ID, token.Owner, token.Mode, token.Quantity, metadata.Attributes, token.History), nil
}

// SwitchMode switches the mode of a SYN722 token between fungible and non-fungible.
func (ui *UserInterface) SwitchMode(tokenID string) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	token, err := ui.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Mode == "fungible" {
		token.Mode = "non-fungible"
	} else if token.Mode == "non-fungible" {
		token.Mode = "fungible"
	} else {
		return errors.New("invalid mode")
	}

	return ui.ledger.UpdateToken(tokenID, token.Owner, token.Quantity)
}

// SetRoyalty sets the royalty details for a SYN722 token.
func (ui *UserInterface) SetRoyalty(tokenID, creator string, rate float64) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	return ui.royaltyManager.SetRoyalty(tokenID, creator, rate)
}

// RecordRoyaltyPayment records a royalty payment for a SYN722 token.
func (ui *UserInterface) RecordRoyaltyPayment(tokenID, payer string, amount float64) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	return ui.royaltyManager.RecordPayment(tokenID, payer, amount)
}

// AddMetadata adds metadata to a SYN722 token.
func (ui *UserInterface) AddMetadata(tokenID, owner, mode string, quantity int, attributes map[string]string) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	return ui.metadataManager.AddMetadata(tokenID, owner, mode, quantity, attributes)
}

// UpdateMetadata updates the metadata of a SYN722 token.
func (ui *UserInterface) UpdateMetadata(tokenID string, attributes map[string]string) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	return ui.metadataManager.UpdateMetadata(tokenID, attributes)
}

// EncryptMetadata encrypts the metadata of a SYN722 token.
func (ui *UserInterface) EncryptMetadata(tokenID, key string) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	return ui.metadataManager.EncryptMetadata(tokenID, key)
}

// DecryptMetadata decrypts the metadata of a SYN722 token.
func (ui *UserInterface) DecryptMetadata(tokenID, key string) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	return ui.metadataManager.DecryptMetadata(tokenID, key)
}

// LogMetadataChange logs changes to the metadata of a SYN722 token.
func (ui *UserInterface) LogMetadataChange(tokenID, action, details string) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	return ui.metadataManager.LogMetadataChange(tokenID, action, details)
}

// DisplayMetadata provides a JSON representation of the metadata for easy viewing.
func (ui *UserInterface) DisplayMetadata(tokenID string) (string, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	return ui.metadataManager.DisplayMetadata(tokenID)
}

// LogTokenEvent logs a significant event in the SYN722 token's history.
func (ui *UserInterface) LogTokenEvent(tokenID, action, details string) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	return ui.ledger.LogEvent(tokenID, action, details)
}
