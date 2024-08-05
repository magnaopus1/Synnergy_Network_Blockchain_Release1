package factory

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/transactions"
)

// TokenFactory is responsible for creating and managing SYN722 tokens.
type TokenFactory struct {
	TokenLedger *ledger.Ledger
}

// NewTokenFactory creates a new instance of TokenFactory.
func NewTokenFactory() *TokenFactory {
	return &TokenFactory{
		TokenLedger: ledger.NewLedger(),
	}
}

// CreateToken creates a new SYN722 token with the given parameters.
func (tf *TokenFactory) CreateToken(owner string, mode string, quantity int, metadata map[string]string) (*assets.Metadata, error) {
	if mode != "fungible" && mode != "non-fungible" {
		return nil, errors.New("invalid mode")
	}

	tokenID := fmt.Sprintf("token-%d", time.Now().UnixNano())
	tokenMetadata := assets.NewMetadata(tokenID, owner, mode, quantity, metadata)

	if err := tokenMetadata.ValidateMetadata(); err != nil {
		return nil, err
	}

	tf.TokenLedger.AddToken(tokenID, owner, quantity)
	return tokenMetadata, nil
}

// MintTokens mints new tokens for the given tokenID.
func (tf *TokenFactory) MintTokens(tokenID string, quantity int) error {
	token, err := tf.TokenLedger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Mode != "fungible" {
		return errors.New("only fungible tokens can be minted")
	}

	token.Quantity += quantity
	tf.TokenLedger.UpdateToken(tokenID, token.Owner, token.Quantity)
	return nil
}

// BurnTokens burns the given quantity of tokens for the given tokenID.
func (tf *TokenFactory) BurnTokens(tokenID string, quantity int) error {
	token, err := tf.TokenLedger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Quantity < quantity {
		return errors.New("insufficient token quantity")
	}

	token.Quantity -= quantity
	tf.TokenLedger.UpdateToken(tokenID, token.Owner, token.Quantity)
	return nil
}

// TransferToken transfers the given quantity of tokens from one owner to another.
func (tf *TokenFactory) TransferToken(tokenID, from, to string, quantity int) error {
	token, err := tf.TokenLedger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Quantity < quantity {
		return errors.New("insufficient token quantity")
	}

	if token.Mode == "non-fungible" && token.Owner != from {
		return errors.New("only the owner can transfer non-fungible tokens")
	}

	tf.TokenLedger.UpdateToken(tokenID, from, token.Quantity-quantity)
	tf.TokenLedger.UpdateToken(tokenID, to, token.Quantity+quantity)

	return nil
}

// SwitchMode switches the mode of the token between fungible and non-fungible.
func (tf *TokenFactory) SwitchMode(tokenID string) error {
	token, err := tf.TokenLedger.GetToken(tokenID)
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

	tf.TokenLedger.UpdateToken(tokenID, token.Owner, token.Quantity)
	return nil
}

// GenerateTokenID generates a unique token ID using a secure method.
func (tf *TokenFactory) GenerateTokenID() (string, error) {
	randomBytes, err := security.GenerateSecureRandomBytes(16)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("token-%x", randomBytes), nil
}

// DisplayTokenDetails provides a JSON representation of the token details for easy viewing.
func (tf *TokenFactory) DisplayTokenDetails(tokenID string) (string, error) {
	token, err := tf.TokenLedger.GetToken(tokenID)
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ValidateToken ensures that the token details follow the SYN722 standard.
func (tf *TokenFactory) ValidateToken(tokenID string) error {
	token, err := tf.TokenLedger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.ID == "" || token.Owner == "" || token.Mode == "" {
		return errors.New("token details missing required fields")
	}

	if token.Mode != "fungible" && token.Mode != "non-fungible" {
		return errors.New("invalid mode")
	}

	if token.Quantity < 0 {
		return errors.New("quantity cannot be negative")
	}

	return nil
}

// LogTokenEvent logs a significant event in the token's history.
func (tf *TokenFactory) LogTokenEvent(tokenID, action, details string) {
	token, err := tf.TokenLedger.GetToken(tokenID)
	if err != nil {
		return
	}

	entry := assets.AssetHistoryEntry{
		Timestamp: time.Now(),
		Action:    action,
		Details:   details,
	}
	token.History = append(token.History, entry)
	tf.TokenLedger.UpdateToken(tokenID, token.Owner, token.Quantity)
}
