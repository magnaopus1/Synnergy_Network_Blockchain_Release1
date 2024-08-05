package transactions

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/storage"
)

// OwnershipTransfer represents the mechanism for transferring ownership of SYN1967 tokens.
type OwnershipTransfer struct {
	TokenID          string
	FromAddress      string
	ToAddress        string
	TransferAmount   float64
	TransferTime     time.Time
	Signature        string
}

// NewOwnershipTransfer creates a new ownership transfer.
func NewOwnershipTransfer(tokenID, fromAddress, toAddress string, transferAmount float64, signature string) (*OwnershipTransfer, error) {
	if fromAddress == "" || toAddress == "" {
		return nil, errors.New("addresses cannot be empty")
	}
	if transferAmount <= 0 {
		return nil, errors.New("transfer amount must be positive")
	}
	return &OwnershipTransfer{
		TokenID:        tokenID,
		FromAddress:    fromAddress,
		ToAddress:      toAddress,
		TransferAmount: transferAmount,
		TransferTime:   time.Now(),
		Signature:      signature,
	}, nil
}

// ValidateTransfer validates the ownership transfer.
func (ot *OwnershipTransfer) ValidateTransfer() error {
	// Validate the signature
	if !security.ValidateSignature(ot.FromAddress, ot.Signature) {
		return errors.New("invalid signature")
	}

	// Validate the token existence
	token, err := storage.GetTokenByID(ot.TokenID)
	if err != nil {
		return errors.New("token not found")
	}

	// Validate the ownership and amount
	if token.Owner != ot.FromAddress || token.Amount < ot.TransferAmount {
		return errors.New("insufficient balance or invalid owner")
	}

	return nil
}

// ExecuteTransfer executes the ownership transfer.
func (ot *OwnershipTransfer) ExecuteTransfer() error {
	if err := ot.ValidateTransfer(); err != nil {
		return err
	}

	// Update token ownership and amount
	token, err := storage.GetTokenByID(ot.TokenID)
	if err != nil {
		return err
	}
	token.Amount -= ot.TransferAmount
	if token.Amount == 0 {
		token.Owner = ot.ToAddress
	}

	// Create new token for the receiver if necessary
	newToken, err := storage.CreateNewToken(token.CommodityID, ot.ToAddress, ot.TransferAmount)
	if err != nil {
		return err
	}

	// Update storage
	err = storage.UpdateToken(token)
	if err != nil {
		return err
	}

	err = storage.SaveToken(newToken)
	if err != nil {
		return err
	}

	// Log the transfer
	transferLog := ledger.TransferLog{
		TokenID:        ot.TokenID,
		FromAddress:    ot.FromAddress,
		ToAddress:      ot.ToAddress,
		TransferAmount: ot.TransferAmount,
		TransferTime:   ot.TransferTime,
	}
	err = ledger.LogTransfer(transferLog)
	if err != nil {
		return err
	}

	return nil
}

// GenerateSignature generates a signature for the transfer.
func GenerateSignature(privateKey string, data []byte) (string, error) {
	hash := sha256.New()
	hash.Write(data)
	hashed := hash.Sum(nil)

	signature, err := security.SignData(privateKey, hashed)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(signature), nil
}

// Example usage of ownership transfer.
func ExampleOwnershipTransfer() {
	privateKey := "user_private_key"
	fromAddress := "user1"
	toAddress := "user2"
	tokenID := "token123"
	transferAmount := 50.0

	data := []byte(fromAddress + toAddress + tokenID)
	signature, _ := GenerateSignature(privateKey, data)
	transfer, _ := NewOwnershipTransfer(tokenID, fromAddress, toAddress, transferAmount, signature)
	err := transfer.ExecuteTransfer()
	if err != nil {
		fmt.Printf("Transfer failed: %s\n", err)
	} else {
		fmt.Println("Transfer successful")
	}
}
