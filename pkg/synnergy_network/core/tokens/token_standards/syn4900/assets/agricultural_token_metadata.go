// Package assets provides the implementation for managing agricultural token metadata within the SYN4900 Token Standard.
package assets

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network/encryption"
	"github.com/synnergy_network/compliance"
	"github.com/synnergy_network/ledger"
)

// AgriculturalToken represents an agricultural asset in the form of a blockchain token.
type AgriculturalToken struct {
	TokenID         string    `json:"token_id"`
	AssetType       string    `json:"asset_type"`
	Quantity        float64   `json:"quantity"`
	Owner           string    `json:"owner"`
	Origin          string    `json:"origin"`
	HarvestDate     time.Time `json:"harvest_date"`
	ExpiryDate      time.Time `json:"expiry_date"`
	Status          string    `json:"status"`
	Certification   string    `json:"certification"`
	TransactionHistory []TransactionRecord `json:"transaction_history"`
}

// TransactionRecord keeps track of transactions involving an agricultural token.
type TransactionRecord struct {
	TransactionID string    `json:"transaction_id"`
	Timestamp     time.Time `json:"timestamp"`
	From          string    `json:"from"`
	To            string    `json:"to"`
	Quantity      float64   `json:"quantity"`
	Description   string    `json:"description"`
}

// CreateToken creates a new agricultural token with the specified details.
func CreateToken(tokenID, assetType, owner, origin, status, certification string, quantity float64, harvestDate, expiryDate time.Time) (*AgriculturalToken, error) {
	if tokenID == "" || assetType == "" || owner == "" {
		return nil, errors.New("missing required fields for creating a token")
	}
	
	return &AgriculturalToken{
		TokenID:        tokenID,
		AssetType:      assetType,
		Quantity:       quantity,
		Owner:          owner,
		Origin:         origin,
		HarvestDate:    harvestDate,
		ExpiryDate:     expiryDate,
		Status:         status,
		Certification:  certification,
	}, nil
}

// UpdateToken updates the attributes of an existing agricultural token.
func UpdateToken(token *AgriculturalToken, assetType, owner, status, certification string, quantity float64, expiryDate time.Time) error {
	if token == nil {
		return errors.New("token cannot be nil")
	}
	token.AssetType = assetType
	token.Owner = owner
	token.Quantity = quantity
	token.Status = status
	token.Certification = certification
	token.ExpiryDate = expiryDate
	return nil
}

// TransferOwnership transfers the ownership of an agricultural token to a new owner.
func TransferOwnership(token *AgriculturalToken, newOwner string, quantity float64, transactionDescription string) error {
	if token == nil || newOwner == "" || quantity <= 0 {
		return errors.New("invalid input for ownership transfer")
	}
	if token.Quantity < quantity {
		return errors.New("insufficient quantity for transfer")
	}

	// Update ownership
	oldOwner := token.Owner
	token.Owner = newOwner
	token.Quantity -= quantity

	// Record transaction
	transaction := TransactionRecord{
		TransactionID: ledger.GenerateTransactionID(),
		Timestamp:     time.Now(),
		From:          oldOwner,
		To:            newOwner,
		Quantity:      quantity,
		Description:   transactionDescription,
	}
	token.TransactionHistory = append(token.TransactionHistory, transaction)

	// Log in ledger
	ledger.LogTransaction(transaction)

	return nil
}

// VerifyOwnership checks if a given entity is the current owner of the token.
func VerifyOwnership(token *AgriculturalToken, owner string) bool {
	return token.Owner == owner
}

// EncryptTokenMetadata encrypts the metadata of an agricultural token.
func EncryptTokenMetadata(token *AgriculturalToken, passphrase string) (string, error) {
	data, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	encryptedData, err := encryption.EncryptData(data, passphrase)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptTokenMetadata decrypts the metadata of an agricultural token.
func DecryptTokenMetadata(encryptedData, passphrase string) (*AgriculturalToken, error) {
	decryptedData, err := encryption.DecryptData(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}
	var token AgriculturalToken
	err = json.Unmarshal(decryptedData, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// ValidateToken ensures that the token complies with relevant regulations.
func ValidateToken(token *AgriculturalToken) error {
	return compliance.ValidateToken(token.Certification)
}

// LogTokenCreation logs the creation of a new token in the system ledger.
func LogTokenCreation(token *AgriculturalToken) error {
	return ledger.LogTokenCreation(token)
}
