package currency_representation

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// CurrencyMetadata represents the comprehensive metadata for a currency token
type CurrencyMetadata struct {
	TokenID       string    `json:"token_id"`
	CurrencyCode  string    `json:"currency_code"`
	IssuerDetails Issuer    `json:"issuer_details"`
	ExchangeRate  float64   `json:"exchange_rate"`
	UpdateTime    time.Time `json:"update_time"`
}

// Issuer represents the details of the central banking node issuing the token
type Issuer struct {
	Name      string `json:"name"`
	Location  string `json:"location"`
	Contact   string `json:"contact"`
	Verified  bool   `json:"verified"`
	Timestamp time.Time `json:"timestamp"`
}

// CurrencyManager manages the metadata for currency tokens
type CurrencyManager struct {
	metadataStore map[string]CurrencyMetadata
}

// NewCurrencyManager initializes a new CurrencyManager
func NewCurrencyManager() *CurrencyManager {
	return &CurrencyManager{metadataStore: make(map[string]CurrencyMetadata)}
}

// CreateCurrencyToken generates a new currency token with the given details
func (cm *CurrencyManager) CreateCurrencyToken(currencyCode string, issuer Issuer) (CurrencyMetadata, error) {
	tokenID, err := generateTokenID()
	if err != nil {
		return CurrencyMetadata{}, err
	}

	metadata := CurrencyMetadata{
		TokenID:       tokenID,
		CurrencyCode:  currencyCode,
		IssuerDetails: issuer,
		ExchangeRate:  1.0, // Initial exchange rate set to 1.0
		UpdateTime:    time.Now(),
	}

	cm.metadataStore[tokenID] = metadata
	return metadata, nil
}

// UpdateExchangeRate updates the exchange rate of the currency token
func (cm *CurrencyManager) UpdateExchangeRate(tokenID string, newRate float64) error {
	metadata, exists := cm.metadataStore[tokenID]
	if !exists {
		return errors.New("token ID not found")
	}

	metadata.ExchangeRate = newRate
	metadata.UpdateTime = time.Now()
	cm.metadataStore[tokenID] = metadata
	return nil
}

// GetCurrencyMetadata retrieves the metadata of a currency token
func (cm *CurrencyManager) GetCurrencyMetadata(tokenID string) (CurrencyMetadata, error) {
	metadata, exists := cm.metadataStore[tokenID]
	if !exists {
		return CurrencyMetadata{}, errors.New("token ID not found")
	}
	return metadata, nil
}

// VerifyIssuer marks the issuer as verified
func (cm *CurrencyManager) VerifyIssuer(tokenID string) error {
	metadata, exists := cm.metadataStore[tokenID]
	if !exists {
		return errors.New("token ID not found")
	}

	metadata.IssuerDetails.Verified = true
	cm.metadataStore[tokenID] = metadata
	return nil
}

// generateTokenID generates a unique token ID using secure random bytes
func generateTokenID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
