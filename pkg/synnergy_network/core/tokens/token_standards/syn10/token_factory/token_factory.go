package token_factory

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/synnergy_network/syn10/compliance"
	"github.com/synnergy_network/syn10/currency_representation"
	"github.com/synnergy_network/syn10/ledger"
	"github.com/synnergy_network/syn10/security"
)

// TokenFactory is responsible for the creation, management, and regulation of SYN10 tokens.
type TokenFactory struct {
	issuer        currency_representation.IssuerDetails
	encryptionKey []byte
	tokenLedger   *ledger.TokenLedger
	kycAMLService *compliance.KYCAmlService
}

// NewTokenFactory initializes a new TokenFactory instance with issuer details, encryption key, and associated services.
func NewTokenFactory(issuer currency_representation.IssuerDetails, encryptionKey []byte) *TokenFactory {
	return &TokenFactory{
		issuer:        issuer,
		encryptionKey: encryptionKey,
		tokenLedger:   ledger.NewTokenLedger(),
		kycAMLService: compliance.NewKYCAmlService(),
	}
}

// CreateToken generates a new SYN10 token with given metadata and initial supply.
func (tf *TokenFactory) CreateToken(metadata currency_representation.CurrencyMetadata, initialSupply uint64) (string, error) {
	if err := tf.validateMetadata(metadata); err != nil {
		return "", err
	}

	tokenID := tf.generateTokenID(metadata.CurrencyCode)
	encryptedTokenID, err := tf.encryptData([]byte(tokenID))
	if err != nil {
		return "", err
	}

	token := ledger.Token{
		TokenID:     tokenID,
		Issuer:      tf.issuer,
		Metadata:    metadata,
		TotalSupply: initialSupply,
	}

	if err := tf.tokenLedger.AddToken(token); err != nil {
		return "", err
	}

	return string(encryptedTokenID), nil
}

// validateMetadata ensures that the token metadata complies with required standards and regulations.
func (tf *TokenFactory) validateMetadata(metadata currency_representation.CurrencyMetadata) error {
	if metadata.CurrencyCode == "" || !metadata.IsISO4217Compliant() {
		return errors.New("invalid currency code")
	}
	if err := tf.kycAMLService.VerifyIssuer(tf.issuer); err != nil {
		return fmt.Errorf("issuer verification failed: %v", err)
	}
	return nil
}

// generateTokenID creates a unique identifier for a token based on the currency code and timestamp.
func (tf *TokenFactory) generateTokenID(currencyCode string) string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("%s-%d", currencyCode, timestamp)
}

// encryptData uses AES-GCM to encrypt data with the factory's encryption key.
func (tf *TokenFactory) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(tf.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// MintTokens increases the total supply of an existing token and updates the ledger.
func (tf *TokenFactory) MintTokens(tokenID string, amount uint64) error {
	if !tf.tokenLedger.TokenExists(tokenID) {
		return errors.New("token not found")
	}
	return tf.tokenLedger.IncreaseSupply(tokenID, amount)
}

// BurnTokens decreases the total supply of an existing token and updates the ledger.
func (tf *TokenFactory) BurnTokens(tokenID string, amount uint64) error {
	if !tf.tokenLedger.TokenExists(tokenID) {
		return errors.New("token not found")
	}
	return tf.tokenLedger.DecreaseSupply(tokenID, amount)
}

// SetExchangeRate sets the exchange rate for a token based on real-time market data.
func (tf *TokenFactory) SetExchangeRate(tokenID string, rate float64) error {
	if !tf.tokenLedger.TokenExists(tokenID) {
		return errors.New("token not found")
	}
	return tf.tokenLedger.UpdateExchangeRate(tokenID, rate)
}

// GetTokenDetails retrieves the details of a token by its ID.
func (tf *TokenFactory) GetTokenDetails(tokenID string) (*ledger.Token, error) {
	return tf.tokenLedger.GetToken(tokenID)
}

// ListAllTokens lists all tokens currently managed by the factory.
func (tf *TokenFactory) ListAllTokens() ([]ledger.Token, error) {
	return tf.tokenLedger.ListTokens()
}

// EnforceCompliance runs compliance checks on a token based on current regulations.
func (tf *TokenFactory) EnforceCompliance(tokenID string) error {
	token, err := tf.tokenLedger.GetToken(tokenID)
	if err != nil {
		return err
	}
	return tf.kycAMLService.EnforceCompliance(token)
}

// UpdateMetadata updates the metadata of a token.
func (tf *TokenFactory) UpdateMetadata(tokenID string, metadata currency_representation.CurrencyMetadata) error {
	return tf.tokenLedger.UpdateMetadata(tokenID, metadata)
}

// RemoveToken removes a token from the ledger, typically used when a token is deprecated or replaced.
func (tf *TokenFactory) RemoveToken(tokenID string) error {
	return tf.tokenLedger.RemoveToken(tokenID)
}
