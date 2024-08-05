package factory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn900/assets"
)

// Syn900Factory is responsible for creating SYN900 tokens
type Syn900Factory struct {
	tokens map[string]*assets.Syn900Token
}

// NewSyn900Factory initializes a new Syn900Factory
func NewSyn900Factory() *Syn900Factory {
	return &Syn900Factory{
		tokens: make(map[string]*assets.Syn900Token),
	}
}

// CreateToken creates a new SYN900 token with the provided identity details
func (f *Syn900Factory) CreateToken(identityDetails assets.IdentityMetadata, owner string, drivingLicenseNumber, passportNumber, encryptionKey string) (*assets.Syn900Token, error) {
	tokenID := generateTokenID(identityDetails)
	drivingLicenseHash := hashData(drivingLicenseNumber)
	encryptedPassNumber, err := assets.EncryptData(passportNumber, encryptionKey)
	if err != nil {
		return nil, err
	}

	token := &assets.Syn900Token{
		TokenID:             tokenID,
		Owner:               owner,
		IdentityDetails:     identityDetails,
		VerificationLog:     []assets.VerificationRecord{},
		AuditTrail:          []assets.AuditRecord{},
		ComplianceRecords:   []assets.ComplianceRecord{},
		RegisteredWallets:   []assets.WalletAddress{},
		DrivingLicenseHash:  drivingLicenseHash,
		EncryptedPassNumber: encryptedPassNumber,
	}

	f.tokens[tokenID] = token
	return token, nil
}

// GetToken retrieves a token by its ID
func (f *Syn900Factory) GetToken(tokenID string) (*assets.Syn900Token, error) {
	token, exists := f.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}
	return token, nil
}

// UpdateToken updates the identity details of an existing token
func (f *Syn900Factory) UpdateToken(tokenID string, newDetails assets.IdentityMetadata) error {
	token, exists := f.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}
	token.IdentityDetails = newDetails
	return nil
}

// DeleteToken removes a token from the factory
func (f *Syn900Factory) DeleteToken(tokenID string) error {
	_, exists := f.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}
	delete(f.tokens, tokenID)
	return nil
}

// RegisterWalletAddress registers a new wallet address for a token
func (f *Syn900Factory) RegisterWalletAddress(tokenID, address, owner string) error {
	token, exists := f.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}
	token.AddWalletAddress(address, owner)
	return nil
}

// TransferToken transfers a token to multiple new owners
func (f *Syn900Factory) TransferToken(tokenID string, newOwners []string) ([]*assets.Syn900Token, error) {
	token, exists := f.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}
	newTokens := token.TransferToken(newOwners)
	for _, newToken := range newTokens {
		f.tokens[newToken.TokenID] = newToken
	}
	return newTokens, nil
}

// generateTokenID generates a unique token ID based on identity details
func generateTokenID(details assets.IdentityMetadata) string {
	hash := sha256.New()
	hash.Write([]byte(details.FullName + details.DateOfBirth + details.Nationality + details.PhysicalAddress))
	return hex.EncodeToString(hash.Sum(nil))
}

// hashData hashes data using SHA-256
func hashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// EventLogging logs events related to token creation, updates, and transfers
func (f *Syn900Factory) EventLogging(eventType, description, actor string) {
	eventLogger := assets.NewEventLogger()
	eventLogger.LogEvent(eventType, description, actor)
	// Additional code to save or handle the logged events can be added here
}

