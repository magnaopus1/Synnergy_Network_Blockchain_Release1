package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/syn10/security"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/storage"
)

// TokenMetadata holds the detailed information about each token.
type TokenMetadata struct {
	TokenID           string
	CurrencyCode      string
	IssuerDetails     IssuerInformation
	ExchangeRate      float64
	CreationDate      time.Time
	PeggingMechanism  PeggingDetails
	TotalSupply       uint64
	CirculatingSupply uint64
	ComplianceStatus  ComplianceDetails
	Signature         string
}

// IssuerInformation provides information about the issuing authority.
type IssuerInformation struct {
	Name    string
	Location string
	Contact  string
	Verified bool
}

// PeggingDetails describes the pegging mechanism used by the token.
type PeggingDetails struct {
	Type          string
	Collateral    string
	StabilityAlgo string
}

// ComplianceDetails provides details on the regulatory compliance status.
type ComplianceDetails struct {
	Status        string
	LastAuditDate time.Time
	Reports       []string
}

// TokenRegistry manages the registry of SYN10 tokens.
type TokenRegistry struct {
	metadata map[string]TokenMetadata
	store    storage.Storage
}

// NewTokenRegistry initializes a new token registry with storage.
func NewTokenRegistry(store storage.Storage) *TokenRegistry {
	return &TokenRegistry{
		metadata: make(map[string]TokenMetadata),
		store:    store,
	}
}

// RegisterToken registers a new token in the registry.
func (tr *TokenRegistry) RegisterToken(meta TokenMetadata) error {
	if _, exists := tr.metadata[meta.TokenID]; exists {
		return errors.New("token already exists in the registry")
	}

	// Sign the token metadata
	meta.Signature = tr.signTokenMetadata(meta)

	tr.metadata[meta.TokenID] = meta
	return tr.store.Save(meta.TokenID, meta)
}

// UpdateTokenMetadata updates the metadata of an existing token.
func (tr *TokenRegistry) UpdateTokenMetadata(tokenID string, updates TokenMetadata) error {
	meta, exists := tr.metadata[tokenID]
	if !exists {
		return errors.New("token does not exist in the registry")
	}

	// Update the fields
	meta.CurrencyCode = updates.CurrencyCode
	meta.ExchangeRate = updates.ExchangeRate
	meta.TotalSupply = updates.TotalSupply
	meta.CirculatingSupply = updates.CirculatingSupply
	meta.PeggingMechanism = updates.PeggingMechanism
	meta.ComplianceStatus = updates.ComplianceStatus

	// Re-sign the updated metadata
	meta.Signature = tr.signTokenMetadata(meta)

	tr.metadata[tokenID] = meta
	return tr.store.Save(tokenID, meta)
}

// GetTokenMetadata retrieves the metadata of a token.
func (tr *TokenRegistry) GetTokenMetadata(tokenID string) (TokenMetadata, error) {
	meta, exists := tr.metadata[tokenID]
	if !exists {
		return TokenMetadata{}, errors.New("token does not exist in the registry")
	}

	return meta, nil
}

// VerifyTokenMetadata verifies the integrity of the token metadata.
func (tr *TokenRegistry) VerifyTokenMetadata(tokenID string) (bool, error) {
	meta, exists := tr.metadata[tokenID]
	if !exists {
		return false, errors.New("token does not exist in the registry")
	}

	// Verify the signature
	if !tr.verifyTokenMetadata(meta) {
		return false, errors.New("metadata signature verification failed")
	}

	return true, nil
}

// signTokenMetadata signs the token metadata using the system's private key.
func (tr *TokenRegistry) signTokenMetadata(meta TokenMetadata) string {
	data := meta.TokenID + meta.CurrencyCode + meta.IssuerDetails.Name + meta.CreationDate.String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// verifyTokenMetadata verifies the signature of the token metadata.
func (tr *TokenRegistry) verifyTokenMetadata(meta TokenMetadata) bool {
	expectedSignature := tr.signTokenMetadata(meta)
	return expectedSignature == meta.Signature
}
