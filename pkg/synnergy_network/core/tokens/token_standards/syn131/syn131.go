package syn131

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/contracts"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/transactions"
)

// Syn131Token represents a comprehensive smart contract for SYN131 token standard
type Syn131Token struct {
	ID                             string                      `json:"id"`
	Name                           string                      `json:"name"`
	Owner                          string                      `json:"owner"`
	IntangibleAssetID              string                      `json:"asset_id"`
	ContractType                   string                      `json:"contract_type"`
	Terms                          string                      `json:"terms"`
	EncryptedTerms                 string                      `json:"encrypted_terms"`
	EncryptionKey                  string                      `json:"encryption_key"`
	Status                         string                      `json:"status"`
	IntangibleAssetCategory        string                      `json:"asset_category"`
	IntangibleAssetClassification  string                      `json:"asset_classification"`
	IntangibleAssetMetadata        assets.AssetMetadata        `json:"asset_metadata"`
	PeggedTangibleAsset            assets.PeggedAsset          `json:"pegged_asset"`
	TrackedTangibleAsset           assets.TrackedAsset         `json:"tracked_asset"`
	IntangibleAssetStatus          assets.AssetStatus          `json:"asset_status"`
	IntangibleAssetValuation       assets.AssetValuation       `json:"asset_valuation"`
	IoTDevice                      assets.IoTDevice            `json:"iot_device"`
	LeaseAgreement                 contracts.LeaseAgreement    `json:"lease_agreement"`
	CoOwnershipAgreements          []contracts.CoOwnershipAgreement `json:"co_ownership_agreements"`
	LicenseAgreement               contracts.LicenseAgreement  `json:"license_agreement"`
	RentalAgreement                contracts.RentalAgreement   `json:"rental_agreement"`
	CreatedAt                      time.Time                   `json:"created_at"`
	UpdatedAt                      time.Time                   `json:"updated_at"`
}

// NewSyn131Token creates a new SYN131 token
func NewSyn131Token(id, name, owner, assetID, contractType, terms, encryptionKey, assetCategory, assetClassification string, metadata assets.AssetMetadata, peggedAsset assets.PeggedAsset, trackedAsset assets.TrackedAsset, assetStatus assets.AssetStatus, assetValuation assets.AssetValuation, iotDevice assets.IoTDevice, leaseAgreement contracts.LeaseAgreement, coOwnershipAgreements []contracts.CoOwnershipAgreement, licenseAgreement contracts.LicenseAgreement, rentalAgreement contracts.RentalAgreement) (*Syn131Token, error) {
	encryptedTerms, err := security.Encrypt(terms, encryptionKey)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	return &Syn131Token{
		ID:                            id,
		Name:                          name,
		Owner:                         owner,
		IntangibleAssetID:             assetID,
		ContractType:                  contractType,
		Terms:                         terms,
		EncryptedTerms:                encryptedTerms,
		EncryptionKey:                 encryptionKey,
		Status:                        "active",
		IntangibleAssetCategory:       assetCategory,
		IntangibleAssetClassification: assetClassification,
		IntangibleAssetMetadata:       metadata,
		PeggedTangibleAsset:           peggedAsset,
		TrackedTangibleAsset:          trackedAsset,
		IntangibleAssetStatus:         assetStatus,
		IntangibleAssetValuation:      assetValuation,
		IoTDevice:                     iotDevice,
		LeaseAgreement:                leaseAgreement,
		CoOwnershipAgreements:         coOwnershipAgreements,
		LicenseAgreement:              licenseAgreement,
		RentalAgreement:               rentalAgreement,
		CreatedAt:                     now,
		UpdatedAt:                     now,
	}, nil
}

// TransferOwnership transfers ownership of the token to a new owner
func (t *Syn131Token) TransferOwnership(newOwner string) error {
	if newOwner == "" {
		return errors.New("new owner address cannot be empty")
	}

	t.Owner = newOwner
	t.Status = "ownership transferred"
	t.UpdatedAt = time.Now()
	return nil
}

// UpdateStatus updates the status of the token
func (t *Syn131Token) UpdateStatus(newStatus string) {
	t.Status = newStatus
	t.UpdatedAt = time.Now()
}

// AddCoOwnershipAgreement adds a new co-ownership agreement to the token
func (t *Syn131Token) AddCoOwnershipAgreement(agreement contracts.CoOwnershipAgreement) {
	t.CoOwnershipAgreements = append(t.CoOwnershipAgreements, agreement)
	t.UpdatedAt = time.Now()
}

// UpdateLeaseAgreement updates the lease agreement of the token
func (t *Syn131Token) UpdateLeaseAgreement(newLease contracts.LeaseAgreement) {
	t.LeaseAgreement = newLease
	t.UpdatedAt = time.Now()
}

// UpdateLicenseAgreement updates the license agreement of the token
func (t *Syn131Token) UpdateLicenseAgreement(newLicense contracts.LicenseAgreement) {
	t.LicenseAgreement = newLicense
	t.UpdatedAt = time.Now()
}

// UpdateRentalAgreement updates the rental agreement of the token
func (t *Syn131Token) UpdateRentalAgreement(newRental contracts.RentalAgreement) {
	t.RentalAgreement = newRental
	t.UpdatedAt = time.Now()
}

// ValidateToken ensures the token's integrity and validity
func (t *Syn131Token) ValidateToken() error {
	// Validate ownership
	if t.Owner == "" {
		return errors.New("owner information is missing")
	}

	// Validate asset metadata
	if err := t.IntangibleAssetMetadata.Validate(); err != nil {
		return fmt.Errorf("invalid asset metadata: %v", err)
	}

	// Validate terms encryption
	decryptedTerms, err := security.Decrypt(t.EncryptedTerms, t.EncryptionKey)
	if err != nil || decryptedTerms != t.Terms {
		return errors.New("terms encryption validation failed")
	}

	// Additional custom validations can be added here

	return nil
}

// ToJSON serializes the token to JSON
func (t *Syn131Token) ToJSON() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes the token from JSON
func (t *Syn131Token) FromJSON(data string) error {
	return json.Unmarshal([]byte(data), t)
}

// RecordTransaction records a transaction in the ledger
func (t *Syn131Token) RecordTransaction(transactionLedger *ledger.TransactionLedger, txn *transactions.Transaction) error {
	return transactionLedger.AddTransaction(txn)
}

// GetTransactionHistory retrieves the transaction history from the ledger
func (t *Syn131Token) GetTransactionHistory(transactionLedger *ledger.TransactionLedger) ([]*transactions.Transaction, error) {
	return transactionLedger.GetTransactionsByAssetID(t.IntangibleAssetID)
}

// GetCurrentValuation retrieves the current valuation of the asset
func (t *Syn131Token) GetCurrentValuation() (assets.AssetValuation, error) {
	return t.IntangibleAssetValuation, nil
}

// UpdateValuation updates the valuation of the asset
func (t *Syn131Token) UpdateValuation(newValuation assets.AssetValuation) {
	t.IntangibleAssetValuation = newValuation
	t.UpdatedAt = time.Now()
}


