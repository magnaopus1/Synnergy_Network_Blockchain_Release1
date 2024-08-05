package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/security"
)

// License represents a license for SYN131 tokens.
type License struct {
	ID           string                `json:"id"`
	AssetID      string                `json:"asset_id"`
	Licensee     string                `json:"licensee"`
	Licensor     string                `json:"licensor"`
	Terms        string                `json:"terms"`
	EncryptedTerms string              `json:"encrypted_terms"`
	EncryptionKey string               `json:"encryption_key"`
	StartDate    time.Time             `json:"start_date"`
	EndDate      time.Time             `json:"end_date"`
	Status       string                `json:"status"`
	UsageMetrics assets.UsageMetrics   `json:"usage_metrics"`
}

// LicensingManagementService provides services for managing licenses.
type LicensingManagementService struct {
	ledger  *ledger.TransactionLedger
	storage *assets.AssetStorage
	security *security.SecurityService
}

// NewLicensingManagementService creates a new LicensingManagementService.
func NewLicensingManagementService(ledger *ledger.TransactionLedger, storage *assets.AssetStorage, security *security.SecurityService) *LicensingManagementService {
	return &LicensingManagementService{ledger: ledger, storage: storage, security: security}
}

// CreateLicense creates a new license.
func (service *LicensingManagementService) CreateLicense(assetID, licensee, licensor, terms string, startDate, endDate time.Time) (*License, error) {
	if startDate.After(endDate) {
		return nil, errors.New("start date must be before end date")
	}

	// Generate a unique ID for the license
	hash := sha256.New()
	hash.Write([]byte(assetID + licensee + licensor + time.Now().String()))
	id := hex.EncodeToString(hash.Sum(nil))

	// Encrypt the terms
	encryptionKey := service.security.GenerateEncryptionKey()
	encryptedTerms, err := service.security.EncryptData(terms, encryptionKey)
	if err != nil {
		return nil, err
	}

	// Create the license object
	license := &License{
		ID:           id,
		AssetID:      assetID,
		Licensee:     licensee,
		Licensor:     licensor,
		Terms:        terms,
		EncryptedTerms: encryptedTerms,
		EncryptionKey: encryptionKey,
		StartDate:    startDate,
		EndDate:      endDate,
		Status:       "active",
	}

	return license, nil
}

// RevokeLicense revokes an existing license.
func (service *LicensingManagementService) RevokeLicense(id string) error {
	license, err := service.GetLicense(id)
	if err != nil {
		return err
	}

	if license.Status != "active" {
		return errors.New("license is not active")
	}

	license.Status = "revoked"
	return nil
}

// GetLicense retrieves a license by ID.
func (service *LicensingManagementService) GetLicense(id string) (*License, error) {
	// This is a placeholder function and should be implemented to retrieve licenses from the storage.
	return nil, errors.New("not implemented")
}

// UpdateLicenseUsageMetrics updates the usage metrics for a license.
func (service *LicensingManagementService) UpdateLicenseUsageMetrics(id string, metrics assets.UsageMetrics) error {
	license, err := service.GetLicense(id)
	if err != nil {
		return err
	}

	license.UsageMetrics = metrics
	return nil
}

// ValidateLicense validates if a license is still active and meets the terms.
func (service *LicensingManagementService) ValidateLicense(id string) (bool, error) {
	license, err := service.GetLicense(id)
	if err != nil {
		return false, err
	}

	if license.Status != "active" || time.Now().After(license.EndDate) {
		return false, nil
	}

	return true, nil
}
