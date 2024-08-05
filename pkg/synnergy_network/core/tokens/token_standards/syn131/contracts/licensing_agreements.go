package contracts

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/smart_contracts"
)

// LicensingAgreement represents a smart contract for licensing an asset.
type LicensingAgreement struct {
	AssetID        string
	Licensor       string
	Licensee       string
	LicenseTerms   string
	StartDate      time.Time
	EndDate        time.Time
	UsageMetrics   map[string]float64 // Track usage metrics such as views, downloads, etc.
	PaymentSchedule []Payment
}

// Payment represents a scheduled payment in the licensing agreement.
type Payment struct {
	DueDate  time.Time
	Amount   float64
	Paid     bool
	PaidDate time.Time
}

// LicensingManager handles the creation and management of licensing agreements.
type LicensingManager struct {
	Agreements map[string]*LicensingAgreement
	Ledger     *ledger.LedgerManager
	Assets     *assets.OwnershipManager
}

// NewLicensingManager initializes a new LicensingManager.
func NewLicensingManager(ledger *ledger.LedgerManager, assets *assets.OwnershipManager) *LicensingManager {
	return &LicensingManager{
		Agreements: make(map[string]*LicensingAgreement),
		Ledger:     ledger,
		Assets:     assets,
	}
}

// CreateLicensingAgreement creates a new licensing agreement.
func (lm *LicensingManager) CreateLicensingAgreement(assetID, licensor, licensee, licenseTerms string, startDate, endDate time.Time, paymentSchedule []Payment) (*LicensingAgreement, error) {
	if _, exists := lm.Agreements[assetID]; exists {
		return nil, fmt.Errorf("licensing agreement for asset ID %s already exists", assetID)
	}

	agreement := &LicensingAgreement{
		AssetID:        assetID,
		Licensor:       licensor,
		Licensee:       licensee,
		LicenseTerms:   licenseTerms,
		StartDate:      startDate,
		EndDate:        endDate,
		UsageMetrics:   make(map[string]float64),
		PaymentSchedule: paymentSchedule,
	}

	lm.Agreements[assetID] = agreement

	// Record the creation of the licensing agreement in the ledger
	if err := lm.Ledger.RecordLicensingCreation(agreement); err != nil {
		return nil, err
	}

	return agreement, nil
}

// RecordPayment records a payment for a licensing agreement.
func (lm *LicensingManager) RecordPayment(assetID string, payment Payment) error {
	agreement, exists := lm.Agreements[assetID]
	if !exists {
		return fmt.Errorf("licensing agreement for asset ID %s not found", assetID)
	}

	for i, p := range agreement.PaymentSchedule {
		if p.DueDate.Equal(payment.DueDate) {
			if agreement.PaymentSchedule[i].Paid {
				return fmt.Errorf("payment for due date %s already paid", payment.DueDate)
			}
			agreement.PaymentSchedule[i].Paid = true
			agreement.PaymentSchedule[i].PaidDate = time.Now()

			// Record the payment in the ledger
			if err := lm.Ledger.RecordLicensingPayment(assetID, payment); err != nil {
				return err
			}

			return nil
		}
	}

	return fmt.Errorf("payment due date %s not found in the schedule", payment.DueDate)
}

// GetLicensingAgreement retrieves the licensing agreement for a given asset ID.
func (lm *LicensingManager) GetLicensingAgreement(assetID string) (*LicensingAgreement, error) {
	agreement, exists := lm.Agreements[assetID]
	if !exists {
		return nil, fmt.Errorf("licensing agreement for asset ID %s not found", assetID)
	}
	return agreement, nil
}

// AdjustLicenseTerms allows authorized entities to manually adjust the license terms of an asset.
func (lm *LicensingManager) AdjustLicenseTerms(assetID, newLicenseTerms string, authorized bool) error {
	if !authorized {
		return errors.New("unauthorized license term adjustment")
	}

	agreement, exists := lm.GetLicensingAgreement(assetID)
	if !exists {
		return fmt.Errorf("licensing agreement for asset ID %s not found", assetID)
	}

	agreement.LicenseTerms = newLicenseTerms

	// Record the adjustment in the ledger
	if err := lm.Ledger.RecordLicenseAdjustment(assetID, newLicenseTerms); err != nil {
		return err
	}

	return nil
}

// AnalyzeLicenseUsage provides analysis tools for stakeholders to make informed decisions.
func (lm *LicensingManager) AnalyzeLicenseUsage(assetID string) (map[string]float64, error) {
	agreement, exists := lm.GetLicensingAgreement(assetID)
	if !exists {
		return nil, fmt.Errorf("licensing agreement for asset ID %s not found", assetID)
	}

	// Example analysis: return usage metrics
	return agreement.UsageMetrics, nil
}

// RecordUsageMetric records usage metrics for a licensing agreement.
func (lm *LicensingManager) RecordUsageMetric(assetID, metric string, value float64) error {
	agreement, exists := lm.GetLicensingAgreement(assetID)
	if !exists {
		return fmt.Errorf("licensing agreement for asset ID %s not found", assetID)
	}

	if _, exists := agreement.UsageMetrics[metric]; !exists {
		agreement.UsageMetrics[metric] = 0
	}
	agreement.UsageMetrics[metric] += value

	// Record the usage metric in the ledger
	if err := lm.Ledger.RecordUsageMetric(assetID, metric, value); err != nil {
		return err
	}

	return nil
}

// SmartContractIntegration integrates licensing agreements with smart contracts for automation.
func (lm *LicensingManager) SmartContractIntegration(assetID, contractCode string) error {
	agreement, exists := lm.GetLicensingAgreement(assetID)
	if !exists {
		return fmt.Errorf("licensing agreement for asset ID %s not found", assetID)
	}

	// Deploy the smart contract
	sc := smart_contracts.NewSmartContract(contractCode, map[string]interface{}{
		"licensor":        agreement.Licensor,
		"licensee":        agreement.Licensee,
		"licenseTerms":    agreement.LicenseTerms,
		"startDate":       agreement.StartDate,
		"endDate":         agreement.EndDate,
		"paymentSchedule": agreement.PaymentSchedule,
		"usageMetrics":    agreement.UsageMetrics,
	})
	if err := sc.Deploy(); err != nil {
		return err
	}

	// Link the smart contract to the licensing agreement
	agreement.LicenseTerms = fmt.Sprintf("%s\nSmart Contract Address: %s", agreement.LicenseTerms, sc.Address)

	return nil
}
