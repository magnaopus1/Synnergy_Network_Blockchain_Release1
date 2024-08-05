package contracts

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/smart_contracts"
)

// RentalAgreement represents a smart contract for renting an asset.
type RentalAgreement struct {
	AssetID        string
	Lessor         string
	Lessee         string
	RentalTerms    string
	StartDate      time.Time
	EndDate        time.Time
	PaymentSchedule []Payment
	Status         string
}

// Payment represents a scheduled payment in the rental agreement.
type Payment struct {
	DueDate  time.Time
	Amount   float64
	Paid     bool
	PaidDate time.Time
}

// RentalManager handles the creation and management of rental agreements.
type RentalManager struct {
	Agreements map[string]*RentalAgreement
	Ledger     *ledger.LedgerManager
	Assets     *assets.OwnershipManager
}

// NewRentalManager initializes a new RentalManager.
func NewRentalManager(ledger *ledger.LedgerManager, assets *assets.OwnershipManager) *RentalManager {
	return &RentalManager{
		Agreements: make(map[string]*RentalAgreement),
		Ledger:     ledger,
		Assets:     assets,
	}
}

// CreateRentalAgreement creates a new rental agreement.
func (rm *RentalManager) CreateRentalAgreement(assetID, lessor, lessee, rentalTerms string, startDate, endDate time.Time, paymentSchedule []Payment) (*RentalAgreement, error) {
	if _, exists := rm.Agreements[assetID]; exists {
		return nil, fmt.Errorf("rental agreement for asset ID %s already exists", assetID)
	}

	agreement := &RentalAgreement{
		AssetID:        assetID,
		Lessor:         lessor,
		Lessee:         lessee,
		RentalTerms:    rentalTerms,
		StartDate:      startDate,
		EndDate:        endDate,
		PaymentSchedule: paymentSchedule,
		Status:         "Active",
	}

	rm.Agreements[assetID] = agreement

	// Record the creation of the rental agreement in the ledger
	if err := rm.Ledger.RecordRentalCreation(agreement); err != nil {
		return nil, err
	}

	return agreement, nil
}

// RecordPayment records a payment for a rental agreement.
func (rm *RentalManager) RecordPayment(assetID string, payment Payment) error {
	agreement, exists := rm.Agreements[assetID]
	if !exists {
		return fmt.Errorf("rental agreement for asset ID %s not found", assetID)
	}

	for i, p := range agreement.PaymentSchedule {
		if p.DueDate.Equal(payment.DueDate) {
			if agreement.PaymentSchedule[i].Paid {
				return fmt.Errorf("payment for due date %s already paid", payment.DueDate)
			}
			agreement.PaymentSchedule[i].Paid = true
			agreement.PaymentSchedule[i].PaidDate = time.Now()

			// Record the payment in the ledger
			if err := rm.Ledger.RecordRentalPayment(assetID, payment); err != nil {
				return err
			}

			return nil
		}
	}

	return fmt.Errorf("payment due date %s not found in the schedule", payment.DueDate)
}

// GetRentalAgreement retrieves the rental agreement for a given asset ID.
func (rm *RentalManager) GetRentalAgreement(assetID string) (*RentalAgreement, error) {
	agreement, exists := rm.Agreements[assetID]
	if !exists {
		return nil, fmt.Errorf("rental agreement for asset ID %s not found", assetID)
	}
	return agreement, nil
}

// AdjustRentalTerms allows authorized entities to manually adjust the rental terms of an asset.
func (rm *RentalManager) AdjustRentalTerms(assetID, newRentalTerms string, authorized bool) error {
	if !authorized {
		return errors.New("unauthorized rental term adjustment")
	}

	agreement, exists := rm.GetRentalAgreement(assetID)
	if !exists {
		return fmt.Errorf("rental agreement for asset ID %s not found", assetID)
	}

	agreement.RentalTerms = newRentalTerms

	// Record the adjustment in the ledger
	if err := rm.Ledger.RecordRentalAdjustment(assetID, newRentalTerms); err != nil {
		return err
	}

	return nil
}

// AnalyzeRentalUsage provides analysis tools for stakeholders to make informed decisions.
func (rm *RentalManager) AnalyzeRentalUsage(assetID string) (map[string]float64, error) {
	agreement, exists := rm.GetRentalAgreement(assetID)
	if !exists {
		return nil, fmt.Errorf("rental agreement for asset ID %s not found", assetID)
	}

	// Example analysis: return payment metrics
	paymentMetrics := make(map[string]float64)
	for _, payment := range agreement.PaymentSchedule {
		if payment.Paid {
			paymentMetrics[payment.DueDate.String()] = payment.Amount
		}
	}

	return paymentMetrics, nil
}

// SmartContractIntegration integrates rental agreements with smart contracts for automation.
func (rm *RentalManager) SmartContractIntegration(assetID, contractCode string) error {
	agreement, exists := rm.GetRentalAgreement(assetID)
	if !exists {
		return fmt.Errorf("rental agreement for asset ID %s not found", assetID)
	}

	// Deploy the smart contract
	sc := smart_contracts.NewSmartContract(contractCode, map[string]interface{}{
		"lessor":         agreement.Lessor,
		"lessee":         agreement.Lessee,
		"rentalTerms":    agreement.RentalTerms,
		"startDate":      agreement.StartDate,
		"endDate":        agreement.EndDate,
		"paymentSchedule": agreement.PaymentSchedule,
		"status":         agreement.Status,
	})
	if err := sc.Deploy(); err != nil {
		return err
	}

	// Link the smart contract to the rental agreement
	agreement.RentalTerms = fmt.Sprintf("%s\nSmart Contract Address: %s", agreement.RentalTerms, sc.Address)

	return nil
}

// TerminateRentalAgreement terminates an active rental agreement.
func (rm *RentalManager) TerminateRentalAgreement(assetID string, authorized bool) error {
	if !authorized {
		return errors.New("unauthorized termination")
	}

	agreement, exists := rm.GetRentalAgreement(assetID)
	if !exists {
		return fmt.Errorf("rental agreement for asset ID %s not found", assetID)
	}

	agreement.Status = "Terminated"

	// Record the termination in the ledger
	if err := rm.Ledger.RecordRentalTermination(assetID); err != nil {
		return err
	}

	return nil
}
