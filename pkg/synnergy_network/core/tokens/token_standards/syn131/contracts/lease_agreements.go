package contracts

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/smart_contracts"
)

// LeaseAgreement represents a smart contract for leasing an asset.
type LeaseAgreement struct {
	AssetID        string
	Lessor         string
	Lessee         string
	LeaseTerms     string
	StartDate      time.Time
	EndDate        time.Time
	PaymentSchedule []Payment
}

// Payment represents a scheduled payment in the lease agreement.
type Payment struct {
	DueDate  time.Time
	Amount   float64
	Paid     bool
	PaidDate time.Time
}

// LeaseManager handles the creation and management of lease agreements.
type LeaseManager struct {
	Agreements map[string]*LeaseAgreement
	Ledger     *ledger.LedgerManager
	Assets     *assets.OwnershipManager
}

// NewLeaseManager initializes a new LeaseManager.
func NewLeaseManager(ledger *ledger.LedgerManager, assets *assets.OwnershipManager) *LeaseManager {
	return &LeaseManager{
		Agreements: make(map[string]*LeaseAgreement),
		Ledger:     ledger,
		Assets:     assets,
	}
}

// CreateLeaseAgreement creates a new lease agreement.
func (lm *LeaseManager) CreateLeaseAgreement(assetID, lessor, lessee, leaseTerms string, startDate, endDate time.Time, paymentSchedule []Payment) (*LeaseAgreement, error) {
	if _, exists := lm.Agreements[assetID]; exists {
		return nil, fmt.Errorf("lease agreement for asset ID %s already exists", assetID)
	}

	agreement := &LeaseAgreement{
		AssetID:        assetID,
		Lessor:         lessor,
		Lessee:         lessee,
		LeaseTerms:     leaseTerms,
		StartDate:      startDate,
		EndDate:        endDate,
		PaymentSchedule: paymentSchedule,
	}

	lm.Agreements[assetID] = agreement

	// Record the creation of the lease agreement in the ledger
	if err := lm.Ledger.RecordLeaseCreation(agreement); err != nil {
		return nil, err
	}

	return agreement, nil
}

// RecordPayment records a payment for a lease agreement.
func (lm *LeaseManager) RecordPayment(assetID string, payment Payment) error {
	agreement, exists := lm.Agreements[assetID]
	if !exists {
		return fmt.Errorf("lease agreement for asset ID %s not found", assetID)
	}

	for i, p := range agreement.PaymentSchedule {
		if p.DueDate.Equal(payment.DueDate) {
			if agreement.PaymentSchedule[i].Paid {
				return fmt.Errorf("payment for due date %s already paid", payment.DueDate)
			}
			agreement.PaymentSchedule[i].Paid = true
			agreement.PaymentSchedule[i].PaidDate = time.Now()

			// Record the payment in the ledger
			if err := lm.Ledger.RecordLeasePayment(assetID, payment); err != nil {
				return err
			}

			return nil
		}
	}

	return fmt.Errorf("payment due date %s not found in the schedule", payment.DueDate)
}

// GetLeaseAgreement retrieves the lease agreement for a given asset ID.
func (lm *LeaseManager) GetLeaseAgreement(assetID string) (*LeaseAgreement, error) {
	agreement, exists := lm.Agreements[assetID]
	if !exists {
		return nil, fmt.Errorf("lease agreement for asset ID %s not found", assetID)
	}
	return agreement, nil
}

// AdjustLeaseTerms allows authorized entities to manually adjust the lease terms of an asset.
func (lm *LeaseManager) AdjustLeaseTerms(assetID, newLeaseTerms string, authorized bool) error {
	if !authorized {
		return errors.New("unauthorized lease term adjustment")
	}

	agreement, exists := lm.GetLeaseAgreement(assetID)
	if !exists {
		return fmt.Errorf("lease agreement for asset ID %s not found", assetID)
	}

	agreement.LeaseTerms = newLeaseTerms

	// Record the adjustment in the ledger
	if err := lm.Ledger.RecordLeaseAdjustment(assetID, newLeaseTerms); err != nil {
		return err
	}

	return nil
}

// AnalyzeLeasePayments provides analysis tools for stakeholders to make informed decisions.
func (lm *LeaseManager) AnalyzeLeasePayments(assetID string) (map[string]float64, error) {
	agreement, exists := lm.GetLeaseAgreement(assetID)
	if !exists {
		return nil, fmt.Errorf("lease agreement for asset ID %s not found", assetID)
	}

	// Example analysis: calculate total paid and unpaid amounts
	totalPaid := 0.0
	totalUnpaid := 0.0

	for _, p := range agreement.PaymentSchedule {
		if p.Paid {
			totalPaid += p.Amount
		} else {
			totalUnpaid += p.Amount
		}
	}

	return map[string]float64{
		"totalPaid":   totalPaid,
		"totalUnpaid": totalUnpaid,
	}, nil
}

// SmartContractIntegration integrates lease agreements with smart contracts for automation.
func (lm *LeaseManager) SmartContractIntegration(assetID, contractCode string) error {
	agreement, exists := lm.GetLeaseAgreement(assetID)
	if !exists {
		return fmt.Errorf("lease agreement for asset ID %s not found", assetID)
	}

	// Deploy the smart contract
	sc := smart_contracts.NewSmartContract(contractCode, map[string]interface{}{
		"lessor":          agreement.Lessor,
		"lessee":          agreement.Lessee,
		"leaseTerms":      agreement.LeaseTerms,
		"startDate":       agreement.StartDate,
		"endDate":         agreement.EndDate,
		"paymentSchedule": agreement.PaymentSchedule,
	})
	if err := sc.Deploy(); err != nil {
		return err
	}

	// Link the smart contract to the lease agreement
	agreement.LeaseTerms = fmt.Sprintf("%s\nSmart Contract Address: %s", agreement.LeaseTerms, sc.Address)

	return nil
}
