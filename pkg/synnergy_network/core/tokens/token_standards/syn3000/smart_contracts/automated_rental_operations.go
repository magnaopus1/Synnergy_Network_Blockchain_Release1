package smart_contracts

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/blockchain/ledger"
	"github.com/synnergy_network/blockchain/payments"
	"github.com/synnergy_network/blockchain/security"
	"github.com/synnergy_network/blockchain/tokens"
)

// AutomatedRentalOperations manages rental operations using smart contracts
type AutomatedRentalOperations struct {
	ledger        ledger.Ledger
	paymentSystem payments.PaymentSystem
	security      security.SecurityManager
}

// NewAutomatedRentalOperations creates a new instance of AutomatedRentalOperations
func NewAutomatedRentalOperations(ledger ledger.Ledger, paymentSystem payments.PaymentSystem, security security.SecurityManager) *AutomatedRentalOperations {
	return &AutomatedRentalOperations{
		ledger:        ledger,
		paymentSystem: paymentSystem,
		security:      security,
	}
}

// ScheduleRentPayments schedules automated rent payments for a rental agreement
func (aro *AutomatedRentalOperations) ScheduleRentPayments(agreementID string, startDate time.Time, monthlyRent float64, durationMonths int) error {
	agreement, err := aro.ledger.GetRentalAgreement(agreementID)
	if err != nil {
		return err
	}

	for i := 0; i < durationMonths; i++ {
		paymentDate := startDate.AddDate(0, i, 0)
		err = aro.paymentSystem.SchedulePayment(agreement.TenantID, agreement.LandlordID, monthlyRent, paymentDate)
		if err != nil {
			return fmt.Errorf("failed to schedule rent payment for month %d: %v", i+1, err)
		}
	}
	return nil
}

// ExecuteRentPayment executes a scheduled rent payment
func (aro *AutomatedRentalOperations) ExecuteRentPayment(tenantID, landlordID string, amount float64) error {
	err := aro.paymentSystem.ProcessPayment(tenantID, landlordID, amount)
	if err != nil {
		return fmt.Errorf("failed to execute rent payment: %v", err)
	}
	return nil
}

// HandleLatePayments handles late rent payments by applying penalties and sending notifications
func (aro *AutomatedRentalOperations) HandleLatePayments(agreementID string, dueDate time.Time, penaltyRate float64) error {
	agreement, err := aro.ledger.GetRentalAgreement(agreementID)
	if err != nil {
		return err
	}

	isLate, err := aro.paymentSystem.IsPaymentLate(agreement.TenantID, dueDate)
	if err != nil {
		return err
	}

	if isLate {
		penalty := agreement.MonthlyRent * penaltyRate
		err = aro.paymentSystem.ProcessPayment(agreement.TenantID, agreement.LandlordID, penalty)
		if err != nil {
			return fmt.Errorf("failed to process late payment penalty: %v", err)
		}
		err = aro.sendLatePaymentNotification(agreement.TenantID, agreement.LandlordID, penalty)
		if err != nil {
			return fmt.Errorf("failed to send late payment notification: %v", err)
		}
	}
	return nil
}

// EnforceLeaseTerms enforces the terms of a rental agreement using smart contracts
func (aro *AutomatedRentalOperations) EnforceLeaseTerms(agreementID string) error {
	agreement, err := aro.ledger.GetRentalAgreement(agreementID)
	if err != nil {
		return err
	}

	if !aro.security.VerifyOwnership(agreement.PropertyID, agreement.LandlordID) {
		return errors.New("landlord does not own the property")
	}

	err = aro.ledger.UpdateRentalAgreementStatus(agreementID, "active")
	if err != nil {
		return fmt.Errorf("failed to update rental agreement status: %v", err)
	}

	return nil
}

// TerminateLease terminates a rental agreement and releases the security deposit
func (aro *AutomatedRentalOperations) TerminateLease(agreementID string) error {
	agreement, err := aro.ledger.GetRentalAgreement(agreementID)
	if err != nil {
		return err
	}

	err = aro.ledger.UpdateRentalAgreementStatus(agreementID, "terminated")
	if err != nil {
		return fmt.Errorf("failed to update rental agreement status: %v", err)
	}

	err = aro.paymentSystem.ReleaseDeposit(agreement.TenantID, agreement.LandlordID, agreement.DepositAmount)
	if err != nil {
		return fmt.Errorf("failed to release security deposit: %v", err)
	}

	return nil
}

// sendLatePaymentNotification sends a notification about a late payment
func (aro *AutomatedRentalOperations) sendLatePaymentNotification(tenantID, landlordID string, penalty float64) error {
	notification := fmt.Sprintf("Late payment notification: Tenant %s has incurred a penalty of %.2f for late rent payment.", tenantID, penalty)
	return aro.ledger.StoreEvent(notification)
}
