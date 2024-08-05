package management

import (
	"errors"
	"time"

	"github.com/synnergy_network/blockchain/assets"
	"github.com/synnergy_network/blockchain/events"
	"github.com/synnergy_network/blockchain/ledger"
	"github.com/synnergy_network/blockchain/payments"
	"github.com/synnergy_network/blockchain/smart_contracts"
	"github.com/synnergy_network/blockchain/transactions"
)

// UserInterface provides methods for users to interact with the SYN3000 token standard
type UserInterface struct {
	Ledger            ledger.Ledger
	AssetManager      assets.AssetManager
	SmartContractMgr  SmartContractManager
	PaymentSystem     payments.PaymentSystem
	EventLogger       events.EventLogger
	TransactionSystem transactions.TransactionSystem
}

// NewUserInterface constructor
func NewUserInterface(ledger ledger.Ledger, assetManager assets.AssetManager, smartContractMgr SmartContractManager, paymentSystem payments.PaymentSystem, eventLogger events.EventLogger, transactionSystem transactions.TransactionSystem) *UserInterface {
	return &UserInterface{
		Ledger:            ledger,
		AssetManager:      assetManager,
		SmartContractMgr:  smartContractMgr,
		PaymentSystem:     paymentSystem,
		EventLogger:       eventLogger,
		TransactionSystem: transactionSystem,
	}
}

// CreateRentalToken creates a new rental token
func (ui *UserInterface) CreateRentalToken(propertyID, tenantID string, leaseStartDate, leaseEndDate time.Time, monthlyRent, deposit float64) (string, error) {
	tokenID := generateTokenID()
	issuedDate := time.Now()

	rentalToken := assets.RentalToken{
		TokenID:        tokenID,
		PropertyID:     propertyID,
		TenantID:       tenantID,
		LeaseStartDate: leaseStartDate,
		LeaseEndDate:   leaseEndDate,
		MonthlyRent:    monthlyRent,
		Deposit:        deposit,
		IssuedDate:     issuedDate,
		ActiveStatus:   true,
		LastUpdateDate: issuedDate,
	}

	if err := ui.AssetManager.CreateRentalToken(rentalToken); err != nil {
		return "", err
	}

	ui.EventLogger.LogEvent(events.Event{
		Type:      "RentalTokenCreated",
		Timestamp: issuedDate,
		Details:   map[string]interface{}{"tokenID": tokenID},
	})

	return tokenID, nil
}

// TransferRentalToken transfers a rental token to another tenant
func (ui *UserInterface) TransferRentalToken(tokenID, newTenantID string) error {
	rentalToken, err := ui.AssetManager.GetRentalToken(tokenID)
	if err != nil {
		return err
	}

	rentalToken.TenantID = newTenantID
	rentalToken.LastUpdateDate = time.Now()

	if err := ui.AssetManager.UpdateRentalToken(rentalToken); err != nil {
		return err
	}

	ui.EventLogger.LogEvent(events.Event{
		Type:      "RentalTokenTransferred",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "newTenantID": newTenantID},
	})

	return nil
}

// PayRent handles the payment of monthly rent
func (ui *UserInterface) PayRent(tokenID string) error {
	rentalToken, err := ui.AssetManager.GetRentalToken(tokenID)
	if err != nil {
		return err
	}

	if !rentalToken.ActiveStatus {
		return errors.New("rental token is not active")
	}

	payment := payments.PaymentRecord{
		TokenID:   tokenID,
		Amount:    rentalToken.MonthlyRent,
		Timestamp: time.Now(),
		Type:      "Rent Payment",
	}

	if err := ui.PaymentSystem.ProcessPayment(payment); err != nil {
		return err
	}

	if err := ui.Ledger.StorePayment(tokenID, payment); err != nil {
		return err
	}

	ui.EventLogger.LogEvent(events.Event{
		Type:      "RentPaid",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "amount": rentalToken.MonthlyRent},
	})

	return nil
}

// HandleLatePayment processes late payment penalties
func (ui *UserInterface) HandleLatePayment(tokenID string) error {
	rentalToken, err := ui.AssetManager.GetRentalToken(tokenID)
	if err != nil {
		return err
	}

	// Example penalty logic: 10% of monthly rent for each day late
	penaltyAmount := rentalToken.MonthlyRent * 0.1
	payment := payments.PaymentRecord{
		TokenID:   tokenID,
		Amount:    penaltyAmount,
		Timestamp: time.Now(),
		Type:      "Late Payment Penalty",
	}

	if err := ui.PaymentSystem.ProcessPayment(payment); err != nil {
		return err
	}

	if err := ui.Ledger.StorePayment(tokenID, payment); err != nil {
		return err
	}

	ui.EventLogger.LogEvent(events.Event{
		Type:      "LatePaymentHandled",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "penaltyAmount": penaltyAmount},
	})

	return nil
}

// TerminateRentalAgreement terminates a rental agreement and deactivates the token
func (ui *UserInterface) TerminateRentalAgreement(tokenID string) error {
	if err := ui.SmartContractMgr.TerminateRentalAgreement(tokenID); err != nil {
		return err
	}

	rentalToken, err := ui.AssetManager.GetRentalToken(tokenID)
	if err != nil {
		return err
	}

	rentalToken.ActiveStatus = false
	rentalToken.LastUpdateDate = time.Now()

	if err := ui.AssetManager.UpdateRentalToken(rentalToken); err != nil {
		return err
	}

	ui.EventLogger.LogEvent(events.Event{
		Type:      "RentalAgreementTerminated",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID},
	})

	return nil
}

// GetRentalYield retrieves the rental yield for a property
func (ui *UserInterface) GetRentalYield(propertyID string) (float64, error) {
	payments, err := ui.Ledger.GetPaymentsForProperty(propertyID)
	if err != nil {
		return 0, err
	}

	totalPayments := 0.0
	for _, payment := range payments {
		totalPayments += payment.Amount
	}

	// Assuming rental yield is total payments received
	return totalPayments, nil
}

// generateTokenID generates a unique ID for a rental token
func generateTokenID() string {
	return fmt.Sprintf("TOKEN-%d", time.Now().UnixNano())
}
