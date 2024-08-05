package management

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
	"github.com/synnergy_network/core/tokens/token_standards/syn845"
)

// UserInterface provides an interface for users to interact with their SYN845 debt instruments
type UserInterface struct {
	mu sync.Mutex
}

// NewUserInterface creates a new instance of UserInterface
func NewUserInterface() *UserInterface {
	return &UserInterface{}
}

// ViewDebtInstrument allows a user to view details of their debt instrument by ID
func (ui *UserInterface) ViewDebtInstrument(debtID string) (syn845.SYN845, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	debtInstrument, err := syn845.GetSYN845(debtID)
	if err != nil {
		return syn845.SYN845{}, err
	}

	return debtInstrument, nil
}

// ViewRepaymentSchedule allows a user to view the repayment schedule for their debt instrument
func (ui *UserInterface) ViewRepaymentSchedule(debtID string) ([]RepaymentEntry, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	rt := NewRepaymentTracking()
	repayments, err := rt.GetRepaymentsByDebtID(debtID)
	if err != nil {
		return nil, err
	}

	return repayments, nil
}

// ViewNotifications allows a user to view their notifications
func (ui *UserInterface) ViewNotifications(stakeholderID string) ([]Notification, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	se := NewStakeholderEngagement()
	notifications, err := se.GetNotifications(stakeholderID)
	if err != nil {
		return nil, err
	}

	return notifications, nil
}

// MarkNotificationAsRead allows a user to mark a notification as read
func (ui *UserInterface) MarkNotificationAsRead(notificationID string) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	se := NewStakeholderEngagement()
	err := se.MarkNotificationAsRead(notificationID)
	if err != nil {
		return err
	}

	return nil
}

// RequestDebtRefinancing allows a user to request refinancing for their debt instrument
func (ui *UserInterface) RequestDebtRefinancing(debtID string, newTerms map[string]interface{}) (string, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	dg := NewDecentralizedGovernance()
	proposalID, err := dg.ProposeChange("user", "Refinancing Request", "User requested refinancing", debtID, newTerms)
	if err != nil {
		return "", err
	}

	return proposalID, nil
}

// ViewPaymentHistory allows a user to view the payment history for their debt instrument
func (ui *UserInterface) ViewPaymentHistory(debtID string) ([]ledger.LedgerEntry, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	l := ledger.NewLedger()
	entries, err := l.GetEntriesByDebtID(debtID)
	if err != nil {
		return nil, err
	}

	return entries, nil
}

// RequestInterestRateAdjustment allows a user to request an adjustment to their interest rate
func (ui *UserInterface) RequestInterestRateAdjustment(debtID string, newRate float64) (string, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	dg := NewDecentralizedGovernance()
	newTerms := map[string]interface{}{
		"interest_rate": newRate,
	}
	proposalID, err := dg.ProposeChange("user", "Interest Rate Adjustment", "User requested interest rate adjustment", debtID, newTerms)
	if err != nil {
		return "", err
	}

	return proposalID, nil
}

// generateRequestID generates a unique ID for requests
func generateRequestID() string {
	// Implement unique ID generation logic, for example using UUID
	return "unique-request-id"
}

// saveRequestToStorage securely stores request data
func saveRequestToStorage(request interface{}) error {
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("request", generateRequestID(), encryptedData)
}

// deleteRequestFromStorage deletes request data from storage
func deleteRequestFromStorage(requestID string) error {
	return storage.Delete("request", requestID)
}
