package management

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/transactions"
)

// UserInterface represents the methods for user interaction with the SYN1700 token standard
type UserInterface struct {
	Ledger          *ledger.Ledger
	SecurityManager *security.SecurityManager
	TransactionManager *transactions.TransactionManager
}

// NewUserInterface creates a new instance of UserInterface
func NewUserInterface(ledger *ledger.Ledger, securityManager *security.SecurityManager, transactionManager *transactions.TransactionManager) *UserInterface {
	return &UserInterface{
		Ledger:          ledger,
		SecurityManager: securityManager,
		TransactionManager: transactionManager,
	}
}

// CreateEvent creates a new event with the given metadata
func (ui *UserInterface) CreateEvent(metadata assets.EventMetadata) (string, error) {
	eventID := metadata.EventID
	err := ui.Ledger.AddEvent(metadata)
	if err != nil {
		return "", err
	}
	return eventID, nil
}

// IssueTicket issues a new ticket for a given event
func (ui *UserInterface) IssueTicket(ticketMetadata assets.TicketMetadata) (string, error) {
	ticketID := ticketMetadata.TicketID
	err := ui.Ledger.AddTicket(ticketMetadata)
	if err != nil {
		return "", err
	}
	return ticketID, nil
}

// TransferTicket transfers a ticket from one owner to another
func (ui *UserInterface) TransferTicket(ticketID, from, to string) error {
	err := ui.TransactionManager.TransferTicket(ticketID, from, to)
	if err != nil {
		return err
	}
	return nil
}

// VerifyTicket verifies the authenticity of a ticket
func (ui *UserInterface) VerifyTicket(ticketID string) (bool, error) {
	valid, err := ui.TransactionManager.ValidateTicket(ticketID)
	if err != nil {
		return false, err
	}
	return valid, nil
}

// GetEventDetails retrieves the details of a given event
func (ui *UserInterface) GetEventDetails(eventID string) (assets.EventMetadata, error) {
	event, err := ui.Ledger.GetEvent(eventID)
	if err != nil {
		return assets.EventMetadata{}, err
	}
	return event, nil
}

// GetTicketDetails retrieves the details of a given ticket
func (ui *UserInterface) GetTicketDetails(ticketID string) (assets.TicketMetadata, error) {
	ticket, err := ui.Ledger.GetTicket(ticketID)
	if err != nil {
		return assets.TicketMetadata{}, err
	}
	return ticket, nil
}

// RevokeTicket revokes a given ticket, making it invalid
func (ui *UserInterface) RevokeTicket(ticketID string) error {
	err := ui.TransactionManager.RevokeTicket(ticketID)
	if err != nil {
		return err
	}
	return nil
}

// DelegateTicketAccess delegates access rights of a ticket to another user
func (ui *UserInterface) DelegateTicketAccess(ticketID, from, to string) error {
	err := ui.TransactionManager.DelegateAccess(ticketID, from, to)
	if err != nil {
		return err
	}
	return nil
}

// TimeLockTicket locks a ticket for a specific period
func (ui *UserInterface) TimeLockTicket(ticketID string, until time.Time) error {
	err := ui.TransactionManager.TimeLockAccess(ticketID, until)
	if err != nil {
		return err
	}
	return nil
}

// EncryptUserData encrypts user data using the security manager
func (ui *UserInterface) EncryptUserData(data string) (string, error) {
	encryptedData, err := ui.SecurityManager.EncryptData(data)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptUserData decrypts user data using the security manager
func (ui *UserInterface) DecryptUserData(encryptedData string) (string, error) {
	decryptedData, err := ui.SecurityManager.DecryptData(encryptedData)
	if err != nil {
		return "", err
	}
	return decryptedData, nil
}

// GetEventLog retrieves the event log for a given event ID
func (ui *UserInterface) GetEventLog(eventID string) ([]assets.EventLog, error) {
	logs, err := ui.Ledger.GetEventLogs(eventID)
	if err != nil {
		return nil, err
	}
	return logs, nil
}

// GetComplianceRecords retrieves compliance records for a given event ID
func (ui *UserInterface) GetComplianceRecords(eventID string) ([]assets.ComplianceRecord, error) {
	records, err := ui.Ledger.GetComplianceRecords(eventID)
	if err != nil {
		return nil, err
	}
	return records, nil
}
