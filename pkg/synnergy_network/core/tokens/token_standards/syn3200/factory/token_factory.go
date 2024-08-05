// Package factory provides functionalities to create and manage SYN3200 tokens.
package factory

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"synnergy_network/core/tokens/token_standards/syn3200/assets"
	"synnergy_network/core/tokens/token_standards/syn3200/ledger"
	"synnergy_network/core/tokens/token_standards/syn3200/events"
)

// TokenFactory handles the creation and management of SYN3200 tokens.
type TokenFactory struct {
	billLedger           *ledger.BillLedger
	metadataLedger       *assets.MetadataLedger
	ownershipVerification *assets.OwnershipVerification
	eventManager         *events.EventManager
}

// NewTokenFactory creates a new TokenFactory.
func NewTokenFactory() *TokenFactory {
	return &TokenFactory{
		billLedger:           ledger.NewBillLedger(),
		metadataLedger:       assets.NewMetadataLedger(),
		ownershipVerification: assets.NewOwnershipVerification(),
		eventManager:         events.NewEventManager(),
	}
}

// CreateToken creates a new SYN3200 token with the specified details.
func (tf *TokenFactory) CreateToken(issuer, payer string, originalAmount float64, dueDate time.Time, termsConditions string) (string, error) {
	billID := uuid.New().String()
	token := assets.Bill{
		ID:              billID,
		Issuer:          issuer,
		Payer:           payer,
		OriginalAmount:  originalAmount,
		RemainingAmount: originalAmount,
		DueDate:         dueDate,
		PaidStatus:      false,
		Metadata:        termsConditions,
		Timestamp:       time.Now(),
	}
	
	tf.billLedger.AddBill(token)
	
	metadata := assets.BillMetadata{
		BillID:          billID,
		Issuer:          issuer,
		Payer:           payer,
		OriginalAmount:  originalAmount,
		RemainingAmount: originalAmount,
		DueDate:         dueDate,
		PaidStatus:      false,
		TermsConditions: termsConditions,
		Timestamp:       time.Now(),
	}
	tf.metadataLedger.AddMetadata(metadata)
	tf.ownershipVerification.CreateOwnershipRecord(billID, issuer)
	
	eventData := map[string]interface{}{
		"billID":           billID,
		"issuer":           issuer,
		"payer":            payer,
		"originalAmount":   originalAmount,
		"dueDate":          dueDate,
		"termsConditions":  termsConditions,
		"timestamp":        time.Now(),
	}
	tf.eventManager.EmitEvent("TokenCreated", eventData)
	
	return billID, nil
}

// GetToken retrieves a SYN3200 token by its ID.
func (tf *TokenFactory) GetToken(billID string) (assets.Bill, error) {
	return tf.billLedger.GetBill(billID)
}

// UpdateToken updates the metadata of an existing SYN3200 token.
func (tf *TokenFactory) UpdateToken(billID, issuer, payer string, remainingAmount float64, dueDate time.Time, termsConditions string, paidStatus bool) error {
	bill, err := tf.billLedger.GetBill(billID)
	if err != nil {
		return err
	}
	
	bill.RemainingAmount = remainingAmount
	bill.DueDate = dueDate
	bill.Metadata = termsConditions
	bill.PaidStatus = paidStatus
	
	err = tf.billLedger.UpdateBill(bill)
	if err != nil {
		return err
	}
	
	metadata := assets.BillMetadata{
		BillID:          billID,
		Issuer:          issuer,
		Payer:           payer,
		OriginalAmount:  bill.OriginalAmount,
		RemainingAmount: remainingAmount,
		DueDate:         dueDate,
		PaidStatus:      paidStatus,
		TermsConditions: termsConditions,
		Timestamp:       time.Now(),
	}
	
	err = tf.metadataLedger.UpdateMetadata(metadata)
	if err != nil {
		return err
	}
	
	eventData := map[string]interface{}{
		"billID":           billID,
		"issuer":           issuer,
		"payer":            payer,
		"remainingAmount":  remainingAmount,
		"dueDate":          dueDate,
		"termsConditions":  termsConditions,
		"paidStatus":       paidStatus,
		"timestamp":        time.Now(),
	}
	tf.eventManager.EmitEvent("TokenUpdated", eventData)
	
	return nil
}

// TransferToken transfers the ownership of a SYN3200 token to a new owner.
func (tf *TokenFactory) TransferToken(billID, newOwner string) error {
	err := tf.ownershipVerification.TransferOwnership(billID, newOwner)
	if err != nil {
		return err
	}
	
	eventData := map[string]interface{}{
		"billID":           billID,
		"newOwner":         newOwner,
		"timestamp":        time.Now(),
	}
	tf.eventManager.EmitEvent("TokenTransferred", eventData)
	
	return nil
}

// BurnToken burns a SYN3200 token, removing it from the system.
func (tf *TokenFactory) BurnToken(billID string) error {
	bill, err := tf.billLedger.GetBill(billID)
	if err != nil {
		return err
	}
	
	err = tf.billLedger.DeleteBill(billID)
	if err != nil {
		return err
	}
	
	err = tf.metadataLedger.DeleteMetadata(billID)
	if err != nil {
		return err
	}
	
	err = tf.ownershipVerification.DeleteOwnershipRecord(billID)
	if err != nil {
		return err
	}
	
	eventData := map[string]interface{}{
		"billID":           billID,
		"issuer":           bill.Issuer,
		"timestamp":        time.Now(),
	}
	tf.eventManager.EmitEvent("TokenBurned", eventData)
	
	return nil
}

// ListTokens lists all SYN3200 tokens in the system.
func (tf *TokenFactory) ListTokens() []assets.Bill {
	return tf.billLedger.ListBills()
}

// GetTokenMetadata retrieves the metadata of a SYN3200 token by its ID.
func (tf *TokenFactory) GetTokenMetadata(billID string) (assets.BillMetadata, error) {
	return tf.metadataLedger.GetMetadata(billID)
}

// ListTokenEvents lists all events associated with a SYN3200 token by its ID.
func (tf *TokenFactory) ListTokenEvents(billID string) ([]events.Event, error) {
	allEvents := tf.eventManager.GetEvents()
	var tokenEvents []events.Event
	
	for _, event := range allEvents {
		if event.Data["billID"] == billID {
			tokenEvents = append(tokenEvents, event)
		}
	}
	
	return tokenEvents, nil
}

// InitializeTokenFactory sets up the token factory with any required initial data.
func (tf *TokenFactory) InitializeTokenFactory(initialData map[string]interface{}) error {
	// Add any initialization logic needed for the token factory here.
	// This could include setting up initial tokens, metadata, etc.
	return nil
}

// GenerateBillID generates a unique ID for a bill token.
func GenerateBillID() string {
	return uuid.New().String()
}

