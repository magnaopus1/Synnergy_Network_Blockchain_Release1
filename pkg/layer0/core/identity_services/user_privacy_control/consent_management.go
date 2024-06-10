package consentmanagement

import (
	"encoding/json"
	"errors"
	"sync"
	"synthron_blockchain_final/pkg/layer0/core/identity_services/privacy_management/blockchain"

	"github.com/google/uuid"
)

// ConsentDetail struct defines the structure for user consent data.
type ConsentDetail struct {
	ConsentID       string `json:"consent_id"`
	UserID          string `json:"user_id"`
	DataCategory    string `json:"data_category"`
	Purpose         string `json:"purpose"`
	ConsentDuration string `json:"consent_duration"`
	ConsentActive   bool   `json:"consent_active"`
}

// ConsentManager handles consent-related operations.
type ConsentManager struct {
	mutex sync.Mutex
}

// NewConsentManager creates a new instance of ConsentManager.
func NewConsentManager() *ConsentManager {
	return &ConsentManager{}
}

// RecordConsent captures and records user consent in the blockchain.
func (cm *ConsentManager) RecordConsent(userID, dataCategory, purpose, duration string) (string, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	consent := ConsentDetail{
		ConsentID:       uuid.NewString(),
		UserID:          userID,
		DataCategory:    dataCategory,
		Purpose:         purpose,
		ConsentDuration: duration,
		ConsentActive:   true,
	}

	data, err := json.Marshal(consent)
	if err != nil {
		return "", err
	}

	// Simulate storing consent in the blockchain.
	if err := blockchain.StoreData(consent.ConsentID, data); err != nil {
		return "", err
	}

	return consent.ConsentID, nil
}

// UpdateConsent allows users to update their existing consent preferences.
func (cm *ConsentManager) UpdateConsent(consentID string, active bool) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	data, err := blockchain.RetrieveData(consentID)
	if err != nil {
		return err
	}

	var consent ConsentDetail
	if err := json.Unmarshal(data, &consent); err != nil {
		return err
	}

	consent.ConsentActive = active

	updatedData, err := json.Marshal(consent)
	if err != nil {
		return err
	}

	// Update the consent data on the blockchain.
	return blockchain.UpdateData(consent.ConsentID, updatedData)
}

// VerifyConsent checks the active status of consent for a given ID.
func (cm *ConsentManager) VerifyConsent(consentID string) (bool, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	data, err := blockchain.RetrieveData(consentID)
	if err != nil {
		return false, err
	}

	var consent ConsentDetail
	if err := json.Unmarshal(data, &consent); err != nil {
		return false, err
	}

	return consent.ConsentActive, nil
}

