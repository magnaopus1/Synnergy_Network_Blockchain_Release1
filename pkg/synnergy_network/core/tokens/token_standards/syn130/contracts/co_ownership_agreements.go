package contracts

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/ledger"
	"github.com/synnergy_network/core/storage"
	"github.com/synnergy_network/utils"
)

// CoOwnershipAgreement represents a co-ownership agreement linked to an asset
type CoOwnershipAgreement struct {
	AgreementID     string
	TangibleAssetID         string
	Owners          map[string]float64 // Owner address to ownership percentage
	CreationDate    time.Time
	ModificationDate time.Time
	Terms           string
	Status          string
}

// CoOwnershipManagement handles the integration and management of co-ownership agreements
type CoOwnershipManagement struct {
	Agreements map[string]CoOwnershipAgreement
	Mutex      sync.Mutex
}

// NewCoOwnershipManagement creates a new instance of CoOwnershipManagement
func NewCoOwnershipManagement() *CoOwnershipManagement {
	return &CoOwnershipManagement{
		Agreements: make(map[string]CoOwnershipAgreement),
	}
}

// CreateCoOwnershipAgreement creates a new co-ownership agreement
func (com *CoOwnershipManagement) CreateCoOwnershipAgreement(agreement CoOwnershipAgreement) error {
	com.Mutex.Lock()
	defer com.Mutex.Unlock()

	if _, exists := com.Agreements[agreement.AgreementID]; exists {
		return errors.New("co-ownership agreement already exists")
	}

	com.Agreements[agreement.AgreementID] = agreement
	return nil
}

// UpdateCoOwnershipAgreement updates an existing co-ownership agreement
func (com *CoOwnershipManagement) UpdateCoOwnershipAgreement(agreement CoOwnershipAgreement) error {
	com.Mutex.Lock()
	defer com.Mutex.Unlock()

	if _, exists := com.Agreements[agreement.AgreementID]; !exists {
		return errors.New("co-ownership agreement not found")
	}

	agreement.ModificationDate = time.Now()
	com.Agreements[agreement.AgreementID] = agreement
	return nil
}

// GetCoOwnershipAgreement retrieves a co-ownership agreement by its ID
func (com *CoOwnershipManagement) GetCoOwnershipAgreement(agreementID string) (CoOwnershipAgreement, error) {
	com.Mutex.Lock()
	defer com.Mutex.Unlock()

	agreement, exists := com.Agreements[agreementID]
	if !exists {
		return CoOwnershipAgreement{}, errors.New("co-ownership agreement not found")
	}
	return agreement, nil
}

// SaveAgreements saves the co-ownership agreement data to persistent storage
func (com *CoOwnershipManagement) SaveAgreements(storagePath string) error {
	com.Mutex.Lock()
	defer com.Mutex.Unlock()

	data, err := json.Marshal(com.Agreements)
	if err != nil {
		return err
	}
	return storage.Save(storagePath, data)
}

// LoadAgreements loads the co-ownership agreement data from persistent storage
func (com *CoOwnershipManagement) LoadAgreements(storagePath string) error {
	com.Mutex.Lock()
	defer com.Mutex.Unlock()

	data, err := storage.Load(storagePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &com.Agreements)
	if err != nil {
		return err
	}
	return nil
}

// TransferOwnership transfers ownership from one party to another
func (com *CoOwnershipManagement) TransferOwnership(agreementID, fromOwner, toOwner string, percentage float64) error {
	com.Mutex.Lock()
	defer com.Mutex.Unlock()

	agreement, exists := com.Agreements[agreementID]
	if !exists {
		return errors.New("co-ownership agreement not found")
	}

	if agreement.Owners[fromOwner] < percentage {
		return errors.New("insufficient ownership percentage")
	}

	agreement.Owners[fromOwner] -= percentage
	if agreement.Owners[fromOwner] == 0 {
		delete(agreement.Owners, fromOwner)
	}
	agreement.Owners[toOwner] += percentage
	agreement.ModificationDate = time.Now()
	com.Agreements[agreementID] = agreement

	return nil
}

// TerminateAgreement terminates a co-ownership agreement
func (com *CoOwnershipManagement) TerminateAgreement(agreementID string) error {
	com.Mutex.Lock()
	defer com.Mutex.Unlock()

	agreement, exists := com.Agreements[agreementID]
	if !exists {
		return errors.New("co-ownership agreement not found")
	}

	agreement.Status = "terminated"
	agreement.ModificationDate = time.Now()
	com.Agreements[agreementID] = agreement

	// Notify all owners about the termination
	notification := map[string]interface{}{
		"agreementID": agreement.AgreementID,
		"owners":      agreement.Owners,
		"timestamp":   time.Now(),
		"status":      "terminated",
	}
	notificationJSON, _ := json.Marshal(notification)
	return storage.Save("/notifications/"+agreement.AgreementID+"_terminated.json", notificationJSON)
}

// NotifyOwnershipChanges notifies owners about significant changes in the ownership structure
func (com *CoOwnershipManagement) NotifyOwnershipChanges(agreementID string) error {
	com.Mutex.Lock()
	defer com.Mutex.Unlock()

	agreement, exists := com.Agreements[agreementID]
	if !exists {
		return errors.New("co-ownership agreement not found")
	}

	// Notify all owners about the changes
	notification := map[string]interface{}{
		"agreementID": agreement.AgreementID,
		"owners":      agreement.Owners,
		"timestamp":   time.Now(),
		"status":      "updated",
	}
	notificationJSON, _ := json.Marshal(notification)
	return storage.Save("/notifications/"+agreement.AgreementID+"_updated.json", notificationJSON)
}
