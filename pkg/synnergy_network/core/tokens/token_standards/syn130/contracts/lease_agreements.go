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

// LeaseAgreement represents a lease agreement linked to an asset
type TangibleAssetLeaseAgreement struct {
	AgreementID     string
	TangibleAssetID         string
	Lessor          string
	Lessee          string
	StartDate       time.Time
	EndDate         time.Time
	PaymentSchedule map[string]float64 // Due dates and amounts
	Terms           string
	Status          string
	CreationDate    time.Time
	ModificationDate time.Time
}

// LeaseManagement handles the integration and management of lease agreements
type TangibleAssetLeaseManagement struct {
	Agreements map[string]TangibleAssetLeaseAgreement
	Mutex      sync.Mutex
}

// NewLeaseManagement creates a new instance of LeaseManagement
func NewLeaseManagement() *TangibleAssetLeaseManagement {
	return &TangibleAssetLeaseManagement{
		Agreements: make(map[string]LeaseAgreement),
	}
}

// CreateLeaseAgreement creates a new lease agreement
func (lm *TangibleAssetLeaseManagement) CreateLeaseAgreement(agreement LeaseAgreement) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	if _, exists := lm.Agreements[agreement.AgreementID]; exists {
		return errors.New("lease agreement already exists")
	}

	agreement.CreationDate = time.Now()
	agreement.ModificationDate = time.Now()
	lm.Agreements[agreement.AgreementID] = agreement
	return nil
}

// UpdateLeaseAgreement updates an existing lease agreement
func (lm *TangibleAssetLeaseManagement) UpdateLeaseAgreement(agreement LeaseAgreement) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	if _, exists := lm.Agreements[agreement.AgreementID]; !exists {
		return errors.New("lease agreement not found")
	}

	agreement.ModificationDate = time.Now()
	lm.Agreements[agreement.AgreementID] = agreement
	return nil
}

// GetLeaseAgreement retrieves a lease agreement by its ID
func (lm *TangibleAssetLeaseManagement) GetLeaseAgreement(agreementID string) (LeaseAgreement, error) {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	agreement, exists := lm.Agreements[agreementID]
	if !exists {
		return LeaseAgreement{}, errors.New("lease agreement not found")
	}
	return agreement, nil
}

// SaveAgreements saves the lease agreement data to persistent storage
func (lm *TangibleAssetLeaseManagement) SaveAgreements(storagePath string) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	data, err := json.Marshal(lm.Agreements)
	if err != nil {
		return err
	}
	return storage.Save(storagePath, data)
}

// LoadAgreements loads the lease agreement data from persistent storage
func (lm *TangibleAssetLeaseManagement) LoadAgreements(storagePath string) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	data, err := storage.Load(storagePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &lm.Agreements)
	if err != nil {
		return err
	}
	return nil
}

// ProcessLeasePayment processes a lease payment
func (lm *TangibleAssetLeaseManagement) ProcessLeasePayment(agreementID string, paymentDate time.Time, amount float64) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	agreement, exists := lm.Agreements[agreementID]
	if !exists {
		return errors.New("lease agreement not found")
	}

	if dueAmount, due := agreement.PaymentSchedule[paymentDate.Format("2006-01-02")]; due {
		if dueAmount != amount {
			return errors.New("payment amount does not match due amount")
		}
		delete(agreement.PaymentSchedule, paymentDate.Format("2006-01-02"))
		agreement.ModificationDate = time.Now()
		lm.Agreements[agreementID] = agreement

		// Record transaction in the ledger
		transaction := ledger.Transaction{
			ID:        utils.GenerateUUID(),
			Timestamp: time.Now(),
			From:      agreement.Lessee,
			To:        agreement.Lessor,
			Amount:    amount,
			AssetID:   agreement.AssetID,
			Type:      "lease_payment",
		}
		ledger.RecordTransaction(transaction)

		// Notify lessee and lessor
		lm.notifyPaymentProcessed(agreement.Lessee, agreement.Lessor, amount, agreementID, paymentDate)

		return nil
	}

	return errors.New("no payment due on this date")
}

// TerminateLeaseAgreement terminates a lease agreement
func (lm *LeaseManagement) TerminateLeaseAgreement(agreementID string) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	agreement, exists := lm.Agreements[agreementID]
	if !exists {
		return errors.New("lease agreement not found")
	}

	agreement.Status = "terminated"
	agreement.ModificationDate = time.Now()
	lm.Agreements[agreementID] = agreement

	// Notify lessor and lessee about the termination
	lm.notifyAgreementTerminated(agreement.Lessee, agreement.Lessor, agreementID)

	return nil
}

// notifyPaymentProcessed notifies parties about a processed payment
func (lm *LeaseManagement) notifyPaymentProcessed(lessee, lessor string, amount float64, agreementID string, paymentDate time.Time) {
	notification := map[string]interface{}{
		"agreementID":  agreementID,
		"lessee":       lessee,
		"lessor":       lessor,
		"amount":       amount,
		"paymentDate":  paymentDate,
		"timestamp":    time.Now(),
		"status":       "payment_processed",
	}
	notificationJSON, _ := json.Marshal(notification)
	storage.Save("/notifications/"+agreementID+"_payment.json", notificationJSON)
}

// notifyAgreementTerminated notifies parties about a terminated agreement
func (lm *LeaseManagement) notifyAgreementTerminated(lessee, lessor string, agreementID string) {
	notification := map[string]interface{}{
		"agreementID":  agreementID,
		"lessee":       lessee,
		"lessor":       lessor,
		"timestamp":    time.Now(),
		"status":       "terminated",
	}
	notificationJSON, _ := json.Marshal(notification)
	storage.Save("/notifications/"+agreementID+"_terminated.json", notificationJSON)
}
