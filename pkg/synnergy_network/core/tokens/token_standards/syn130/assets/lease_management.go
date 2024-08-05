package assets

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/contracts"
	"github.com/synnergy_network/core/ledger"
	"github.com/synnergy_network/core/storage"
	"github.com/synnergy_network/utils"
)

// LeaseManagement handles the integration and management of lease agreements
type LeaseManagement struct {
	Leases map[string]LeaseAgreement
	Mutex  sync.Mutex
}

// LeaseAgreement represents a lease agreement linked to an asset
type LeaseAgreement struct {
	LeaseID         string
	AssetID         string
	Lessor          string
	Lessee          string
	Terms           string
	StartDate       time.Time
	EndDate         time.Time
	PaymentSchedule PaymentSchedule
	Status          string
}

// PaymentSchedule represents the payment schedule for a lease agreement
type PaymentSchedule struct {
	Interval    string
	Amount      float64
	NextPayment time.Time
}

// NewLeaseManagement creates a new instance of LeaseManagement
func NewLeaseManagement() *LeaseManagement {
	return &LeaseManagement{
		Leases: make(map[string]LeaseAgreement),
	}
}

// CreateLeaseAgreement creates a new lease agreement
func (lm *LeaseManagement) CreateLeaseAgreement(lease LeaseAgreement) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	if _, exists := lm.Leases[lease.LeaseID]; exists {
		return errors.New("lease agreement already exists")
	}

	lm.Leases[lease.LeaseID] = lease
	return nil
}

// UpdateLeaseAgreement updates an existing lease agreement
func (lm *LeaseManagement) UpdateLeaseAgreement(lease LeaseAgreement) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	if _, exists := lm.Leases[lease.LeaseID]; !exists {
		return errors.New("lease agreement not found")
	}

	lm.Leases[lease.LeaseID] = lease
	return nil
}

// GetLeaseAgreement retrieves a lease agreement by its ID
func (lm *LeaseManagement) GetLeaseAgreement(leaseID string) (LeaseAgreement, error) {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	lease, exists := lm.Leases[leaseID]
	if !exists {
		return LeaseAgreement{}, errors.New("lease agreement not found")
	}
	return lease, nil
}

// ProcessLeasePayments processes lease payments for all active leases
func (lm *LeaseManagement) ProcessLeasePayments() error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	for _, lease := range lm.Leases {
		if lease.Status == "active" && time.Now().After(lease.PaymentSchedule.NextPayment) {
			err := lm.processPayment(lease)
			if err != nil {
				return err
			}
			lease.PaymentSchedule.NextPayment = lm.calculateNextPayment(lease.PaymentSchedule)
			lm.Leases[lease.LeaseID] = lease
		}
	}
	return nil
}

// processPayment handles the payment processing for a lease agreement
func (lm *LeaseManagement) processPayment(lease LeaseAgreement) error {
	// Implement payment logic, e.g., transferring funds from lessee to lessor
	paymentRecord := map[string]interface{}{
		"leaseID":      lease.LeaseID,
		"amount":       lease.PaymentSchedule.Amount,
		"lessee":       lease.Lessee,
		"lessor":       lease.Lessor,
		"timestamp":    time.Now(),
		"status":       "completed",
	}

	paymentJSON, _ := json.Marshal(paymentRecord)
	return storage.Save("/payments/"+lease.LeaseID+".json", paymentJSON)
}

// calculateNextPayment calculates the next payment date based on the payment schedule interval
func (lm *LeaseManagement) calculateNextPayment(schedule PaymentSchedule) time.Time {
	switch schedule.Interval {
	case "monthly":
		return schedule.NextPayment.AddDate(0, 1, 0)
	case "yearly":
		return schedule.NextPayment.AddDate(1, 0, 0)
	default:
		return schedule.NextPayment.AddDate(0, 0, 1)
	}
}

// SaveLeases saves the lease data to persistent storage
func (lm *LeaseManagement) SaveLeases(storagePath string) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	data, err := json.Marshal(lm.Leases)
	if err != nil {
		return err
	}
	return storage.Save(storagePath, data)
}

// LoadLeases loads the lease data from persistent storage
func (lm *LeaseManagement) LoadLeases(storagePath string) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	data, err := storage.Load(storagePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &lm.Leases)
	if err != nil {
		return err
	}
	return nil
}

// NotifyLeaseExpiration notifies users of upcoming lease expirations
func (lm *LeaseManagement) NotifyLeaseExpiration() error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	for _, lease := range lm.Leases {
		if lease.Status == "active" && time.Now().After(lease.EndDate.AddDate(0, 0, -30)) {
			// Notify lessor and lessee about the upcoming expiration
			notification := map[string]interface{}{
				"leaseID":   lease.LeaseID,
				"lessee":    lease.Lessee,
				"lessor":    lease.Lessor,
				"endDate":   lease.EndDate,
				"timestamp": time.Now(),
			}
			notificationJSON, _ := json.Marshal(notification)
			storage.Save("/notifications/"+lease.LeaseID+".json", notificationJSON)
		}
	}
	return nil
}

// TerminateLease terminates a lease agreement
func (lm *LeaseManagement) TerminateLease(leaseID string) error {
	lm.Mutex.Lock()
	defer lm.Mutex.Unlock()

	lease, exists := lm.Leases[leaseID]
	if !exists {
		return errors.New("lease agreement not found")
	}

	lease.Status = "terminated"
	lm.Leases[leaseID] = lease

	// Notify lessor and lessee about the termination
	notification := map[string]interface{}{
		"leaseID":   lease.LeaseID,
		"lessee":    lease.Lessee,
		"lessor":    lease.Lessor,
		"timestamp": time.Now(),
		"status":    "terminated",
	}
	notificationJSON, _ := json.Marshal(notification)
	return storage.Save("/notifications/"+lease.LeaseID+"_terminated.json", notificationJSON)
}
