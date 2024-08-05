package transactions

import (
    "errors"
    "sync"
    "time"
)

// OwnershipTransferType defines the type of ownership transfer
type OwnershipTransferType int

const (
    DirectTransfer OwnershipTransferType = iota
    SecuredTransfer
)

// DebtInstrument represents a debt instrument
type DebtInstrument struct {
    ID            string
    Owner         string
    Principal     float64
    InterestRate  float64
    LastUpdated   time.Time
    Status        string
}

// OwnershipTransferRecord represents a record of ownership transfer
type OwnershipTransferRecord struct {
    InstrumentID string
    From         string
    To           string
    TransferType OwnershipTransferType
    Timestamp    time.Time
}

// DebtManager manages debt instruments and their ownership transfers
type DebtManager struct {
    debts                map[string]*DebtInstrument
    ownershipTransfers   []OwnershipTransferRecord
    mu                   sync.RWMutex
}

// NewDebtManager creates a new DebtManager instance
func NewDebtManager() *DebtManager {
    return &DebtManager{
        debts: make(map[string]*DebtInstrument),
    }
}

// AddDebtInstrument adds a new debt instrument to the manager
func (dm *DebtManager) AddDebtInstrument(id, owner string, principal, interestRate float64) {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    dm.debts[id] = &DebtInstrument{
        ID:           id,
        Owner:        owner,
        Principal:    principal,
        InterestRate: interestRate,
        LastUpdated:  time.Now(),
        Status:       "active",
    }
}

// TransferOwnership transfers ownership of a debt instrument
func (dm *DebtManager) TransferOwnership(instrumentID, newOwner string, transferType OwnershipTransferType) error {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    debt, exists := dm.debts[instrumentID]
    if !exists {
        return errors.New("debt instrument not found")
    }

    if debt.Status != "active" {
        return errors.New("ownership transfer is only allowed for active debt instruments")
    }

    transferRecord := OwnershipTransferRecord{
        InstrumentID: instrumentID,
        From:         debt.Owner,
        To:           newOwner,
        TransferType: transferType,
        Timestamp:    time.Now(),
    }

    dm.ownershipTransfers = append(dm.ownershipTransfers, transferRecord)
    debt.Owner = newOwner
    debt.LastUpdated = time.Now()

    return nil
}

// GetDebtInstrument returns details of a debt instrument by ID
func (dm *DebtManager) GetDebtInstrument(id string) (*DebtInstrument, error) {
    dm.mu.RLock()
    defer dm.mu.RUnlock()

    debt, exists := dm.debts[id]
    if !exists {
        return nil, errors.New("debt instrument not found")
    }

    return debt, nil
}

// GetOwnershipTransferRecords returns the ownership transfer records for a given debt instrument
func (dm *DebtManager) GetOwnershipTransferRecords(instrumentID string) ([]OwnershipTransferRecord, error) {
    dm.mu.RLock()
    defer dm.mu.RUnlock()

    records := []OwnershipTransferRecord{}
    for _, record := range dm.ownershipTransfers {
        if record.InstrumentID == instrumentID {
            records = append(records, record)
        }
    }

    if len(records) == 0 {
        return nil, errors.New("no ownership transfer records found for the given instrument ID")
    }

    return records, nil
}

// GetOwnershipHistory returns the ownership history of a given debt instrument
func (dm *DebtManager) GetOwnershipHistory(instrumentID string) ([]OwnershipTransferRecord, error) {
    return dm.GetOwnershipTransferRecords(instrumentID)
}

// ValidateTransfer ensures that the transfer complies with all necessary rules and regulations
func (dm *DebtManager) ValidateTransfer(instrumentID, newOwner string, transferType OwnershipTransferType) error {
    dm.mu.RLock()
    defer dm.mu.RUnlock()

    debt, exists := dm.debts[instrumentID]
    if !exists {
        return errors.New("debt instrument not found")
    }

    if debt.Status != "active" {
        return errors.New("only active debt instruments can be transferred")
    }

    // Additional validation logic (e.g., regulatory compliance checks) can be added here
    // Example: Checking if the new owner meets certain criteria
    // if !isValidNewOwner(newOwner) {
    //     return errors.New("the new owner does not meet the required criteria for ownership transfer")
    // }

    return nil
}

// RecordOwnershipTransfer records the details of an ownership transfer
func (dm *DebtManager) RecordOwnershipTransfer(record OwnershipTransferRecord) {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    dm.ownershipTransfers = append(dm.ownershipTransfers, record)
}

// RevertOwnershipTransfer reverts an ownership transfer in case of errors or disputes
func (dm *DebtManager) RevertOwnershipTransfer(instrumentID string) error {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    if len(dm.ownershipTransfers) == 0 {
        return errors.New("no ownership transfers found to revert")
    }

    lastTransfer := dm.ownershipTransfers[len(dm.ownershipTransfers)-1]
    if lastTransfer.InstrumentID != instrumentID {
        return errors.New("the latest ownership transfer record does not match the given instrument ID")
    }

    debt, exists := dm.debts[instrumentID]
    if !exists {
        return errors.New("debt instrument not found")
    }

    debt.Owner = lastTransfer.From
    debt.LastUpdated = time.Now()
    dm.ownershipTransfers = dm.ownershipTransfers[:len(dm.ownershipTransfers)-1]

    return nil
}

// GetDebtInstrumentsByOwner returns a list of debt instruments owned by a specific owner
func (dm *DebtManager) GetDebtInstrumentsByOwner(owner string) ([]*DebtInstrument, error) {
    dm.mu.RLock()
    defer dm.mu.RUnlock()

    ownedDebts := []*DebtInstrument{}
    for _, debt := range dm.debts {
        if debt.Owner == owner {
            ownedDebts = append(ownedDebts, debt)
        }
    }

    if len(ownedDebts) == 0 {
        return nil, errors.New("no debt instruments found for the given owner")
    }

    return ownedDebts, nil
}
