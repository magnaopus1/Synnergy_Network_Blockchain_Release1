package smart_contracts

import (
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"golang.org/x/crypto/scrypt"
)

// FairBillAllocation defines the structure of a fair bill allocation
type FairBillAllocation struct {
	AllocationID   string    `json:"allocation_id"`
	BillID         string    `json:"bill_id"`
	TotalAmount    *big.Int  `json:"total_amount"`
	AllocatedAmount *big.Int `json:"allocated_amount"`
	Allocated      bool      `json:"allocated"`
	AllocationDate time.Time `json:"allocation_date"`
	Metadata       string    `json:"metadata"`
}

// FairBillAllocationDB manages the database operations for FairBillAllocation
type FairBillAllocationDB struct {
	DB *leveldb.DB
}

// NewFairBillAllocationDB initializes a new database for FairBillAllocation
func NewFairBillAllocationDB(dbPath string) (*FairBillAllocationDB, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &FairBillAllocationDB{DB: db}, nil
}

// CloseDB closes the database connection
func (fadb *FairBillAllocationDB) CloseDB() error {
	return fadb.DB.Close()
}

// AddFairBillAllocation adds a new fair bill allocation entry
func (fadb *FairBillAllocationDB) AddFairBillAllocation(allocation FairBillAllocation) error {
	if err := fadb.ValidateFairBillAllocation(allocation); err != nil {
		return err
	}
	data, err := json.Marshal(allocation)
	if err != nil {
		return err
	}
	return fadb.DB.Put([]byte("fair_bill_allocation_"+allocation.AllocationID), data, nil)
}

// GetFairBillAllocation retrieves a fair bill allocation entry by its ID
func (fadb *FairBillAllocationDB) GetFairBillAllocation(allocationID string) (*FairBillAllocation, error) {
	data, err := fadb.DB.Get([]byte("fair_bill_allocation_"+allocationID), nil)
	if err != nil {
		return nil, err
	}
	var allocation FairBillAllocation
	if err := json.Unmarshal(data, &allocation); err != nil {
		return nil, err
	}
	return &allocation, nil
}

// GetAllFairBillAllocations retrieves all fair bill allocation entries
func (fadb *FairBillAllocationDB) GetAllFairBillAllocations() ([]FairBillAllocation, error) {
	var allocations []FairBillAllocation
	iter := fadb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var allocation FairBillAllocation
		if err := json.Unmarshal(iter.Value(), &allocation); err != nil {
			return nil, err
		}
		allocations = append(allocations, allocation)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return allocations, nil
}

// ValidateFairBillAllocation validates the structure of a fair bill allocation
func (fadb *FairBillAllocationDB) ValidateFairBillAllocation(allocation FairBillAllocation) error {
	if allocation.AllocationID == "" {
		return errors.New("allocation ID must be provided")
	}
	if allocation.BillID == "" {
		return errors.New("bill ID must be provided")
	}
	if allocation.TotalAmount == nil || allocation.TotalAmount.Sign() <= 0 {
		return errors.New("total amount must be greater than zero")
	}
	if allocation.AllocatedAmount == nil || allocation.AllocatedAmount.Sign() < 0 {
		return errors.New("allocated amount must not be negative")
	}
	return nil
}

// UpdateFairBillAllocation updates an existing fair bill allocation entry
func (fadb *FairBillAllocationDB) UpdateFairBillAllocation(allocation FairBillAllocation) error {
	if _, err := fadb.GetFairBillAllocation(allocation.AllocationID); err != nil {
		return err
	}
	if err := fadb.ValidateFairBillAllocation(allocation); err != nil {
		return err
	}
	data, err := json.Marshal(allocation)
	if err != nil {
		return err
	}
	return fadb.DB.Put([]byte("fair_bill_allocation_"+allocation.AllocationID), data, nil)
}

// DeleteFairBillAllocation deletes a fair bill allocation entry by its ID
func (fadb *FairBillAllocationDB) DeleteFairBillAllocation(allocationID string) error {
	return fadb.DB.Delete([]byte("fair_bill_allocation_"+allocationID), nil)
}

// AllocateBillAmount allocates the bill amount fairly
func (fadb *FairBillAllocationDB) AllocateBillAmount(billID string, totalAmount *big.Int) error {
	allocationID := generateAllocationID(billID)
	allocation := FairBillAllocation{
		AllocationID:   allocationID,
		BillID:         billID,
		TotalAmount:    totalAmount,
		AllocatedAmount: new(big.Int).Set(totalAmount),
		Allocated:      true,
		AllocationDate: time.Now(),
		Metadata:       "",
	}
	return fadb.AddFairBillAllocation(allocation)
}

// generateAllocationID generates a unique allocation ID based on the bill ID
func generateAllocationID(billID string) string {
	// Implement a unique ID generation logic
	hashedID, _ := hashData(billID + time.Now().String())
	return hashedID
}

// hashData generates a hash of the data using scrypt with a salt
func hashData(data string) (string, error) {
	salt := []byte("somesalt") // Ensure to use a proper salt generation mechanism
	dk, err := scrypt.Key([]byte(data), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return string(dk), nil
}
