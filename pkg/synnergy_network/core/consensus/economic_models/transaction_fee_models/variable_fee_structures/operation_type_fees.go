package variable_fee_structures

import (
	"errors"
	"math/big"
	"sync"
)

// OperationType defines the type of operation on the blockchain
type OperationType string

const (
	// SimpleOperation represents a simple operation type
	SimpleOperation OperationType = "simple"
	// ComplexOperation represents a complex operation type
	ComplexOperation OperationType = "complex"
	// DataIntensiveOperation represents a data-intensive operation type
	DataIntensiveOperation OperationType = "data_intensive"
)

// OperationTypeFees manages the fee structure based on operation types
type OperationTypeFees struct {
	sync.Mutex
	baseFee          *big.Int
	operationFees    map[OperationType]*big.Int
	operationWeights map[OperationType]*big.Int
}

// NewOperationTypeFees initializes a new OperationTypeFees instance
func NewOperationTypeFees(baseFee int64) *OperationTypeFees {
	return &OperationTypeFees{
		baseFee:       big.NewInt(baseFee),
		operationFees: make(map[OperationType]*big.Int),
		operationWeights: map[OperationType]*big.Int{
			SimpleOperation:        big.NewInt(1),
			ComplexOperation:       big.NewInt(3),
			DataIntensiveOperation: big.NewInt(5),
		},
	}
}

// SetOperationFee sets the fee for a specific operation type
func (otf *OperationTypeFees) SetOperationFee(opType OperationType, fee int64) {
	otf.Lock()
	defer otf.Unlock()
	otf.operationFees[opType] = big.NewInt(fee)
}

// GetOperationFee retrieves the fee for a specific operation type
func (otf *OperationTypeFees) GetOperationFee(opType OperationType) (*big.Int, error) {
	otf.Lock()
	defer otf.Unlock()
	fee, exists := otf.operationFees[opType]
	if !exists {
		return nil, errors.New("operation type fee not set")
	}
	return new(big.Int).Set(fee), nil
}

// CalculateTotalFee calculates the total fee based on the operation type and its weight
func (otf *OperationTypeFees) CalculateTotalFee(opType OperationType) (*big.Int, error) {
	otf.Lock()
	defer otf.Unlock()
	baseFee := new(big.Int).Set(otf.baseFee)
	weight, exists := otf.operationWeights[opType]
	if !exists {
		return nil, errors.New("operation type weight not set")
	}
	totalFee := new(big.Int).Mul(baseFee, weight)
	return totalFee, nil
}

// SetOperationWeight sets the weight for a specific operation type
func (otf *OperationTypeFees) SetOperationWeight(opType OperationType, weight int64) {
	otf.Lock()
	defer otf.Unlock()
	otf.operationWeights[opType] = big.NewInt(weight)
}

// GetOperationWeight retrieves the weight for a specific operation type
func (otf *OperationTypeFees) GetOperationWeight(opType OperationType) (*big.Int, error) {
	otf.Lock()
	defer otf.Unlock()
	weight, exists := otf.operationWeights[opType]
	if !exists {
		return nil, errors.New("operation type weight not set")
	}
	return new(big.Int).Set(weight), nil
}

// GetBaseFee returns the current base fee
func (otf *OperationTypeFees) GetBaseFee() *big.Int {
	otf.Lock()
	defer otf.Unlock()
	return new(big.Int).Set(otf.baseFee)
}

// SetBaseFee sets a new base fee
func (otf *OperationTypeFees) SetBaseFee(baseFee int64) {
	otf.Lock()
	defer otf.Unlock()
	otf.baseFee = big.NewInt(baseFee)
}

