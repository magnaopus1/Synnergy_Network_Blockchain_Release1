package transaction_fee_models

import (
	"errors"
	"sync"
	"time"
)

// FeeModel defines the interface for different transaction fee models
type FeeModel interface {
	CalculateFee(transactionSize int, operationType string, networkCongestion int) (int, error)
	DistributeFees(totalFee int) error
}

// VariableFeeModel implements a variable transaction fee model
type VariableFeeModel struct {
	mu               sync.Mutex
	baseFee          int
	congestionFactor int
	sizeFactor       int
	operationFactors map[string]int
}

// NewVariableFeeModel creates a new VariableFeeModel with initial values
func NewVariableFeeModel(baseFee, congestionFactor, sizeFactor int, operationFactors map[string]int) *VariableFeeModel {
	return &VariableFeeModel{
		baseFee:          baseFee,
		congestionFactor: congestionFactor,
		sizeFactor:       sizeFactor,
		operationFactors: operationFactors,
	}
}

// CalculateFee calculates the fee for a transaction based on size, operation type, and network congestion
func (vfm *VariableFeeModel) CalculateFee(transactionSize int, operationType string, networkCongestion int) (int, error) {
	vfm.mu.Lock()
	defer vfm.mu.Unlock()

	opFactor, exists := vfm.operationFactors[operationType]
	if !exists {
		return 0, errors.New("invalid operation type")
	}

	fee := vfm.baseFee + (networkCongestion * vfm.congestionFactor) + (transactionSize * vfm.sizeFactor) + opFactor
	return fee, nil
}

// DistributeFees distributes the collected fees to different parties (e.g., miners, public goods)
func (vfm *VariableFeeModel) DistributeFees(totalFee int) error {
	// Implement the logic to distribute fees
	// For demonstration purposes, we'll just print the distribution
	minerFee := int(0.8 * float64(totalFee))
	publicGoodsFee := totalFee - minerFee

	// Simulate the distribution
	println("Distributed to miners:", minerFee)
	println("Distributed to public goods:", publicGoodsFee)

	return nil
}

// ZeroFeeModel implements a zero-fee transaction model under specific conditions
type ZeroFeeModel struct {
	mu                sync.Mutex
	allowedAccounts   map[string]bool
	thresholdAmount   int64
	allowedOperations map[string]bool
}

// NewZeroFeeModel creates a new ZeroFeeModel with initial values
func NewZeroFeeModel(thresholdAmount int64, allowedOperations []string) *ZeroFeeModel {
	allowedOps := make(map[string]bool)
	for _, op := range allowedOperations {
		allowedOps[op] = true
	}
	return &ZeroFeeModel{
		allowedAccounts:   make(map[string]bool),
		thresholdAmount:   thresholdAmount,
		allowedOperations: allowedOps,
	}
}

// AddAllowedAccount adds an account to the allowed zero-fee list
func (zfm *ZeroFeeModel) AddAllowedAccount(account string) {
	zfm.mu.Lock()
	defer zfm.mu.Unlock()
	zfm.allowedAccounts[account] = true
}

// RemoveAllowedAccount removes an account from the allowed zero-fee list
func (zfm *ZeroFeeModel) RemoveAllowedAccount(account string) {
	zfm.mu.Lock()
	defer zfm.mu.Unlock()
	delete(zfm.allowedAccounts, account)
}

// CalculateFee calculates the fee for a transaction, potentially zero if conditions are met
func (zfm *ZeroFeeModel) CalculateFee(transactionSize int, operationType string, networkCongestion int) (int, error) {
	zfm.mu.Lock()
	defer zfm.mu.Unlock()

	if !zfm.allowedOperations[operationType] {
		return 0, errors.New("operation not eligible for zero-fee")
	}

	if transactionSize <= int(zfm.thresholdAmount) {
		return 0, nil
	}

	return int(transactionSize), nil
}

// DistributeFees for ZeroFeeModel would normally be a no-op
func (zfm *ZeroFeeModel) DistributeFees(totalFee int) error {
	// ZeroFeeModel might not need to distribute fees, but this is a placeholder
	return nil
}

// FeeManager manages different fee models and applies the appropriate one based on conditions
type FeeManager struct {
	mu             sync.Mutex
	feeModels      map[string]FeeModel
	defaultFeeModel FeeModel
}

// NewFeeManager creates a new FeeManager with given fee models
func NewFeeManager(defaultFeeModel FeeModel) *FeeManager {
	return &FeeManager{
		feeModels:      make(map[string]FeeModel),
		defaultFeeModel: defaultFeeModel,
	}
}

// RegisterFeeModel registers a new fee model with a name
func (fm *FeeManager) RegisterFeeModel(name string, model FeeModel) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.feeModels[name] = model
}

// CalculateFee calculates the fee using the appropriate model
func (fm *FeeManager) CalculateFee(modelName string, transactionSize int, operationType string, networkCongestion int) (int, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	model, exists := fm.feeModels[modelName]
	if !exists {
		model = fm.defaultFeeModel
	}

	return model.CalculateFee(transactionSize, operationType, networkCongestion)
}

// DistributeFees distributes the fees using the appropriate model
func (fm *FeeManager) DistributeFees(modelName string, totalFee int) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	model, exists := fm.feeModels[modelName]
	if !exists {
		model = fm.defaultFeeModel
	}

	return model.DistributeFees(totalFee)
}

func main() {
	// Example usage
	defaultModel := NewVariableFeeModel(10, 2, 1, map[string]int{
		"transfer": 5,
		"stake":    10,
	})
	zeroFeeModel := NewZeroFeeModel(100, []string{"transfer", "vote"})

	fm := NewFeeManager(defaultModel)
	fm.RegisterFeeModel("zeroFee", zeroFeeModel)

	// Calculate and distribute fees
	fee, err := fm.CalculateFee("zeroFee", 50, "transfer", 5)
	if err != nil {
		println("Error:", err.Error())
	} else {
		println("Calculated Fee:", fee)
		err = fm.DistributeFees("zeroFee", fee)
		if err != nil {
			println("Error distributing fees:", err.Error())
		}
	}
}
