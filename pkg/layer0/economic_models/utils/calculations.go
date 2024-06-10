package utils

import (
	"errors"
	"math"
	"sync"
)

// FeeCalculator is the interface that defines the methods for calculating transaction fees
type FeeCalculator interface {
	CalculateNetworkCongestionFee(networkCongestion int) int
	CalculateTransactionSizeFee(transactionSize int) int
	CalculateOperationTypeFee(operationType string) (int, error)
	CalculateTotalFee(networkCongestion, transactionSize int, operationType string) (int, error)
}

// TransactionFeeCalculator is a struct that implements the FeeCalculator interface
type TransactionFeeCalculator struct {
	mu              sync.Mutex
	baseFee         int
	congestionFactor int
	sizeFactor      int
	operationFactors map[string]int
}

// NewTransactionFeeCalculator creates a new TransactionFeeCalculator with initial values
func NewTransactionFeeCalculator(baseFee, congestionFactor, sizeFactor int, operationFactors map[string]int) *TransactionFeeCalculator {
	return &TransactionFeeCalculator{
		baseFee:          baseFee,
		congestionFactor: congestionFactor,
		sizeFactor:       sizeFactor,
		operationFactors: operationFactors,
	}
}

// CalculateNetworkCongestionFee calculates the fee based on network congestion
func (tfc *TransactionFeeCalculator) CalculateNetworkCongestionFee(networkCongestion int) int {
	tfc.mu.Lock()
	defer tfc.mu.Unlock()
	return networkCongestion * tfc.congestionFactor
}

// CalculateTransactionSizeFee calculates the fee based on the transaction size
func (tfc *TransactionFeeCalculator) CalculateTransactionSizeFee(transactionSize int) int {
	tfc.mu.Lock()
	defer tfc.mu.Unlock()
	return transactionSize * tfc.sizeFactor
}

// CalculateOperationTypeFee calculates the fee based on the operation type
func (tfc *TransactionFeeCalculator) CalculateOperationTypeFee(operationType string) (int, error) {
	tfc.mu.Lock()
	defer tfc.mu.Unlock()
	opFactor, exists := tfc.operationFactors[operationType]
	if !exists {
		return 0, errors.New("invalid operation type")
	}
	return opFactor, nil
}

// CalculateTotalFee calculates the total fee for a transaction
func (tfc *TransactionFeeCalculator) CalculateTotalFee(networkCongestion, transactionSize int, operationType string) (int, error) {
	tfc.mu.Lock()
	defer tfc.mu.Unlock()

	networkFee := tfc.CalculateNetworkCongestionFee(networkCongestion)
	sizeFee := tfc.CalculateTransactionSizeFee(transactionSize)
	opTypeFee, err := tfc.CalculateOperationTypeFee(operationType)
	if err != nil {
		return 0, err
	}

	totalFee := tfc.baseFee + networkFee + sizeFee + opTypeFee
	return totalFee, nil
}

// Helper functions for various calculations
// HashWithSalt applies a hashing function with salt for added security
func HashWithSalt(input, salt string) string {
	// Implement the hashing logic here, for example using Scrypt
	// This is a placeholder
	hashedValue := scryptKey([]byte(input), []byte(salt))
	return hashedValue
}

// CalculateStakeWeight calculates the stake weight based on the user's stake
func CalculateStakeWeight(userStake, totalStake int64) float64 {
	return float64(userStake) / float64(totalStake)
}

// CalculateTransactionImportance calculates the importance of a transaction
func CalculateTransactionImportance(transactionValue, senderReputation, transactionUrgency int) float64 {
	importance := math.Log(float64(transactionValue+1)) * (float64(senderReputation) / 100.0) * math.Sqrt(float64(transactionUrgency))
	return importance
}

// Helper function for Scrypt hashing
func scryptKey(password, salt []byte) string {
	// Placeholder for Scrypt hashing
	// Implement Scrypt key derivation function here
	return string(password) + string(salt)
}
