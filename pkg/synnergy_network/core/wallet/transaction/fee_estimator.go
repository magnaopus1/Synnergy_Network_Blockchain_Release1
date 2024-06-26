package transaction

import (
	"errors"
	"math"
	"sync"
)

// FeeEstimator is responsible for estimating the transaction fees.
type FeeEstimator struct {
	baseFee       float64
	dynamicFeeMap map[int]float64
	mu            sync.RWMutex
}

// NewFeeEstimator initializes and returns a new FeeEstimator.
func NewFeeEstimator(baseFee float64) *FeeEstimator {
	return &FeeEstimator{
		baseFee:       baseFee,
		dynamicFeeMap: make(map[int]float64),
	}
}

// SetBaseFee sets the base fee for transactions.
func (fe *FeeEstimator) SetBaseFee(baseFee float64) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.baseFee = baseFee
}

// GetBaseFee returns the current base fee.
func (fe *FeeEstimator) GetBaseFee() float64 {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return fe.baseFee
}

// AddDynamicFee adds a dynamic fee for a given block height.
func (fe *FeeEstimator) AddDynamicFee(blockHeight int, fee float64) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.dynamicFeeMap[blockHeight] = fee
}

// GetDynamicFee returns the dynamic fee for a given block height.
func (fe *FeeEstimator) GetDynamicFee(blockHeight int) (float64, error) {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	fee, exists := fe.dynamicFeeMap[blockHeight]
	if !exists {
		return 0, errors.New("dynamic fee not found for the given block height")
	}
	return fee, nil
}

// EstimateFee estimates the fee for a transaction based on size and current network conditions.
func (fe *FeeEstimator) EstimateFee(transactionSize int, blockHeight int) (float64, error) {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	dynamicFee, err := fe.GetDynamicFee(blockHeight)
	if err != nil {
		dynamicFee = fe.baseFee
	}

	// Estimate fee based on transaction size and dynamic fee
	estimatedFee := dynamicFee * float64(transactionSize)
	return math.Max(estimatedFee, fe.baseFee), nil
}

// DynamicFeeAdjustment dynamically adjusts the fee based on network congestion and user-defined parameters.
func (fe *FeeEstimator) DynamicFeeAdjustment(currentBlockHeight int, networkCongestion float64) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	adjustmentFactor := 1 + networkCongestion
	for blockHeight, fee := range fe.dynamicFeeMap {
		if blockHeight >= currentBlockHeight {
			fe.dynamicFeeMap[blockHeight] = fee * adjustmentFactor
		}
	}
}

// ValidateTransactionFee validates if the provided transaction fee meets the minimum requirements.
func (fe *FeeEstimator) ValidateTransactionFee(providedFee float64, transactionSize int, blockHeight int) (bool, error) {
	estimatedFee, err := fe.EstimateFee(transactionSize, blockHeight)
	if err != nil {
		return false, err
	}
	return providedFee >= estimatedFee, nil
}

// GetEstimatedFees returns the estimated fees for the next 'n' blocks.
func (fe *FeeEstimator) GetEstimatedFees(startBlockHeight, numBlocks int) ([]float64, error) {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	estimatedFees := make([]float64, numBlocks)
	for i := 0; i < numBlocks; i++ {
		blockHeight := startBlockHeight + i
		fee, err := fe.GetDynamicFee(blockHeight)
		if err != nil {
			fee = fe.baseFee
		}
		estimatedFees[i] = fee
	}
	return estimatedFees, nil
}

func main() {
	// Example usage
	fe := NewFeeEstimator(0.01)
	fe.AddDynamicFee(100, 0.02)
	fe.AddDynamicFee(200, 0.03)

	baseFee := fe.GetBaseFee()
	println("Base fee:", baseFee)

	fee, err := fe.GetDynamicFee(100)
	if err != nil {
		panic(err)
	}
	println("Dynamic fee for block 100:", fee)

	estimatedFee, err := fe.EstimateFee(250, 100)
	if err != nil {
		panic(err)
	}
	println("Estimated fee for a transaction of size 250 bytes at block 100:", estimatedFee)

	isValid, err := fe.ValidateTransactionFee(0.05, 250, 100)
	if err != nil {
		panic(err)
	}
	if isValid {
		println("The provided fee is valid.")
	} else {
		println("The provided fee is not sufficient.")
	}

	fe.DynamicFeeAdjustment(150, 0.2)
	adjustedFee, err := fe.GetDynamicFee(200)
	if err != nil {
		panic(err)
	}
	println("Adjusted dynamic fee for block 200:", adjustedFee)

	estimatedFees, err := fe.GetEstimatedFees(100, 5)
	if err != nil {
		panic(err)
	}
	println("Estimated fees for the next 5 blocks starting from block 100:")
	for i, fee := range estimatedFees {
		println("Block", 100+i, "Fee:", fee)
	}
}
