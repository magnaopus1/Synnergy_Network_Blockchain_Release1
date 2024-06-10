package variable_fee_structures

import (
	"math/big"
	"sync"
	"time"
)

// FeeAdjustment manages the dynamic adjustment of transaction fees based on various factors.
type FeeAdjustment struct {
	sync.Mutex
	baseFee       *big.Int
	congestionFee *big.Int
	sizeFee       *big.Int
	typeFee       *big.Int
	lastUpdated   time.Time
}

// NewFeeAdjustment initializes a new FeeAdjustment instance.
func NewFeeAdjustment(baseFee int64) *FeeAdjustment {
	return &FeeAdjustment{
		baseFee:       big.NewInt(baseFee),
		congestionFee: big.NewInt(0),
		sizeFee:       big.NewInt(0),
		typeFee:       big.NewInt(0),
		lastUpdated:   time.Now(),
	}
}

// UpdateFees dynamically adjusts the fees based on network conditions.
func (fa *FeeAdjustment) UpdateFees(networkCongestion int64, avgTransactionSize int64, transactionType string) {
	fa.Lock()
	defer fa.Unlock()

	// Adjust congestion fee based on network congestion
	if networkCongestion > 80 {
		fa.congestionFee = big.NewInt(networkCongestion / 10)
	} else {
		fa.congestionFee = big.NewInt(0)
	}

	// Adjust size fee based on average transaction size
	if avgTransactionSize > 1024 {
		fa.sizeFee = big.NewInt(avgTransactionSize / 1024)
	} else {
		fa.sizeFee = big.NewInt(0)
	}

	// Adjust type fee based on transaction type
	switch transactionType {
	case "complex":
		fa.typeFee = big.NewInt(2)
	case "simple":
		fa.typeFee = big.NewInt(1)
	default:
		fa.typeFee = big.NewInt(0)
	}

	fa.lastUpdated = time.Now()
}

// CalculateFee calculates the total fee for a transaction.
func (fa *FeeAdjustment) CalculateFee(transactionSize int64, transactionType string) *big.Int {
	fa.Lock()
	defer fa.Unlock()

	sizeFee := big.NewInt(0)
	if transactionSize > 1024 {
		sizeFee = big.NewInt(transactionSize / 1024)
	}

	typeFee := big.NewInt(0)
	switch transactionType {
	case "complex":
		typeFee = big.NewInt(2)
	case "simple":
		typeFee = big.NewInt(1)
	}

	totalFee := new(big.Int).Add(fa.baseFee, fa.congestionFee)
	totalFee.Add(totalFee, sizeFee)
	totalFee.Add(totalFee, typeFee)

	return totalFee
}

// GetBaseFee returns the current base fee.
func (fa *FeeAdjustment) GetBaseFee() *big.Int {
	fa.Lock()
	defer fa.Unlock()

	return new(big.Int).Set(fa.baseFee)
}

// SetBaseFee sets a new base fee.
func (fa *FeeAdjustment) SetBaseFee(baseFee int64) {
	fa.Lock()
	defer fa.Unlock()

	fa.baseFee = big.NewInt(baseFee)
}

// GetCongestionFee returns the current congestion fee.
func (fa *FeeAdjustment) GetCongestionFee() *big.Int {
	fa.Lock()
	defer fa.Unlock()

	return new(big.Int).Set(fa.congestionFee)
}

// GetSizeFee returns the current size fee.
func (fa *FeeAdjustment) GetSizeFee() *big.Int {
	fa.Lock()
	defer fa.Unlock()

	return new(big.Int).Set(fa.sizeFee)
}

// GetTypeFee returns the current type fee.
func (fa *FeeAdjustment) GetTypeFee() *big.Int {
	fa.Lock()
	defer fa.Unlock()

	return new(big.Int).Set(fa.typeFee)
}

// GetLastUpdated returns the last time fees were updated.
func (fa *FeeAdjustment) GetLastUpdated() time.Time {
	fa.Lock()
	defer fa.Unlock()

	return fa.lastUpdated
}
