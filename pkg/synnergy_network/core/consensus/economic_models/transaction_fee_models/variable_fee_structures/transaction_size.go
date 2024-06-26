package variable_fee_structures

import (
	"errors"
	"math/big"
	"sync"
)

// TransactionSizeFeeManager manages the fee structure based on transaction sizes
type TransactionSizeFeeManager struct {
	sync.Mutex
	baseFee  *big.Int
	feePerKB *big.Int
}

// NewTransactionSizeFeeManager initializes a new TransactionSizeFeeManager instance
func NewTransactionSizeFeeManager(baseFee, feePerKB int64) *TransactionSizeFeeManager {
	return &TransactionSizeFeeManager{
		baseFee:  big.NewInt(baseFee),
		feePerKB: big.NewInt(feePerKB),
	}
}

// SetBaseFee sets the base fee for transactions
func (tsfm *TransactionSizeFeeManager) SetBaseFee(baseFee int64) {
	tsfm.Lock()
	defer tsfm.Unlock()
	tsfm.baseFee = big.NewInt(baseFee)
}

// GetBaseFee retrieves the base fee for transactions
func (tsfm *TransactionSizeFeeManager) GetBaseFee() *big.Int {
	tsfm.Lock()
	defer tsfm.Unlock()
	return new(big.Int).Set(tsfm.baseFee)
}

// SetFeePerKB sets the fee per kilobyte for transactions
func (tsfm *TransactionSizeFeeManager) SetFeePerKB(feePerKB int64) {
	tsfm.Lock()
	defer tsfm.Unlock()
	tsfm.feePerKB = big.NewInt(feePerKB)
}

// GetFeePerKB retrieves the fee per kilobyte for transactions
func (tsfm *TransactionSizeFeeManager) GetFeePerKB() *big.Int {
	tsfm.Lock()
	defer tsfm.Unlock()
	return new(big.Int).Set(tsfm.feePerKB)
}

// CalculateFee calculates the total fee based on the transaction size in bytes
func (tsfm *TransactionSizeFeeManager) CalculateFee(sizeInBytes int64) (*big.Int, error) {
	if sizeInBytes <= 0 {
		return nil, errors.New("transaction size must be greater than 0")
	}

	tsfm.Lock()
	defer tsfm.Unlock()

	sizeInKB := new(big.Int).Div(big.NewInt(sizeInBytes), big.NewInt(1024))
	if sizeInBytes%1024 != 0 {
		sizeInKB.Add(sizeInKB, big.NewInt(1))
	}

	fee := new(big.Int).Mul(sizeInKB, tsfm.feePerKB)
	totalFee := new(big.Int).Add(tsfm.baseFee, fee)

	return totalFee, nil
}

