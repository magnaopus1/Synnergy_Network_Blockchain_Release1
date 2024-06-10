package transaction_prioritization

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"math"
	"sync"
)

// FeeManager handles dynamic transaction fee calculations and adjustments.
type FeeManager struct {
	baseFee         float64
	feeAdjustFactor float64
	lock            sync.Mutex
}

// NewFeeManager initializes a FeeManager with default values.
func NewFeeManager(baseFee, adjustFactor float64) *FeeManager {
	return &FeeManager{
		baseFee:         baseFee,
		feeAdjustFactor: adjustFactor,
	}
}

// CalculateFee calculates the transaction fee based on the transaction size and congestion level.
func (fm *FeeManager) CalculateFee(txSize int, congestionLevel float64) (float64, error) {
	if txSize < 0 {
		return 0, errors.New("transaction size cannot be negative")
	}
	fm.lock.Lock()
	defer fm.lock.Unlock()

	adjustedFee := fm.baseFee + (float64(txSize)/1024)*fm.feeAdjustFactor*math.Log(1+congestionLevel)
	return adjustedFee, nil
}

// AdjustBaseFee dynamically adjusts the base fee of transactions in the network.
func (fm *FeeManager) AdjustBaseFee(newBaseFee float64) error {
	if newBaseFee < 0 {
		return errors.New("base fee cannot be negative")
	}
	fm.lock.Lock()
	defer fm.lock.Unlock()

	fm.baseFee = newBaseFee
	return nil
}

// SecureConfig encrypts the fee manager configuration using AES.
func (fm *FeeManager) SecureConfig(key []byte) ([]byte, error) {
	fm.lock.Lock()
	defer fm.lock.Unlock()

	configData, err := json.Marshal(fm)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	ciphertext := gcm.Seal(nil, nonce, configData, nil)
	return ciphertext, nil
}

// Encryption and decryption utility functions can be expanded here
