package swap_functionality

import (
	"errors"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// FeeCustomization handles the customization of fees for various pools and tokens
type FeeCustomization struct {
	PoolFees map[string]*PoolFeeSettings
	Lock     sync.Mutex
}

// PoolFeeSettings represents the fee settings for a specific liquidity pool
type PoolFeeSettings struct {
	SwapFees       map[string]*big.Float
	WithdrawalFees map[string]*big.Float
	DepositFees    map[string]*big.Float
}

// NewFeeCustomization creates a new FeeCustomization instance
func NewFeeCustomization() *FeeCustomization {
	return &FeeCustomization{
		PoolFees: make(map[string]*PoolFeeSettings),
	}
}

// SetSwapFee sets the swap fee for a specific token in a pool
func (fc *FeeCustomization) SetSwapFee(poolID common.Hash, token string, fee *big.Float) error {
	fc.Lock.Lock()
	defer fc.Lock.Unlock()

	poolFeeSettings, exists := fc.PoolFees[poolID.Hex()]
	if !exists {
		poolFeeSettings = &PoolFeeSettings{
			SwapFees:       make(map[string]*big.Float),
			WithdrawalFees: make(map[string]*big.Float),
			DepositFees:    make(map[string]*big.Float),
		}
		fc.PoolFees[poolID.Hex()] = poolFeeSettings
	}

	poolFeeSettings.SwapFees[token] = fee
	return nil
}

// GetSwapFee retrieves the swap fee for a specific token in a pool
func (fc *FeeCustomization) GetSwapFee(poolID common.Hash, token string) (*big.Float, error) {
	fc.Lock.Lock()
	defer fc.Lock.Unlock()

	poolFeeSettings, exists := fc.PoolFees[poolID.Hex()]
	if !exists {
		return nil, errors.New("pool not found")
	}

	fee, exists := poolFeeSettings.SwapFees[token]
	if !exists {
		return nil, errors.New("token swap fee not set")
	}

	return fee, nil
}

// SetWithdrawalFee sets the withdrawal fee for a specific token in a pool
func (fc *FeeCustomization) SetWithdrawalFee(poolID common.Hash, token string, fee *big.Float) error {
	fc.Lock.Lock()
	defer fc.Lock.Unlock()

	poolFeeSettings, exists := fc.PoolFees[poolID.Hex()]
	if !exists {
		poolFeeSettings = &PoolFeeSettings{
			SwapFees:       make(map[string]*big.Float),
			WithdrawalFees: make(map[string]*big.Float),
			DepositFees:    make(map[string]*big.Float),
		}
		fc.PoolFees[poolID.Hex()] = poolFeeSettings
	}

	poolFeeSettings.WithdrawalFees[token] = fee
	return nil
}

// GetWithdrawalFee retrieves the withdrawal fee for a specific token in a pool
func (fc *FeeCustomization) GetWithdrawalFee(poolID common.Hash, token string) (*big.Float, error) {
	fc.Lock.Lock()
	defer fc.Lock.Unlock()

	poolFeeSettings, exists := fc.PoolFees[poolID.Hex()]
	if !exists {
		return nil, errors.New("pool not found")
	}

	fee, exists := poolFeeSettings.WithdrawalFees[token]
	if !exists {
		return nil, errors.New("token withdrawal fee not set")
	}

	return fee, nil
}

// SetDepositFee sets the deposit fee for a specific token in a pool
func (fc *FeeCustomization) SetDepositFee(poolID common.Hash, token string, fee *big.Float) error {
	fc.Lock.Lock()
	defer fc.Lock.Unlock()

	poolFeeSettings, exists := fc.PoolFees[poolID.Hex()]
	if !exists {
		poolFeeSettings = &PoolFeeSettings{
			SwapFees:       make(map[string]*big.Float),
			WithdrawalFees: make(map[string]*big.Float),
			DepositFees:    make(map[string]*big.Float),
		}
		fc.PoolFees[poolID.Hex()] = poolFeeSettings
	}

	poolFeeSettings.DepositFees[token] = fee
	return nil
}

// GetDepositFee retrieves the deposit fee for a specific token in a pool
func (fc *FeeCustomization) GetDepositFee(poolID common.Hash, token string) (*big.Float, error) {
	fc.Lock.Lock()
	defer fc.Lock.Unlock()

	poolFeeSettings, exists := fc.PoolFees[poolID.Hex()]
	if !exists {
		return nil, errors.New("pool not found")
	}

	fee, exists := poolFeeSettings.DepositFees[token]
	if !exists {
		return nil, errors.New("token deposit fee not set")
	}

	return fee, nil
}

// RemovePoolFees removes all fee settings for a specific pool
func (fc *FeeCustomization) RemovePoolFees(poolID common.Hash) error {
	fc.Lock.Lock()
	defer fc.Lock.Unlock()

	_, exists := fc.PoolFees[poolID.Hex()]
	if !exists {
		return errors.New("pool not found")
	}

	delete(fc.PoolFees, poolID.Hex())
	return nil
}

// ListPools lists all pools with fee settings
func (fc *FeeCustomization) ListPools() []common.Hash {
	fc.Lock.Lock()
	defer fc.Lock.Unlock()

	poolIDs := []common.Hash{}
	for poolID := range fc.PoolFees {
		poolIDs = append(poolIDs, common.HexToHash(poolID))
	}

	return poolIDs
}
