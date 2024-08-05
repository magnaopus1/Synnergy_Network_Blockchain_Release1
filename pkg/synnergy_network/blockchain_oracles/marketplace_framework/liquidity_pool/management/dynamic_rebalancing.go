package management

import (
	"errors"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// DynamicRebalancer manages the dynamic rebalancing of liquidity pools
type DynamicRebalancer struct {
	Pools             map[string]*LiquidityPool
	TargetRatios      map[string]*big.Float
	Threshold         *big.Float
	Lock              sync.Mutex
}

// LiquidityPool represents a single liquidity pool
type LiquidityPool struct {
	ID                common.Hash
	TokenBalances     map[string]*big.Float
}

// NewDynamicRebalancer creates a new DynamicRebalancer
func NewDynamicRebalancer(threshold *big.Float) *DynamicRebalancer {
	return &DynamicRebalancer{
		Pools:        make(map[string]*LiquidityPool),
		TargetRatios: make(map[string]*big.Float),
		Threshold:    threshold,
	}
}

// AddPool adds a liquidity pool to the dynamic rebalancer
func (dr *DynamicRebalancer) AddPool(poolID common.Hash, initialBalances map[string]*big.Float) {
	dr.Lock.Lock()
	defer dr.Lock.Unlock()

	pool := &LiquidityPool{
		ID:            poolID,
		TokenBalances: initialBalances,
	}
	dr.Pools[poolID.Hex()] = pool
}

// SetTargetRatio sets the target ratio for a specific token
func (dr *DynamicRebalancer) SetTargetRatio(token string, ratio *big.Float) {
	dr.Lock.Lock()
	defer dr.Lock.Unlock()

	dr.TargetRatios[token] = ratio
}

// RebalancePool rebalances the liquidity pool to match target ratios
func (dr *DynamicRebalancer) RebalancePool(poolID common.Hash) error {
	dr.Lock.Lock()
	defer dr.Lock.Unlock()

	pool, exists := dr.Pools[poolID.Hex()]
	if !exists {
		return errors.New("pool not found")
	}

	totalValue := dr.calculateTotalValue(pool)

	for token, balance := range pool.TokenBalances {
		targetValue := new(big.Float).Mul(totalValue, dr.TargetRatios[token])
		delta := new(big.Float).Sub(balance, targetValue)
		percentChange := new(big.Float).Quo(delta, targetValue)
		if percentChange.Cmp(dr.Threshold) > 0 || percentChange.Cmp(new(big.Float).Neg(dr.Threshold)) < 0 {
			dr.adjustBalance(pool, token, delta)
		}
	}

	return nil
}

// calculateTotalValue calculates the total value of the liquidity pool
func (dr *DynamicRebalancer) calculateTotalValue(pool *LiquidityPool) *big.Float {
	totalValue := big.NewFloat(0)
	for _, balance := range pool.TokenBalances {
		totalValue.Add(totalValue, balance)
	}
	return totalValue
}

// adjustBalance adjusts the balance of a specific token in the liquidity pool
func (dr *DynamicRebalancer) adjustBalance(pool *LiquidityPool, token string, delta *big.Float) {
	pool.TokenBalances[token].Sub(pool.TokenBalances[token], delta)
	// In a real-world scenario, the adjustment would involve interacting with the blockchain network
}

// GetPoolBalance retrieves the balance of a specific token in the liquidity pool
func (dr *DynamicRebalancer) GetPoolBalance(poolID common.Hash, token string) (*big.Float, error) {
	dr.Lock.Lock()
	defer dr.Lock.Unlock()

	pool, exists := dr.Pools[poolID.Hex()]
	if !exists {
		return nil, errors.New("pool not found")
	}

	balance, exists := pool.TokenBalances[token]
	if !exists {
		return nil, errors.New("token not found in pool")
	}

	return balance, nil
}

// GetTargetRatio retrieves the target ratio for a specific token
func (dr *DynamicRebalancer) GetTargetRatio(token string) (*big.Float, error) {
	dr.Lock.Lock()
	defer dr.Lock.Unlock()

	ratio, exists := dr.TargetRatios[token]
	if !exists {
		return nil, errors.New("target ratio not set for token")
	}

	return ratio, nil
}

// RemovePool removes a liquidity pool from the dynamic rebalancer
func (dr *DynamicRebalancer) RemovePool(poolID common.Hash) {
	dr.Lock.Lock()
	defer dr.Lock.Unlock()

	delete(dr.Pools, poolID.Hex())
}

// ListPools lists all the liquidity pools managed by the dynamic rebalancer
func (dr *DynamicRebalancer) ListPools() []*LiquidityPool {
	dr.Lock.Lock()
	defer dr.Lock.Unlock()

	pools := []*LiquidityPool{}
	for _, pool := range dr.Pools {
		pools = append(pools, pool)
	}

	return pools
}

// UpdatePoolBalance updates the balance of a specific token in the liquidity pool
func (dr *DynamicRebalancer) UpdatePoolBalance(poolID common.Hash, token string, newBalance *big.Float) error {
	dr.Lock.Lock()
	defer dr.Lock.Unlock()

	pool, exists := dr.Pools[poolID.Hex()]
	if !exists {
		return errors.New("pool not found")
	}

	pool.TokenBalances[token] = newBalance
	return nil
}

// AdjustThreshold adjusts the threshold for rebalancing
func (dr *DynamicRebalancer) AdjustThreshold(newThreshold *big.Float) {
	dr.Lock.Lock()
	defer dr.Lock.Unlock()

	dr.Threshold = newThreshold
}

