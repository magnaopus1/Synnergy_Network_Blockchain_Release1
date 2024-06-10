package interblockchaintransactions

import (
	"errors"
	"fmt"
	"sync"

	"synthron-blockchain/pkg/blockchain"
)

// LiquidityPool represents a pool that holds assets from various blockchains to facilitate cross-chain transactions.
type LiquidityPool struct {
	Assets map[string]float64 // Holds the balance of different assets identified by their blockchain symbol.
	mu     sync.RWMutex       // Ensures thread-safe access to the pool assets.
}

// NewLiquidityPool initializes a new liquidity pool.
func NewLiquidityPool() *LiquidityPool {
	return &LiquidityPool{
		Assets: make(map[string]float64),
	}
}

// AddLiquidity adds assets to the liquidity pool.
func (lp *LiquidityPool) AddLiquidity(blockchainSymbol string, amount float64) error {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	if amount <= 0 {
		return errors.New("invalid amount: must be greater than zero")
	}
	lp.Assets[blockchainSymbol] += amount
	return nil
}

// RemoveLiquidity removes assets from the liquidity pool.
func (lp *LiquidityPool) RemoveLiquidity(blockchainSymbol string, amount float64) error {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	if amount <= 0 {
		return errors.New("invalid amount: must be greater than zero")
	}
	if lp.Assets[blockchainSymbol] < amount {
		return errors.New("insufficient liquidity")
	}
	lp.Assets[blockchainSymbol] -= amount
	return nil
}

// GetLiquidity returns the amount of a specific asset in the pool.
func (lp *LiquidityPool) GetLiquidity(blockchainSymbol string) (float64, error) {
	lp.mu.RLock()
	defer lp.mu.RUnlock()

	amount, exists := lp.Assets[blockchainSymbol]
	if !exists {
		return 0, fmt.Errorf("no liquidity found for blockchain symbol: %s", blockchainSymbol)
	}
	return amount, nil
}

// ExecuteSwap performs an atomic swap between two assets in the liquidity pool.
func (lp *LiquidityPool) ExecuteSwap(fromSymbol, toSymbol string, fromAmount, toAmount float64) error {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	if fromAmount <= 0 || toAmount <= 0 {
		return errors.New("invalid swap amounts: must be greater than zero")
	}

	if lp.Assets[fromSymbol] < fromAmount || lp.Assets[toSymbol] < toAmount {
		return errors.New("insufficient liquidity for the requested swap")
	}

	lp.Assets[fromSymbol] -= fromAmount
	lp.Assets[toSymbol] += fromAmount

	lp.Assets[toSymbol] -= toAmount
	lp.Assets[fromSymbol] += toAmount

	return nil
}

// Example usage of LiquidityPool
func main() {
	pool := NewLiquidityPool()
	err := pool.AddLiquidity("ETH", 1000.0)
	if err != nil {
		fmt.Println("Error adding liquidity:", err)
		return
	}
	err = pool.AddLiquidity("BTC", 500.0)
	if err != nil {
		fmt.Println("Error adding liquidity:", err)
		return
	}

	fmt.Println("Liquidity added successfully.")

	err = pool.ExecuteSwap("ETH", "BTC", 100.0, 10.0)
	if err != nil {
		fmt.Println("Error executing swap:", err)
		return
	}

	fmt.Println("Swap executed successfully.")
}
