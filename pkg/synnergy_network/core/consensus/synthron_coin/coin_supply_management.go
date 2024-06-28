package synthron_coin

import (
	"math/big"
	"sync"
	"time"
)

// CoinSupplyManager manages the total and circulating supply of Synthron Coins.
type CoinSupplyManager struct {
	TotalSupply       *big.Int
	CirculatingSupply *big.Int
	MaxSupply         *big.Int
	BlockReward       *big.Int
	HalvingInterval   int
	lock              sync.Mutex
}

// NewCoinSupplyManager initializes a new coin supply manager with predefined settings.
func NewCoinSupplyManager() *CoinSupplyManager {
	return &CoinSupplyManager{
		TotalSupply:       big.NewInt(5000000), // initial supply from genesis block
		CirculatingSupply: big.NewInt(5000000),
		MaxSupply:         big.NewInt(500000000), // capped at 500 million coins
		BlockReward:       big.NewInt(50),        // initial block reward
		HalvingInterval:   200000,                // halving every 200,000 blocks
	}
}

// HalveReward reduces the block reward by half every set number of blocks.
func (csm *CoinSupplyManager) HalveReward(currentBlock int) {
	if currentBlock%csm.HalvingInterval == 0 {
		csm.lock.Lock()
		defer csm.lock.Unlock()
		csm.BlockReward.Div(csm.BlockReward, big.NewInt(2))
	}
}

// IssueCoins adds new coins to the circulating and total supply.
func (csm *CoinSupplyManager) IssueCoins(numCoins *big.Int) error {
	csm.lock.Lock()
	defer csm.lock.Unlock()

	newTotal := new(big.Int).Add(csm.TotalSupply, numCoins)
	if newTotal.Cmp(csm.MaxSupply) > 0 {
		return ErrMaxSupplyExceeded
	}

	csm.TotalSupply.Add(csm.TotalSupply, numCoins)
	csm.CirculatingSupply.Add(csm.CirculatingSupply, numCoins)
	return nil
}

// BurnCoins removes coins from the circulating supply.
func (csm *CoinSupplyManager) BurnCoins(numCoins *big.Int) error {
	csm.lock.Lock()
	defer csm.lock.Unlock()

	if numCoins.Cmp(csm.CirculatingSupply) > 0 {
		return ErrInsufficientCoins
	}

	csm.CirculatingSupply.Sub(csm.CirculatingSupply, numCoins)
	return nil
}

// GetCurrentBlockReward returns the current block reward.
func (csm *CoinSupplyManager) GetCurrentBlockReward() *big.Int {
	csm.lock.Lock()
	defer csm.lock.Unlock()

	return new(big.Int).Set(csm.BlockReward)
}

var (
	ErrMaxSupplyExceeded = errors.New("maximum supply exceeded")
	ErrInsufficientCoins = errors.New("insufficient coins available for burn")
)

// Setup runs the necessary initialization routines for the coin supply manager.
func (csm *CoinSupplyManager) Setup() {
	// Potentially load from a database or perform other initialization tasks.
}


