package synthron_coin

import (
	"errors"
	"sync"
	"time"
)

// CoinSupplyManager handles the supply management for Synthron Coin
type CoinSupplyManager struct {
	TotalSupply        int64
	MaxSupply          int64
	BlockReward        int64
	HalvingInterval    int64
	LastHalvingBlock   int64
	CurrentBlockHeight int64
	RewardLock         sync.Mutex
	SupplyLock         sync.Mutex
}

// NewCoinSupplyManager initializes a new instance of CoinSupplyManager
func NewCoinSupplyManager(initialSupply, maxSupply, initialBlockReward, halvingInterval int64) *CoinSupplyManager {
	return &CoinSupplyManager{
		TotalSupply:     initialSupply,
		MaxSupply:       maxSupply,
		BlockReward:     initialBlockReward,
		HalvingInterval: halvingInterval,
	}
}

// MintNewBlock mints a new block and adjusts the supply and block reward as necessary
func (csm *CoinSupplyManager) MintNewBlock() error {
	csm.RewardLock.Lock()
	defer csm.RewardLock.Unlock()

	if csm.TotalSupply+csm.BlockReward > csm.MaxSupply {
		return errors.New("cannot mint new block: max supply reached")
	}

	csm.TotalSupply += csm.BlockReward
	csm.CurrentBlockHeight++

	if csm.CurrentBlockHeight%csm.HalvingInterval == 0 {
		csm.halveBlockReward()
	}

	return nil
}

// halveBlockReward halves the block reward
func (csm *CoinSupplyManager) halveBlockReward() {
	csm.BlockReward /= 2
	csm.LastHalvingBlock = csm.CurrentBlockHeight
}

// CheckSupplyCap checks if the current supply has reached the max supply cap
func (csm *CoinSupplyManager) CheckSupplyCap() bool {
	csm.SupplyLock.Lock()
	defer csm.SupplyLock.Unlock()

	return csm.TotalSupply >= csm.MaxSupply
}

// GetCurrentSupply returns the current total supply of Synthron Coins
func (csm *CoinSupplyManager) GetCurrentSupply() int64 {
	csm.SupplyLock.Lock()
	defer csm.SupplyLock.Unlock()

	return csm.TotalSupply
}

// AdjustEmissionRate allows for dynamic adjustments to the emission rate
func (csm *CoinSupplyManager) AdjustEmissionRate(newReward int64) error {
	csm.RewardLock.Lock()
	defer csm.RewardLock.Unlock()

	if newReward < 0 {
		return errors.New("new reward must be non-negative")
	}

	csm.BlockReward = newReward
	return nil
}

// BurnCoins burns a specified amount of coins, reducing the total supply
func (csm *CoinSupplyManager) BurnCoins(amount int64) error {
	csm.SupplyLock.Lock()
	defer csm.SupplyLock.Unlock()

	if amount < 0 || amount > csm.TotalSupply {
		return errors.New("invalid burn amount")
	}

	csm.TotalSupply -= amount
	return nil
}

// SetInitialDistribution sets the initial distribution of coins to various wallets
func (csm *CoinSupplyManager) SetInitialDistribution(genesisWallet, devWallet, charityWallet, loanPoolWallet, passiveIncomeWallet, nodeHostWallet, creatorWallet int64) error {
	csm.SupplyLock.Lock()
	defer csm.SupplyLock.Unlock()

	totalInitialDistribution := genesisWallet + devWallet + charityWallet + loanPoolWallet + passiveIncomeWallet + nodeHostWallet + creatorWallet

	if totalInitialDistribution > csm.TotalSupply {
		return errors.New("initial distribution exceeds total supply")
	}

	// Assuming some implementation to allocate these amounts to respective wallets
	// This is just a placeholder for actual wallet allocations
	csm.allocateToWallet("genesis", genesisWallet)
	csm.allocateToWallet("development", devWallet)
	csm.allocateToWallet("charity", charityWallet)
	csm.allocateToWallet("loan_pool", loanPoolWallet)
	csm.allocateToWallet("passive_income", passiveIncomeWallet)
	csm.allocateToWallet("node_host", nodeHostWallet)
	csm.allocateToWallet("creator", creatorWallet)

	return nil
}

// allocateToWallet is a placeholder function for actual wallet allocation logic
func (csm *CoinSupplyManager) allocateToWallet(walletType string, amount int64) {
	// Placeholder for wallet allocation logic
}

// PeriodicAudit performs regular audits to ensure total supply integrity
func (csm *CoinSupplyManager) PeriodicAudit() error {
	csm.SupplyLock.Lock()
	defer csm.SupplyLock.Unlock()

	// Placeholder for actual audit logic
	// This would include verifying the total supply, checking for anomalies, etc.

	return nil
}

// AdjustHalvingInterval allows for dynamic adjustments to the halving interval
func (csm *CoinSupplyManager) AdjustHalvingInterval(newInterval int64) error {
	if newInterval <= 0 {
		return errors.New("halving interval must be positive")
	}

	csm.HalvingInterval = newInterval
	return nil
}

// GetEmissionDetails provides details about the current emission rate and halving status
func (csm *CoinSupplyManager) GetEmissionDetails() (int64, int64, int64) {
	csm.RewardLock.Lock()
	defer csm.RewardLock.Unlock()

	return csm.BlockReward, csm.LastHalvingBlock, csm.HalvingInterval
}

// SecureTransfer securely transfers coins from one wallet to another
func (csm *CoinSupplyManager) SecureTransfer(fromWallet, toWallet string, amount int64) error {
	csm.SupplyLock.Lock()
	defer csm.SupplyLock.Unlock()

	if amount < 0 {
		return errors.New("transfer amount must be non-negative")
	}

	// Placeholder for actual secure transfer logic, including validation and balance checks

	return nil
}

// LogSupplyEvent logs significant supply events for auditing and transparency
func (csm *CoinSupplyManager) LogSupplyEvent(event string) {
	// Placeholder for actual logging logic
}

