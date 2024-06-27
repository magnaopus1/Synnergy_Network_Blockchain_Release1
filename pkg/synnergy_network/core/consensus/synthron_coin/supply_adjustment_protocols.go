package synthron_coin

import (
	"errors"
	"sync"
	"time"
)

// CoinSupplyManager manages the supply of Synthron Coin
type CoinSupplyManager struct {
	TotalSupply       float64
	MaxSupply         float64
	BlockReward       float64
	HalvingInterval   int
	HalvingCount      int
	TransactionBurnRate float64
	Treasury          *Treasury
	mu                sync.Mutex
}

// Treasury manages the community treasury
type Treasury struct {
	CommunityFund   float64
	EcosystemFund   float64
	ReservedFund    float64
	mu              sync.Mutex
}

// NewCoinSupplyManager creates a new CoinSupplyManager
func NewCoinSupplyManager(initialSupply, maxSupply, initialBlockReward, burnRate float64, halvingInterval int) *CoinSupplyManager {
	return &CoinSupplyManager{
		TotalSupply:       initialSupply,
		MaxSupply:         maxSupply,
		BlockReward:       initialBlockReward,
		HalvingInterval:   halvingInterval,
		TransactionBurnRate: burnRate,
		Treasury:          &Treasury{},
	}
}

// DistributeBlockReward distributes the block reward and handles halving
func (csm *CoinSupplyManager) DistributeBlockReward() {
	csm.mu.Lock()
	defer csm.mu.Unlock()

	if csm.TotalSupply+csm.BlockReward <= csm.MaxSupply {
		csm.TotalSupply += csm.BlockReward
	}

	// Handle halving
	if (csm.HalvingCount+1)*csm.HalvingInterval <= int(csm.TotalSupply/csm.BlockReward) {
		csm.BlockReward /= 2
		csm.HalvingCount++
	}
}

// BurnTokens burns a portion of the transaction fees
func (csm *CoinSupplyManager) BurnTokens(transactionFee float64) {
	burnAmount := transactionFee * csm.TransactionBurnRate
	csm.TotalSupply -= burnAmount
}

// AddToTreasury adds funds to the community and ecosystem funds
func (csm *CoinSupplyManager) AddToTreasury(communityFund, ecosystemFund float64) {
	csm.Treasury.mu.Lock()
	defer csm.Treasury.mu.Unlock()

	csm.Treasury.CommunityFund += communityFund
	csm.Treasury.EcosystemFund += ecosystemFund
}

// TreasuryManagement handles the management of the community treasury
func (csm *CoinSupplyManager) TreasuryManagement() *Treasury {
	return csm.Treasury
}

// AllocateCommunityFunds allocates funds from the community fund for a project
func (t *Treasury) AllocateCommunityFunds(amount float64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if amount > t.CommunityFund {
		return errors.New("insufficient community funds")
	}

	t.CommunityFund -= amount
	return nil
}

// AllocateEcosystemFunds allocates funds from the ecosystem fund for a project
func (t *Treasury) AllocateEcosystemFunds(amount float64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if amount > t.EcosystemFund {
		return errors.New("insufficient ecosystem funds")
	}

	t.EcosystemFund -= amount
	return nil
}

// RewardsRedistributionModel represents the model for redistributing rewards
type RewardsRedistributionModel struct {
	Validators       map[string]*Validator
	TotalStake       float64
	RedistributionFund float64
}

// NewRewardsRedistributionModel creates a new RewardsRedistributionModel
func NewRewardsRedistributionModel() *RewardsRedistributionModel {
	return &RewardsRedistributionModel{
		Validators:       make(map[string]*Validator),
		RedistributionFund: 0,
	}
}

// AddValidator adds a validator to the rewards redistribution model
func (rrm *RewardsRedistributionModel) AddValidator(address string, stake float64) {
	if _, exists := rrm.Validators[address]; !exists {
		rrm.Validators[address] = &Validator{
			Address: address,
			Stake:   stake,
		}
		rrm.TotalStake += stake
	}
}

// RemoveValidator removes a validator from the rewards redistribution model
func (rrm *RewardsRedistributionModel) RemoveValidator(address string) error {
	validator, exists := rrm.Validators[address]
	if !exists {
		return errors.New("validator does not exist")
	}
	rrm.TotalStake -= validator.Stake
	delete(rrm.Validators, address)
	return nil
}

// UpdateValidatorStake updates the stake of a validator
func (rrm *RewardsRedistributionModel) UpdateValidatorStake(address string, newStake float64) error {
	validator, exists := rrm.Validators[address]
	if !exists {
		return errors.New("validator does not exist")
	}
	rrm.TotalStake = rrm.TotalStake - validator.Stake + newStake
	validator.Stake = newStake
	return nil
}

// RedistributeRewards redistributes rewards based on stake and other criteria
func (rrm *RewardsRedistributionModel) RedistributeRewards() map[string]float64 {
	rewards := make(map[string]float64)
	for address, validator := range rrm.Validators {
		reward := (validator.Stake / rrm.TotalStake) * rrm.RedistributionFund
		rewards[address] = reward
	}
	rrm.RedistributionFund = 0
	return rewards
}

// RecordRedistributionFund records the amount to be redistributed
func (rrm *RewardsRedistributionModel) RecordRedistributionFund(amount float64) {
	rrm.RedistributionFund += amount
}

// SupplyAdjustmentController controls the supply adjustment protocols
type SupplyAdjustmentController struct {
	CoinSupplyManager         *CoinSupplyManager
	RewardsRedistributionModel *RewardsRedistributionModel
}

// NewSupplyAdjustmentController creates a new SupplyAdjustmentController
func NewSupplyAdjustmentController(coinSupplyManager *CoinSupplyManager, rewardsRedistributionModel *RewardsRedistributionModel) *SupplyAdjustmentController {
	return &SupplyAdjustmentController{
		CoinSupplyManager:         coinSupplyManager,
		RewardsRedistributionModel: rewardsRedistributionModel,
	}
}

// ExecuteSupplyAdjustment executes supply adjustment protocols
func (sac *SupplyAdjustmentController) ExecuteSupplyAdjustment(transactionFee float64, communityFund, ecosystemFund float64) {
	sac.CoinSupplyManager.DistributeBlockReward()
	sac.CoinSupplyManager.BurnTokens(transactionFee)
	sac.CoinSupplyManager.AddToTreasury(communityFund, ecosystemFund)
}

// ExecuteRewardsRedistribution executes the rewards redistribution process
func (sac *SupplyAdjustmentController) ExecuteRewardsRedistribution() map[string]float64 {
	return sac.RewardsRedistributionModel.RedistributeRewards()
}

// DynamicInflationControl dynamically adjusts emission rates based on network performance
func (sac *SupplyAdjustmentController) DynamicInflationControl(performanceMetric float64) {
	sac.CoinSupplyManager.mu.Lock()
	defer sac.CoinSupplyManager.mu.Unlock()

	if performanceMetric > 1.0 {
		// Increase emission rate
		sac.CoinSupplyManager.BlockReward *= 1.05
	} else if performanceMetric < 1.0 {
		// Decrease emission rate
		sac.CoinSupplyManager.BlockReward *= 0.95
	}
}

// RegularAudits performs regular audits and adjusts protocols
func (sac *SupplyAdjustmentController) RegularAudits() {
	// Placeholder for audit logic
	// In a real-world scenario, this would involve comprehensive checks and balances
	time.Sleep(1 * time.Hour) // Simulate audit time
	// Adjustments based on audit results can be implemented here
}

