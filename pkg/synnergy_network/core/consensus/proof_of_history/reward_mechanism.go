package consensus

import (
    "math/big"
    "sync"
    "synnergy_network/pkg/synnergy_network/core/blockchain"
)

// RewardConfig defines the configuration for reward calculations
type RewardConfig struct {
    BaseReward    *big.Int
    TotalStake    *big.Int
    DynamicFactor float64
}

// RewardCalculator handles the computation of rewards for block validation and transaction processing.
type RewardCalculator struct {
    config *RewardConfig
}

// NewRewardCalculator initializes a new RewardCalculator with provided configurations.
func NewRewardCalculator(config *RewardConfig) *RewardCalculator {
    return &RewardCalculator{
        config: config,
    }
}

// CalculateBlockReward computes the reward for a block based on the validator's stake.
func (rc *RewardCalculator) CalculateBlockReward(validatorStake *big.Int) *big.Int {
    validatorFactor := new(big.Float).Quo(new(big.Float).SetInt(validatorStake), new(big.Float).SetInt(rc.config.TotalStake))
    dynamicFactor := big.NewFloat(rc.config.DynamicFactor)
    reward := new(big.Float).Mul(new(big.Float).SetInt(rc.config.BaseReward), validatorFactor)
    reward.Mul(reward, dynamicFactor)
    result := new(big.Int)
    reward.Int(result)
    return result
}

// DistributeTransactionFees calculates the transaction fee reward for a block.
func (rc *RewardCalculator) DistributeTransactionFees(fees []*big.Int, blockReward *big.Int) *big.Int {
    totalFees := big.NewInt(0)
    for _, fee := range fees {
        totalFees.Add(totalFees, fee)
    }

    totalReward := big.NewInt(0)
    for _, fee := range fees {
        share := new(big.Float).Quo(new(big.Float).SetInt(fee), new(big.Float).SetInt(totalFees))
        reward := new(big.Float).Mul(share, new(big.Float).SetInt(blockReward))
        partialReward := new(big.Int)
        reward.Int(partialReward)
        totalReward.Add(totalReward, partialReward)
    }
    return totalReward
}

// ValidatorRewards manages the distribution of rewards to validators.
type ValidatorRewards struct {
    calculator *RewardCalculator
    mutex      sync.Mutex
}

// NewValidatorRewards creates an instance of ValidatorRewards.
func NewValidatorRewards(calculator *RewardCalculator) *ValidatorRewards {
    return &ValidatorRewards{
        calculator: calculator,
    }
}

// RewardValidator calculates and distributes the rewards for a block's validator.
func (vr *ValidatorRewards) RewardValidator(validatorStake *big.Int, fees []*big.Int) *big.Int {
    vr.mutex.Lock()
    defer vr.mutex.Unlock()

    blockReward := vr.calculator.CalculateBlockReward(validatorStake)
    transactionRewards := vr.calculator.DistributeTransactionFees(fees, blockReward)
    totalReward := new(big.Int).Add(blockReward, transactionRewards)
    return totalReward
}

