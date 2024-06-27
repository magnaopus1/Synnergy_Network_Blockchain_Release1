package consensus

import (
	"math/big"
	"synthron-blockchain/pkg/synnergy_network/core/common"
)

// RewardCalculator handles the calculation of mining rewards, considering halving.
type RewardCalculator struct {
	TotalSupply *big.Int
}

// NewRewardCalculator initializes a reward calculator.
func NewRewardCalculator() *RewardCalculator {
	return &RewardCalculator{
		TotalSupply: big.NewInt(common.TotalSynthronSupply), // Max supply of SYN tokens.
	}
}

// CalculateReward determines the mining reward at a given block height.
func (rc *RewardCalculator) CalculateReward(height int) *big.Int {
	halvings := height / common.BlockHalvingPeriod
	if halvings >= common.MaxHalvings {
		return big.NewInt(0) // Reward drops to zero after maximum halvings.
	}
	reward := big.NewInt(common.InitialReward)
	for i := 0; i < halvings; i++ {
		reward.Div(reward, big.NewInt(2))
	}
	return reward
}
