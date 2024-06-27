package consensus

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"
	"synthron-blockchain/pkg/synnergy_network/core/common"
)

// BlockRewardManager handles the block reward distribution logic and maintains cumulative total supply.
type BlockRewardManager struct {
	BlockHeight   int
	Reward        *big.Int
	TotalMinedSyn *big.Int
}

// NewBlockRewardManager creates a new block reward manager with initial settings.
func NewBlockRewardManager() *BlockRewardManager {
	return &BlockRewardManager{
		BlockHeight:   0,
		Reward:        big.NewInt(common.InitialReward),
		TotalMinedSyn: big.NewInt(0),
	}
}

// CalculateReward calculates the reward for mining a block at the current block height.
func (brm *BlockRewardManager) CalculateReward() *big.Int {
	if brm.BlockHeight%common.BlockHalvingPeriod == 0 && brm.BlockHeight != 0 {
		brm.Reward.Div(brm.Reward, big.NewInt(2)) // Halve the reward every 'BlockHalvingPeriod' blocks.
	}

	// Make sure not to exceed the total supply limit.
	prospectiveTotal := new(big.Int).Add(brm.TotalMinedSyn, brm.Reward)
	if prospectiveTotal.Cmp(big.NewInt(common.TotalSynthronSupply)) > 0 {
		// Reduce reward if the next reward exceeds total supply
		brm.Reward.Sub(brm.Reward, new(big.Int).Sub(prospectiveTotal, big.NewInt(common.TotalSynthronSupply)))
		if brm.Reward.Cmp(big.NewInt(0)) < 0 {
			brm.Reward.SetInt64(0)
		}
	}

	return new(big.Int).Set(brm.Reward) // Return a copy to prevent external modification.
}

// IncrementBlockHeight increments the block height and updates total mined SYN.
func (brm *BlockRewardManager) IncrementBlockHeight() {
	brm.TotalMinedSyn.Add(brm.TotalMinedSyn, brm.Reward)
	brm.BlockHeight++
}
