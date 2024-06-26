package proof_of_work

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sync"
	"time"

	"github.com/synthron/synthroncore/block"
	"github.com/synthron/synthroncore/transaction"
	"github.com/synthron/synthroncore/utils"
	"golang.org/x/crypto/argon2"
)

// BlockRewardManager handles the logic of block reward distribution and halving.
type BlockRewardManager struct {
	InitialReward       float64
	HalvingInterval     int
	RewardReduction     float64
	BlockReward         float64
	HalvingCount        int
	mutex               sync.Mutex
	TotalBlocksMined    int
	MaxSupply           float64
	CurrentSupply       float64
}

// NewBlockRewardManager initializes a BlockRewardManager with the initial parameters.
func NewBlockRewardManager() *BlockRewardManager {
	return &BlockRewardManager{
		InitialReward:   1252,
		HalvingInterval: 200000,
		RewardReduction: 0.5,
		BlockReward:     1252,
		HalvingCount:    0,
		MaxSupply:       500000000,
		CurrentSupply:   0,
	}
}

// CalculateBlockReward calculates the reward for a block given the total number of blocks mined.
func (brm *BlockRewardManager) CalculateBlockReward() float64 {
	brm.mutex.Lock()
	defer brm.mutex.Unlock()

	// Calculate the number of halvings based on the total number of blocks mined.
	numberOfHalvings := brm.TotalBlocksMined / brm.HalvingInterval

	// If the number of halvings has changed since the last block, adjust the block reward.
	if numberOfHalvings != brm.HalvingCount {
		brm.HalvingCount = numberOfHalvings
		brm.BlockReward = brm.InitialReward

		// Apply the halving reduction formula.
		for i := 0; i < numberOfHalvings; i++ {
			brm.BlockReward *= brm.RewardReduction
		}
	}

	// If the total supply plus the current block reward exceeds the max supply, adjust the reward.
	if brm.CurrentSupply+brm.BlockReward > brm.MaxSupply {
		brm.BlockReward = brm.MaxSupply - brm.CurrentSupply
	}

	// Update the current supply with the new block reward.
	brm.CurrentSupply += brm.BlockReward

	return brm.BlockReward
}

// DistributeReward handles the distribution of the block reward to the miner's address.
func (brm *BlockRewardManager) DistributeReward(minerAddress string, block *block.Block) {
	reward := brm.CalculateBlockReward()
	if reward > 0 {
		// Create a transaction from the "network" to the miner rewarding them the block reward.
		rewardTx := transaction.NewTransaction("network", minerAddress, reward)
		block.Transactions = append(block.Transactions, rewardTx)
	}
}

// ValidateBlockReward verifies that the block reward is correctly calculated and assigned.
func (brm *BlockRewardManager) ValidateBlockReward(block *block.Block) bool {
	calculatedReward := brm.CalculateBlockReward()
	rewardTx := block.Transactions[0] // Assuming the first transaction is the reward transaction.

	// Check if the reward transaction is correct.
	return rewardTx.Amount == calculatedReward && rewardTx.FromAddress == "network" && rewardTx.ToAddress == block.MinerAddress
}

// adjustDifficulty adjusts the mining difficulty based on the time taken to mine the last set of blocks.
func (brm *BlockRewardManager) adjustDifficulty(lastBlockTimes []int64, targetTimePerBlock int64) {
	// Implementation of difficulty adjustment logic based on the actual mining time of recent blocks.
}

// Implement the full logic including mining, reward distribution, and halving checks.
// Further integration with blockchain and mining nodes would be necessary for a complete system.
