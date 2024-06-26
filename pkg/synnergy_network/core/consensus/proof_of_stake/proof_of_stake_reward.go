package proof_of_stake

import (
	"crypto"
	"math/big"
	"time"

	"github.com/synthron/synthronchain/crypto/vrf"
	"github.com/synthron/synthronchain/storage"
)

// Validator struct holds details about each validator
type Validator struct {
	Address       string
	Stake         *big.Int
	LastActive    time.Time
	IsSlashed     bool
	StakedSince   time.Time
	LockUpPeriod  time.Duration
}

// PoSRewardSystem manages the reward distribution and slashing for the PoS mechanism
type PoSRewardSystem struct {
	Blockchain *Blockchain
}

// NewPoSRewardSystem creates a new instance of PoSRewardSystem
func NewPoSRewardSystem(blockchain *Blockchain) *PoSRewardSystem {
	return &PoSRewardSystem{
		Blockchain: blockchain,
	}
}

// CalculateReward computes the reward for a given validator based on the stake proportion
func (prs *PoSRewardSystem) CalculateReward(validator Validator) *big.Int {
	totalStake := prs.Blockchain.TotalStakedTokens()
	stakeProportion := new(big.Int).Div(validator.Stake, totalStake)
	baseReward := new(big.Int).Div(prs.Blockchain.TotalTransactionVolume(), big.NewInt(10000)) // Example reward calculation
	reward := new(big.Int).Mul(baseReward, stakeProportion)
	return reward
}

// DistributeRewards processes rewards for all validators
func (prs *PoSRewardSystem) DistributeRewards() {
	for _, validator := range prs.Blockchain.Validators {
		if validator.IsSlashed {
			continue
		}
		reward := prs.CalculateReward(validator)
		prs.Blockchain.UpdateTokenBalance(validator.Address, reward)
	}
}

// ApplySlashing applies penalties based on the severity of the violation
func (prs *PoSRewardSystem) ApplySlashing(validator *Validator, severity int) {
	if severity > 0 {
		lossPercentage := big.NewInt(int64(severity * 10)) // 10% per severity level
		lossAmount := new(big.Int).Mul(validator.Stake, lossPercentage)
		lossAmount.Div(lossAmount, big.NewInt(100))
		validator.Stake.Sub(validator.Stake, lossAmount)
		validator.IsSlashed = true
		storage.UpdateValidatorStatus(validator.Address, validator.IsSlashed)
	}
}

// ValidateBlockSignature checks if a block has been validly signed by the majority of validators
func (prs *PoSRewardSystem) ValidateBlockSignature(block *Block, validators []*Validator) bool {
	signatureCount := 0
	for _, validator := range validators {
		if crypto.VerifySignature(validator.Address, block.Hash, block.Signature) {
			signatureCount++
		}
	}
	return signatureCount >= len(validators)/2+1 // Simple majority
}

// SelectValidators uses a VRF to randomly select validators for the next block
func (prs *PoSRewardSystem) SelectValidators() []*Validator {
	seed := prs.Blockchain.LatestBlock().Hash
	selectedValidators := []*Validator{}
	for _, validator := range prs.Blockchain.Validators {
		if vrf.Verify(validator.Address, seed, nil) { // Simplified check
			selectedValidators = append(selectedValidators, validator)
		}
	}
	return selectedValidators
}

// Example main function to run and test PoS reward system
func main() {
	blockchain := InitializeBlockchain()
	posRewardSystem := NewPoSRewardSystem(blockchain)

	// Example of running reward distribution
	posRewardSystem.DistributeRewards()

	// Slashing example
	validator := blockchain.Validators[0] // Assuming there's at least one validator
	posRewardSystem.ApplySlashing(&validator, 2)

	// Validate block signature
	block := blockchain.LatestBlock()
	validators := posRewardSystem.SelectValidators()
	if posRewardSystem.ValidateBlockSignature(block, validators) {
		// Proceed with blockchain operations
	}
}
