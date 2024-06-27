package synthron_coin

import (
	"errors"
	"time"
)

// Validator represents a network validator
type Validator struct {
	Address       string
	Stake         float64
	RewardAddress string
}

// Network represents the blockchain network
type Network struct {
	Validators        map[string]*Validator
	TotalStake        float64
	BlockReward       float64
	CommunityFund     float64
	StakingRewards    float64
	EcosystemFund     float64
	TransactionFees   float64
	RewardDistribution []RewardDistribution
}

// RewardDistribution represents the distribution of rewards
type RewardDistribution struct {
	ValidatorAddress string
	Amount           float64
	Timestamp        time.Time
}

// NewNetwork initializes a new network
func NewNetwork(initialReward, communityFund, ecosystemFund float64) *Network {
	return &Network{
		Validators:        make(map[string]*Validator),
		BlockReward:       initialReward,
		CommunityFund:     communityFund,
		EcosystemFund:     ecosystemFund,
		RewardDistribution: []RewardDistribution{},
	}
}

// AddValidator adds a validator to the network
func (n *Network) AddValidator(address string, stake float64, rewardAddress string) {
	if _, exists := n.Validators[address]; !exists {
		n.Validators[address] = &Validator{
			Address:       address,
			Stake:         stake,
			RewardAddress: rewardAddress,
		}
		n.TotalStake += stake
	}
}

// RemoveValidator removes a validator from the network
func (n *Network) RemoveValidator(address string) error {
	validator, exists := n.Validators[address]
	if !exists {
		return errors.New("validator does not exist")
	}
	n.TotalStake -= validator.Stake
	delete(n.Validators, address)
	return nil
}

// UpdateValidatorStake updates the stake of a validator
func (n *Network) UpdateValidatorStake(address string, newStake float64) error {
	validator, exists := n.Validators[address]
	if !exists {
		return errors.New("validator does not exist")
	}
	n.TotalStake = n.TotalStake - validator.Stake + newStake
	validator.Stake = newStake
	return nil
}

// DistributeBlockReward distributes the block reward to validators
func (n *Network) DistributeBlockReward() {
	for _, validator := range n.Validators {
		reward := (validator.Stake / n.TotalStake) * n.BlockReward
		n.RewardDistribution = append(n.RewardDistribution, RewardDistribution{
			ValidatorAddress: validator.RewardAddress,
			Amount:           reward,
			Timestamp:        time.Now(),
		})
	}
}

// DistributeTransactionFees distributes transaction fees to various funds
func (n *Network) DistributeTransactionFees() {
	// Example allocation: 50% to staking rewards, 30% to community fund, 20% to ecosystem fund
	stakingReward := 0.5 * n.TransactionFees
	communityFund := 0.3 * n.TransactionFees
	ecosystemFund := 0.2 * n.TransactionFees

	n.StakingRewards += stakingReward
	n.CommunityFund += communityFund
	n.EcosystemFund += ecosystemFund
	n.TransactionFees = 0 // Reset transaction fees after distribution
}

// StakingRewardsCalculation calculates staking rewards for validators
func (n *Network) StakingRewardsCalculation() {
	for _, validator := range n.Validators {
		reward := (validator.Stake / n.TotalStake) * n.StakingRewards
		n.RewardDistribution = append(n.RewardDistribution, RewardDistribution{
			ValidatorAddress: validator.RewardAddress,
			Amount:           reward,
			Timestamp:        time.Now(),
		})
	}
	n.StakingRewards = 0 // Reset staking rewards after distribution
}

// ProposeCommunityProject proposes a community project for funding
func (n *Network) ProposeCommunityProject(projectID string, amount float64) error {
	if amount > n.CommunityFund {
		return errors.New("insufficient community fund")
	}
	n.CommunityFund -= amount
	// Assuming community project logic is handled elsewhere
	return nil
}

// FundEcosystemDevelopment funds ecosystem development projects
func (n *Network) FundEcosystemDevelopment(amount float64) error {
	if amount > n.EcosystemFund {
		return errors.New("insufficient ecosystem fund")
	}
	n.EcosystemFund -= amount
	// Assuming ecosystem development logic is handled elsewhere
	return nil
}

// RecordTransactionFee records transaction fees collected
func (n *Network) RecordTransactionFee(fee float64) {
	n.TransactionFees += fee
}

// PostGenesisDistributionController controls post-genesis distribution logic
type PostGenesisDistributionController struct {
	Network *Network
}

// NewPostGenesisDistributionController creates a new PostGenesisDistributionController
func NewPostGenesisDistributionController(network *Network) *PostGenesisDistributionController {
	return &PostGenesisDistributionController{
		Network: network,
	}
}

// ExecuteDistribution executes the reward and fee distribution
func (p *PostGenesisDistributionController) ExecuteDistribution() {
	p.Network.DistributeBlockReward()
	p.Network.DistributeTransactionFees()
	p.Network.StakingRewardsCalculation()
}

