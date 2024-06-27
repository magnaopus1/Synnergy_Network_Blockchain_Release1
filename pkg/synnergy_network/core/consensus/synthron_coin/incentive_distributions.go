package synthron_coin

import (
	"errors"
	"time"
)

// IncentiveDistributions contains the details and methods for handling incentive distributions for Synthron Coin.
type IncentiveDistributions struct {
	GenesisBlockReward           float64
	TotalCoins                   float64
	CurrentSupply                float64
	InitialGenesisBlockTimestamp time.Time
	TransactionFeePool           float64
}

// NewIncentiveDistributions initializes a new IncentiveDistributions structure.
func NewIncentiveDistributions(totalCoins float64) *IncentiveDistributions {
	return &IncentiveDistributions{
		GenesisBlockReward:           5000000,
		TotalCoins:                   totalCoins,
		CurrentSupply:                0,
		InitialGenesisBlockTimestamp: time.Now(),
		TransactionFeePool:           0,
	}
}

// ValidateGenesisBlockReward checks if the genesis block reward is valid.
func (id *IncentiveDistributions) ValidateGenesisBlockReward() error {
	if id.GenesisBlockReward <= 0 || id.GenesisBlockReward > id.TotalCoins {
		return errors.New("invalid genesis block reward")
	}
	id.CurrentSupply += id.GenesisBlockReward
	return nil
}

// AddTransactionFee adds a transaction fee to the pool.
func (id *IncentiveDistributions) AddTransactionFee(fee float64) {
	id.TransactionFeePool += fee
}

// DistributeTransactionFees distributes transaction fees to various wallets.
func (id *IncentiveDistributions) DistributeTransactionFees() (map[string]float64, error) {
	if id.TransactionFeePool == 0 {
		return nil, errors.New("no transaction fees available for distribution")
	}

	distributions := make(map[string]float64)
	distributions["DevelopmentFund"] = id.TransactionFeePool * 0.1
	distributions["CommunityGrantsFund"] = id.TransactionFeePool * 0.1
	distributions["StakingRewardsFund"] = id.TransactionFeePool * 0.5
	distributions["NodeHostDistributionFund"] = id.TransactionFeePool * 0.1
	distributions["PassiveIncomeFund"] = id.TransactionFeePool * 0.1
	distributions["LoanPoolFund"] = id.TransactionFeePool * 0.05
	distributions["CharitableContributionFund"] = id.TransactionFeePool * 0.05

	id.TransactionFeePool = 0 // Reset the transaction fee pool after distribution

	return distributions, nil
}

// CalculateStakingRewards calculates the staking rewards based on the staking duration and total staked amount.
func (id *IncentiveDistributions) CalculateStakingRewards(stakedAmount, stakingDuration float64) float64 {
	annualInterestRate := 0.05
	return stakedAmount * annualInterestRate * stakingDuration / 365
}

// AllocateNodeHostRewards allocates rewards to node hosts based on their contributions.
func (id *IncentiveDistributions) AllocateNodeHostRewards(nodeContributions map[string]float64) (map[string]float64, error) {
	totalContributions := 0.0
	for _, contribution := range nodeContributions {
		totalContributions += contribution
	}

	if totalContributions == 0 {
		return nil, errors.New("no node contributions provided")
	}

	nodeRewards := make(map[string]float64)
	for node, contribution := range nodeContributions {
		nodeRewards[node] = (contribution / totalContributions) * id.TransactionFeePool * 0.1
	}

	return nodeRewards, nil
}

// DistributePassiveIncome distributes passive income to holders based on their holdings.
func (id *IncentiveDistributions) DistributePassiveIncome(holderBalances map[string]float64) (map[string]float64, error) {
	totalHoldings := 0.0
	for _, balance := range holderBalances {
		totalHoldings += balance
	}

	if totalHoldings == 0 {
		return nil, errors.New("no holder balances provided")
	}

	passiveIncomeDistributions := make(map[string]float64)
	for holder, balance := range holderBalances {
		passiveIncomeDistributions[holder] = (balance / totalHoldings) * id.TransactionFeePool * 0.1
	}

	return passiveIncomeDistributions, nil
}
