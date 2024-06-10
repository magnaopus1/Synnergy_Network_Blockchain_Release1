package proof_of_stake

import (
	"math"
	"time"

	"github.com/synthron/synthronchain/crypto"
)

type StakingParameters struct {
	MinimumStake        float64
	Alpha               float64
	CirculatingSupply   float64
	TotalTransactions   int64
	VolatilityIndex     float64
	ParticipationRate   float64
	EconomicStability   float64
	NormalizationFactor float64
}

type PoSInitialDifficulty struct {
	StakingParams StakingParameters
	Blockchain    *PoSBlockchain
}

func NewPoSInitialDifficulty(blockchain *PoSBlockchain) *PoSInitialDifficulty {
	return &PoSInitialDifficulty{
		Blockchain: blockchain,
		StakingParams: StakingParameters{
			NormalizationFactor: 0.01, // Example value
		},
	}
}

// CalculateAlpha dynamically adjusts alpha based on current network and market conditions.
func (pid *PoSInitialDifficulty) CalculateAlpha() float64 {
	v := pid.StakingParams.VolatilityIndex
	p := pid.StakingParams.ParticipationRate
	e := pid.StakingParams.EconomicStability

	alpha := (v + p + e) / 3 * pid.StakingParams.NormalizationFactor
	return alpha
}

// UpdateStakingParameters updates the parameters used to calculate the minimum stake.
func (pid *PoSInitialDifficulty) UpdateStakingParameters(currentReward float64, transactions int64, supply float64) {
	pid.StakingParams.CirculatingSupply = supply
	pid.StakingParams.TotalTransactions = transactions
	alpha := pid.CalculateAlpha()
	pid.StakingParams.MinimumStake = (currentReward * supply / float64(transactions)) * alpha
}

// CalculateInitialDifficulty determines the initial difficulty based on the blockchain's current state.
func (pid *PoSInitialDifficulty) CalculateInitialDifficulty() {
	totalStaked := 0.0
	for _, stake := range pid.Blockchain.Stakes {
		totalStaked += stake.Amount
	}
	difficulty := math.Log(totalStaked+1) // Logarithmic scale for difficulty calculation
	pid.Blockchain.Difficulty = uint32(difficulty)
}

// LockUpEnforcement manages the lock-up period for staked assets.
func (pid *PoSInitialDifficulty) LockUpEnforcement() {
	now := time.Now()
	for i, stake := range pid.Blockchain.Stakes {
		if now.Before(stake.StartTime.Add(stake.LockDuration)) {
			continue
		}
		// Free up staked tokens after lock-up period
		pid.Blockchain.Stakes[i].Owner = ""
	}
}

func main() {
	blockchain := NewPoSBlockchain()
	initialDifficulty := NewPoSInitialDifficulty(blockchain)

	// Simulating an update in staking parameters based on network data
	initialDifficulty.UpdateStakingParameters(500.0, 10000, 1000000.0)

	// Calculating initial difficulty based on updated staking parameters
	initialDifficulty.CalculateInitialDifficulty()

	// Enforcing lock-up periods
	initialDifficulty.LockUpEnforcement()
}
