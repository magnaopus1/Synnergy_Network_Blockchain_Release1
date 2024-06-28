package synthron_coin

import (
	"errors"
	"math"
)

// Constants for economic parameters
const (
	InitialCoinSupply      = 500000000 // Total coin supply
	InitialBlockReward     = 50        // Initial reward for mining a block
	HalvingInterval        = 200000    // Number of blocks after which reward is halved
	BlockGenerationTime    = 10 * 60   // Block generation time in seconds
)

// CalculateHalving calculates the current block reward based on the block number.
func CalculateHalving(currentBlock int) float64 {
	halvings := currentBlock / HalvingInterval
	if halvings > 64 { // Maximum halvings that can occur
		halvings = 64
	}
	return InitialBlockReward / math.Pow(2, float64(halvings))
}

// InflationRate calculates the annual inflation rate based on the current supply and emission rate.
func InflationRate(currentSupply float64, annualEmission float64) float64 {
	return (annualEmission / currentSupply) * 100
}

// CalculateEmissionRate calculates the number of new coins introduced per year based on current block reward.
func CalculateEmissionRate(currentBlock int) float64 {
	reward := CalculateHalving(currentBlock)
	blocksPerYear := (365.25 * 24 * 3600) / BlockGenerationTime
	return reward * blocksPerYear
}

// AdjustRewardDistribution dynamically adjusts reward distribution among validators based on their performance and stake duration.
func AdjustRewardDistribution(totalReward float64, performanceScore float64, stakeDuration int) float64 {
	// Example: More weight given to longer stake durations and higher performance scores
	baseReward := totalReward * 0.5 // 50% of rewards are split equally
	performanceReward := (totalReward * 0.5) * (performanceScore / 100) // Up to 50% based on performance
	stakeMultiplier := 1 + (float64(stakeDuration)/365) // Additional bonus for each year staked

	return (baseReward + performanceReward) * stakeMultiplier
}

// TokenBurningRate calculates the amount of tokens to be burned based on the transaction volume.
func TokenBurningRate(transactionVolume float64, burnRate float64) float64 {
	return transactionVolume * (burnRate / 100)
}

// EconomicAdjustment reacts to changes in network performance and external economic conditions to adjust token metrics.
func EconomicAdjustment(currentConditions string) (float64, error) {
	switch currentConditions {
	case "high_demand":
		return 0.02, nil // Increase emission by 2%
	case "low_demand":
		return -0.02, nil // Decrease emission by 2%
	default:
		return 0, errors.New("undefined economic condition")
	}
}

var (
	ErrUndefinedCondition = errors.New("undefined economic condition")
)
