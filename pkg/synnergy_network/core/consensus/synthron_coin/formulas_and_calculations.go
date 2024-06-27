package synthron_coin

import (
	"errors"
	"math"
)

// Pricing parameters
const (
	BaseMultiplier = 1.0
)

// FormulaInput holds the input parameters for price calculation
type FormulaInput struct {
	OperationalCosts       float64
	DevelopmentCosts       float64
	SecurityCosts          float64
	ComplianceCosts        float64
	RiskProvision          float64
	InitialSupply          float64
	ProjectedDemand        float64
	AverageMarketPrice     float64
	ValueScores            []float64
	FeatureWeights         []float64
	CommunityPositiveVotes int64
	CommunityNegativeVotes int64
	TotalCommunityVotes    int64
}

// CalculateCostOfProduction calculates the cost of production (C)
func CalculateCostOfProduction(operationalCosts, developmentCosts, securityCosts float64) float64 {
	return operationalCosts + developmentCosts + securityCosts
}

// CalculateRegulatoryComplianceCosts calculates the regulatory and compliance costs (R)
func CalculateRegulatoryComplianceCosts(complianceCosts, riskProvision, estimatedVolume float64) float64 {
	return (complianceCosts + riskProvision) / estimatedVolume
}

// CalculateMarketComparables calculates the market comparables (M)
func CalculateMarketComparables(averageMarketPrice float64, valueScores, featureWeights []float64) (float64, error) {
	if len(valueScores) != len(featureWeights) {
		return 0, errors.New("valueScores and featureWeights arrays must have the same length")
	}

	totalWeight := 0.0
	weightedSum := 0.0

	for i, weight := range featureWeights {
		totalWeight += weight
		weightedSum += valueScores[i] * weight
	}

	return averageMarketPrice * (weightedSum / totalWeight), nil
}

// CalculateTokenomicsAdjustmentFactor calculates the tokenomics adjustment factor (T)
func CalculateTokenomicsAdjustmentFactor(initialSupply, projectedDemand float64) float64 {
	return initialSupply / projectedDemand
}

// CalculateCommunityAdjustmentFactor calculates the community and ecosystem adjustment multiplier (E)
func CalculateCommunityAdjustmentFactor(positiveVotes, negativeVotes, totalVotes int64) float64 {
	if totalVotes == 0 {
		return 1.0
	}
	return 1.0 + float64(positiveVotes-negativeVotes)/float64(totalVotes)
}

// CalculateInitialPrice calculates the initial price of Synthron Coin
func CalculateInitialPrice(input FormulaInput) (float64, error) {
	costOfProduction := CalculateCostOfProduction(input.OperationalCosts, input.DevelopmentCosts, input.SecurityCosts)
	regulatoryComplianceCosts := CalculateRegulatoryComplianceCosts(input.ComplianceCosts, input.RiskProvision, input.InitialSupply)
	marketComparables, err := CalculateMarketComparables(input.AverageMarketPrice, input.ValueScores, input.FeatureWeights)
	if err != nil {
		return 0, err
	}
	tokenomicsAdjustmentFactor := CalculateTokenomicsAdjustmentFactor(input.InitialSupply, input.ProjectedDemand)
	communityAdjustmentFactor := CalculateCommunityAdjustmentFactor(input.CommunityPositiveVotes, input.CommunityNegativeVotes, input.TotalCommunityVotes)

	return (costOfProduction + regulatoryComplianceCosts + (marketComparables / tokenomicsAdjustmentFactor)) * communityAdjustmentFactor, nil
}

// Additional Tokenomics Features

// InflationControlMechanism adjusts the emission rates based on network performance and economic indicators
func InflationControlMechanism(currentSupply, targetSupply float64) float64 {
	return math.Max(0.0, (targetSupply-currentSupply)/targetSupply)
}

// TokenBurningMechanism permanently removes a percentage of transaction fees from circulation
func TokenBurningMechanism(transactionFee, burnPercentage float64) float64 {
	return transactionFee * (burnPercentage / 100.0)
}

// TreasuryManagement manages the allocation of tokens for long-term sustainability and development
func TreasuryManagement(totalSupply float64, communityVotePercentage float64) float64 {
	return totalSupply * (communityVotePercentage / 100.0)
}

// RewardsRedistribution adjusts payouts based on validator performance, staking duration, and network participation levels
func RewardsRedistribution(totalRewards, validatorPerformance, stakingDuration, networkParticipation float64) float64 {
	return totalRewards * (validatorPerformance * stakingDuration * networkParticipation)
}
