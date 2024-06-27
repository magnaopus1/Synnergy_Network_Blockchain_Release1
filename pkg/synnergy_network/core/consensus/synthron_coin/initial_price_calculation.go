package synthron_coin

import (
	"errors"
	"fmt"
)

// Constants for pricing formula
const (
	BaseMultiplier            = 1.0
	CommunityAndEcosystemBase = 1.0
)

// CostFactors holds the various cost factors involved in price calculation
type CostFactors struct {
	OperationalCosts  float64
	DevelopmentCosts  float64
	SecurityCosts     float64
	ComplianceCosts   float64
	RiskProvision     float64
	InitialVolume     float64
}

// MarketComparables holds the market comparable data for price adjustment
type MarketComparables struct {
	ComparablePrices []float64
	FeatureWeights   []float64
}

// ValueFactors holds the value proposition data
type ValueFactors struct {
	TechnologyAdvancement float64
	UseCaseBreadth        float64
	MarketDifferentiation float64
}

// CommunityInput holds the community input metrics
type CommunityInput struct {
	PositiveFeedback float64
	NegativeFeedback float64
	TotalFeedback    float64
}

// InitialPriceCalculator handles the calculation of initial price
type InitialPriceCalculator struct {
	CostFactors       CostFactors
	MarketComparables MarketComparables
	ValueFactors      ValueFactors
	CommunityInput    CommunityInput
	TokenSupply       float64
	ProjectedDemand   float64
}

// CalculateCostOfProduction calculates the total cost of production per unit
func (ipc *InitialPriceCalculator) CalculateCostOfProduction() float64 {
	return ipc.CostFactors.OperationalCosts + ipc.CostFactors.DevelopmentCosts + ipc.CostFactors.SecurityCosts
}

// CalculateMarketComparable calculates the average market comparable price
func (ipc *InitialPriceCalculator) CalculateMarketComparable() (float64, error) {
	if len(ipc.MarketComparables.ComparablePrices) != len(ipc.MarketComparables.FeatureWeights) {
		return 0, errors.New("mismatch in length of comparable prices and feature weights")
	}

	var totalWeightedPrice float64
	for i, price := range ipc.MarketComparables.ComparablePrices {
		totalWeightedPrice += price * ipc.MarketComparables.FeatureWeights[i]
	}
	return totalWeightedPrice / float64(len(ipc.MarketComparables.ComparablePrices)), nil
}

// CalculateValueProposition calculates the value proposition multiplier
func (ipc *InitialPriceCalculator) CalculateValueProposition() float64 {
	return BaseMultiplier + ipc.ValueFactors.TechnologyAdvancement + ipc.ValueFactors.UseCaseBreadth + ipc.ValueFactors.MarketDifferentiation
}

// CalculateRegulatoryCosts calculates the regulatory and compliance costs per unit
func (ipc *InitialPriceCalculator) CalculateRegulatoryCosts() float64 {
	return (ipc.CostFactors.ComplianceCosts + ipc.CostFactors.RiskProvision) / ipc.CostFactors.InitialVolume
}

// CalculateTokenomicsAdjustment calculates the tokenomics adjustment factor
func (ipc *InitialPriceCalculator) CalculateTokenomicsAdjustment() float64 {
	return ipc.TokenSupply / ipc.ProjectedDemand
}

// CalculateCommunityAdjustment calculates the community and ecosystem adjustment multiplier
func (ipc *InitialPriceCalculator) CalculateCommunityAdjustment() float64 {
	return CommunityAndEcosystemBase + ((ipc.CommunityInput.PositiveFeedback - ipc.CommunityInput.NegativeFeedback) / ipc.CommunityInput.TotalFeedback)
}

// CalculateInitialPrice calculates the initial price of Synthron Coin
func (ipc *InitialPriceCalculator) CalculateInitialPrice() (float64, error) {
	costOfProduction := ipc.CalculateCostOfProduction()
	regulatoryCosts := ipc.CalculateRegulatoryCosts()
	marketComparable, err := ipc.CalculateMarketComparable()
	if err != nil {
		return 0, err
	}
	valueProposition := ipc.CalculateValueProposition()
	tokenomicsAdjustment := ipc.CalculateTokenomicsAdjustment()
	communityAdjustment := ipc.CalculateCommunityAdjustment()

	initialPrice := (costOfProduction + regulatoryCosts + (marketComparable * valueProposition / tokenomicsAdjustment)) * communityAdjustment
	return initialPrice, nil
}

