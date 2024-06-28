package synthron_coin

import (
	"fmt"
	"math"
)

// EconomicFactors structure to hold all the factors affecting the price calculation
type EconomicFactors struct {
	CostOfProduction         float64
	RegulatoryCosts          float64
	AvgMarketPrice           float64
	ValueMultiplier          float64
	TokenomicsAdjustment     float64
	CommunityAdjustment      float64
}

// CalculateInitialPrice computes the initial price of Synthron Coin using the provided economic factors
func CalculateInitialPrice(factors EconomicFactors) float64 {
	valueComponent := (factors.AvgMarketPrice * factors.ValueMultiplier) / factors.TokenomicsAdjustment
	initialPrice := (factors.CostOfProduction + factors.RegulatoryCosts + valueComponent) * factors.CommunityAdjustment
	return initialPrice
}

// GetEconomicFactors fetches and computes all necessary economic factors for price calculation
func GetEconomicFactors() EconomicFactors {
	// Constants for demonstration purposes
	const (
		baseMarketPrice    = 2.0  // Hypothetical average market price of comparable coins
		baseValueMultiplier = 1.2 // Hypothetical value multiplier based on technology and use case
		baseTokenomicsAdjustment = 0.9 // Supply vs demand projected adjustment
		baseCommunityAdjustment = 1.1  // Community and ecosystem feedback adjustment
	)

	// Cost calculations
	costOfProduction := calculateProductionCost(100, 200, 50) // Example costs: operational, development, security
	regulatoryCosts := calculateRegulatoryCosts(20, 100000)   // Example costs with expected token sales volume

	return EconomicFactors{
		CostOfProduction:         costOfProduction,
		RegulatoryCosts:          regulatoryCosts,
		AvgMarketPrice:           baseMarketPrice,
		ValueMultiplier:          baseValueMultiplier,
		TokenomicsAdjustment:     baseTokenomicsAdjustment,
		CommunityAdjustment:      baseCommunityAdjustment,
	}
}

// calculateProductionCost calculates the total cost of production based on operational, development, and security costs
func calculateProductionCost(operationalCost, developmentCost, securityCost float64) float64 {
	return operationalCost + developmentCost + securityCost
}

// calculateRegulatoryCosts calculates the regulatory and compliance costs
func calculateRegulatoryCosts(regulatoryCost float64, salesVolume float64) float64 {
	riskProvision := 0.05 * regulatoryCost // 5% risk provision for unexpected changes
	return (regulatoryCost + riskProvision) / salesVolume
}