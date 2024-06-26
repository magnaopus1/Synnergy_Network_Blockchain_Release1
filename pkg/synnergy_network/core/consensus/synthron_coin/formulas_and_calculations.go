package synthron_coin

import (
	"errors"
	"fmt"
	"math"
	"sync"
)

// EconomicParameters defines all the economic variables needed for the calculations.
type EconomicParameters struct {
	OperationalCosts      float64
	DevelopmentCosts      float64
	SecurityCosts         float64
	TotalComplianceCosts  float64
	RiskProvision         float64
	InitialSupply         float64
	ProjectedDemand       float64
	BaseMultiplier        float64
	FeatureWeight         map[string]float64
	ValueScores           map[string]float64
	PositiveFeedback      float64
	NegativeFeedback      float64
	TotalFeedback         float64
	ComparablePrices      []float64
	NumberComparables     float64
	CommunityEngagement   float64
	StakeholderEngagement float64
}

// CalculateCostOfProduction computes the total cost of producing one unit of Synthron.
func (ep *EconomicParameters) CalculateCostOfProduction() float64 {
	return ep.OperationalCosts + ep.DevelopmentCosts + ep.SecurityCosts
}

// CalculateMarketComparable derives an adjusted average price based on comparables and feature weight.
func (ep *EconomicParameters) CalculateMarketComparable() (float64, error) {
	if ep.NumberComparables == 0 {
		return 0, errors.New("number of comparables cannot be zero")
	}
	var sum float64
	for _, price := range ep.ComparablePrices {
		sum += price
	}
	return sum / ep.NumberComparables, nil
}

// CalculateValuePropositionMultiplier computes the multiplier based on the advanced technology and market differentiation.
func (ep *EconomicParameters) CalculateValuePropositionMultiplier() float64 {
	totalScore := 0.0
	for feature, score := range ep.ValueScores {
		totalScore += score * ep.FeatureWeight[feature]
	}
	return ep.BaseMultiplier + totalScore
}

// CalculateRegulatoryCosts estimates the per-unit regulatory costs.
func (ep *EconomicParameters) CalculateRegulatoryCosts(estimatedVolume float64) float64 {
	if estimatedVolume == 0 {
		return 0
	}
	return (ep.TotalComplianceCosts + ep.RiskProvision) / estimatedVolume
}

// CalculateTokenomicsAdjustmentFactor determines the adjustment factor based on token supply and demand forecasts.
func (ep *EconomicParameters) CalculateTokenomicsAdjustmentFactor() float64 {
	if ep.ProjectedDemand == 0 {
		return 0
	}
	return ep.InitialSupply / ep.ProjectedDemand
}

// CalculateCommunityAndEcosystemInput computes the community input factor.
func (ep *EconomicParameters) CalculateCommunityAndEcosystemInput() float64 {
	if ep.TotalFeedback == 0 {
		return 1
	}
	return 1 + ((ep.PositiveFeedback - ep.NegativeFeedback) / ep.TotalFeedback)
}

// CalculateInitialPrice computes the initial price of Synthron using all economic factors.
func (ep *EconomicParameters) CalculateInitialPrice() (float64, error) {
	c := ep.CalculateCostOfProduction()
	r, err := ep.CalculateRegulatoryCosts(1000) // Assume initial volume of 1000 units for demonstration
	if err != nil {
		return 0, err
	}
	m, err := ep.CalculateMarketComparable()
	if err != nil {
		return 0, err
	}
	v := ep.CalculateValuePropositionMultiplier()
	t := ep.CalculateTokenomicsAdjustmentFactor()
	e := ep.CalculateCommunityAndEcosystemInput()

	initialPrice := (c + r + ((m * v) / t)) * e
	return initialPrice, nil
}

func main() {
	// Concurrency example using WaitGroup and Mutex for updating parameters
	var wg sync.WaitGroup
	var mu sync.Mutex
	params := EconomicParameters{
		OperationalCosts:      100000,
		DevelopmentCosts:      500000,
		SecurityCosts:         150000,
		TotalComplianceCosts:  50000,
		RiskProvision:         10000,
		InitialSupply:         500000000,
		ProjectedDemand:       750000000,
		BaseMultiplier:        1.5,
		FeatureWeight:         map[string]float64{"Technology": 0.4, "UseCase": 0.6},
		ValueScores:           map[string]float64{"Technology": 2, "UseCase": 3},
		PositiveFeedback:      800,
		NegativeFeedback:      200,
		TotalFeedback:         1000,
		ComparablePrices:      []float64{0.5, 0.75, 0.65},
		NumberComparables:     3,
		CommunityEngagement:   500,
		StakeholderEngagement: 300,
	}

	// Example concurrent update of parameters
	wg.Add(1)
	go func() {
		defer wg.Done()
		mu.Lock()
		params.OperationalCosts += 50000 // Simulating an operational cost change
		mu.Unlock()
	}()

	wg.Wait()

	price, err := params.CalculateInitialPrice()
	if err != nil {
		fmt.Printf("Error calculating initial price: %s\n", err)
	} else {
		fmt.Printf("Calculated Initial Price of Synthron: $%.2f\n", price)
	}
}
