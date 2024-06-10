package synthron_coin

import (
	"fmt"
	"log"
	"math"
)

// EconomicFactors holds all the parameters needed to calculate the coin's initial price.
type EconomicFactors struct {
	CostOfProduction      float64
	RegulatoryCosts       float64
	MarketAvgPrice        float64
	ValueMultiplier       float64
	TokenomicsAdjustment  float64
	CommunityInput        float64
}

// CoinPriceCalculator provides methods to compute and manage the pricing of Synthron coins.
type CoinPriceCalculator struct {
	factors EconomicFactors
}

// NewCoinPriceCalculator creates a new calculator instance with given economic factors.
func NewCoinPriceCalculator(factors EconomicFactors) *CoinPriceCalculator {
	return &CoinPriceCalculator{
		factors: factors,
	}
}

// CalculateInitialPrice computes the initial price of Synthron coin using the formula provided in the whitepaper.
func (calc *CoinPriceCalculator) CalculateInitialPrice() float64 {
	// (C + R + ((M * V) / T)) * E
	c := calc.factors.CostOfProduction
	r := calc.factors.RegulatoryCosts
	m := calc.factors.MarketAvgPrice
	v := calc.factors.ValueMultiplier
	t := calc.factors.TokenomicsAdjustment
	e := calc.factors.CommunityInput

	if t == 0 { // Avoid division by zero
		log.Println("Tokenomics adjustment factor cannot be zero.")
		return 0
	}

	price := (c + r + ((m * v) / t)) * e
	return price
}

func main() {
	// Setup initial economic factors
	factors := EconomicFactors{
		CostOfProduction:      0.5,  // Example values
		RegulatoryCosts:       0.2,
		MarketAvgPrice:        3.0,
		ValueMultiplier:       1.5,
		TokenomicsAdjustment:  1.1,
		CommunityInput:        1.05,
	}

	calculator := NewCoinPriceCalculator(factors)
	initialPrice := calculator.CalculateInitialPrice()
	fmt.Printf("Initial price of Synthron Coin: $%.2f\n", initialPrice)
}
