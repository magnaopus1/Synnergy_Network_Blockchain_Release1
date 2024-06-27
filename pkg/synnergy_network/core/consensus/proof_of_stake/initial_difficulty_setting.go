package consensus

import (
    "math"
    "time"
)

// Constants for adjusting difficulty and alpha dynamically
const (
    DefaultAlphaAdjustmentFactor = 0.05
    HighVolatilityThreshold      = 0.1
    LowVolatilityThreshold       = 0.05
    MinAlpha                     = 0.005
    MaxAlpha                     = 0.015
)

// DifficultySetting stores parameters for the PoS difficulty setting
type DifficultySetting struct {
    CurrentMiningReward float64
    CirculatingSupply   float64
    TransactionVolume   float64
    Alpha               float64
    LastAdjustmentTime  time.Time
}

// NewDifficultySetting initializes the difficulty setting with economic indicators
func NewDifficultySetting(reward, supply, volume, alpha float64) *DifficultySetting {
    return &DifficultySetting{
        CurrentMiningReward: reward,
        CirculatingSupply:   supply,
        TransactionVolume:   volume,
        Alpha:               alpha,
        LastAdjustmentTime:  time.Now(),
    }
}

// CalculateMinimumStake calculates the minimum stake required using the formula from the whitepaper
func (ds *DifficultySetting) CalculateMinimumStake() float64 {
    return (ds.TransactionVolume * ds.CurrentMiningReward / ds.CirculatingSupply) * ds.Alpha
}

// AdjustDifficulty adjusts the difficulty based on transaction volume and market conditions
func (ds *DifficultySetting) AdjustDifficulty(newVolume float64, marketConditions MarketConditions) {
    ds.Alpha = ds.calculateAlpha(marketConditions.VolatilityIndex)
    ds.TransactionVolume = newVolume
    ds.LastAdjustmentTime = time.Now()
}

// calculateAlpha dynamically calculates the new Alpha value based on market volatility and other conditions
func (ds *DifficultySetting) calculateAlpha(volatility float64) float64 {
    // Adjust alpha based on a volatility index and check against bounds
    adjustment := volatility * DefaultAlphaAdjustmentFactor
    if volatility > HighVolatilityThreshold {
        ds.Alpha += adjustment
    } else if volatility < LowVolatilityThreshold {
        ds.Alpha -= adjustment
    }

    // Ensure alpha stays within specified bounds
    if ds.Alpha < MinAlpha {
        ds.Alpha = MinAlpha
    } else if ds.Alpha > MaxAlpha {
        ds.Alpha = MaxAlpha
    }
    return ds.Alpha
}

// MarketConditions struct to encapsulate various dynamic metrics affecting the blockchain
type MarketConditions struct {
    VolatilityIndex float64
}


