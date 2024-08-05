package liquidity

import (
	"fmt"
	"log"
	"math"
	"time"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// RiskAssessment represents the risk assessment structure
type RiskAssessment struct {
	AssetID        string
	LiquidityPool  string
	RiskScore      float64
	LastUpdated    time.Time
	mutex          sync.Mutex
}

// RiskAssessor manages risk assessment calculations
type RiskAssessor struct {
	assessments map[string]*RiskAssessment
	mutex       sync.Mutex
}

// NewRiskAssessor creates a new RiskAssessor
func NewRiskAssessor() *RiskAssessor {
	return &RiskAssessor{
		assessments: make(map[string]*RiskAssessment),
	}
}

// CalculateRiskScore calculates the risk score for a given asset in a liquidity pool
func (ra *RiskAssessor) CalculateRiskScore(assetID, liquidityPool string, liquidity, volatility, externalFactors float64) float64 {
	// Simplified risk score calculation using a weighted sum of factors
	liquidityWeight := 0.5
	volatilityWeight := 0.3
	externalFactorsWeight := 0.2

	riskScore := liquidityWeight*math.Log(liquidity+1) + volatilityWeight*volatility + externalFactorsWeight*externalFactors
	return riskScore
}

// UpdateRiskAssessment updates the risk assessment for a given asset in a liquidity pool
func (ra *RiskAssessor) UpdateRiskAssessment(assetID, liquidityPool string, liquidity, volatility, externalFactors float64) {
	ra.mutex.Lock()
	defer ra.mutex.Unlock()

	riskScore := ra.CalculateRiskScore(assetID, liquidityPool, liquidity, volatility, externalFactors)
	assessment := &RiskAssessment{
		AssetID:       assetID,
		LiquidityPool: liquidityPool,
		RiskScore:     riskScore,
		LastUpdated:   time.Now(),
	}

	hash := sha256.Sum256([]byte(assetID + liquidityPool))
	assessmentID := hex.EncodeToString(hash[:])

	ra.assessments[assessmentID] = assessment
	log.Printf("Updated risk assessment for asset %s in liquidity pool %s: Risk Score = %.2f", assetID, liquidityPool, riskScore)
}

// GetRiskAssessment retrieves the risk assessment for a given asset in a liquidity pool
func (ra *RiskAssessor) GetRiskAssessment(assetID, liquidityPool string) (*RiskAssessment, error) {
	ra.mutex.Lock()
	defer ra.mutex.Unlock()

	hash := sha256.Sum256([]byte(assetID + liquidityPool))
	assessmentID := hex.EncodeToString(hash[:])

	assessment, exists := ra.assessments[assessmentID]
	if !exists {
		return nil, fmt.Errorf("risk assessment not found for asset %s in liquidity pool %s", assetID, liquidityPool)
	}

	return assessment, nil
}

// MonitorRisk continuously monitors and updates the risk assessments based on new data
func (ra *RiskAssessor) MonitorRisk(dataChannel chan RiskData) {
	for data := range dataChannel {
		ra.UpdateRiskAssessment(data.AssetID, data.LiquidityPool, data.Liquidity, data.Volatility, data.ExternalFactors)
	}
}

// RiskData represents the data used for risk assessment
type RiskData struct {
	AssetID        string
	LiquidityPool  string
	Liquidity      float64
	Volatility     float64
	ExternalFactors float64
}

// StartRiskMonitoring starts monitoring risk assessments with simulated data
func StartRiskMonitoring(ra *RiskAssessor, dataChannel chan RiskData) {
	go ra.MonitorRisk(dataChannel)

	// Simulate incoming data
	for {
		simulatedData := RiskData{
			AssetID:        "asset123",
			LiquidityPool:  "poolXYZ",
			Liquidity:      1000.0,
			Volatility:     0.2,
			ExternalFactors: 0.1,
		}
		dataChannel <- simulatedData
		time.Sleep(10 * time.Second)
	}
}
