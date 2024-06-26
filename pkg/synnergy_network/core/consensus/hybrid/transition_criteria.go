package synthron_coin

import (
	"fmt"
	"math/rand"
	"time"
)

// ConsensusConfig holds configuration for each type of consensus mechanism.
type ConsensusConfig struct {
	NetworkLoadThreshold    float64
	SecurityThreatThreshold float64
	StakeConcentrationLimit float64
}

// HybridConsensusManager manages the state and operations of the hybrid consensus mechanisms.
type HybridConsensusManager struct {
	currentMode      string
	consensusConfigs ConsensusConfig
}

// NewHybridConsensusManager creates a new manager for handling consensus transitions.
func NewHybridConsensusManager() *HybridConsensusManager {
	return &HybridConsensusManager{
		currentMode: "PoW", // Initialize with Proof of Work
		consensusConfigs: ConsensusConfig{
			NetworkLoadThreshold:    75.0,
			SecurityThreatThreshold: 0.2,
			StakeConcentrationLimit: 50.0,
		},
	}
}

// EvaluateNetworkConditions checks current network conditions and adjusts the consensus mode accordingly.
func (hcm *HybridConsensusManager) EvaluateNetworkConditions(networkLoad float64, securityLevel float64, stakeConcentration float64) {
	switch {
	case securityLevel > hcm.consensusConfigs.SecurityThreatThreshold:
		hcm.switchToConsensusMode("PoW")
	case stakeConcentration > hcm.consensusConfigs.StakeConcentrationLimit:
		hcm.switchToConsensusMode("PoS")
	case networkLoad > hcm.consensusConfigs.NetworkLoadThreshold:
		hcm.switchToConsensusMode("PoH")
	default:
		hcm.maintainCurrentMode()
	}
}

// switchToConsensusMode updates the current consensus mode based on conditions.
func (hcm *HybridConsensusManager) switchToConsensusMode(mode string) {
	if hcm.currentMode != mode {
		fmt.Printf("Switching consensus mode from %s to %s\n", hcm.currentMode, mode)
		hcm.currentMode = mode
	}
}

// maintainCurrentMode keeps the current consensus mode if no changes are needed.
func (hcm *HybridConsensusManager) maintainCurrentMode() {
	fmt.Println("Maintaining current consensus mode:", hcm.currentMode)
}

func main() {
	consensusManager := NewHybridConsensusManager()

	// Simulate changing network conditions
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Randomly generated conditions for demonstration
		networkLoad := rand.Float64() * 100
		securityLevel := rand.Float64()
		stakeConcentration := rand.Float64() * 100

		fmt.Printf("Evaluating conditions: Network Load=%.2f, Security Level=%.2f, Stake Concentration=%.2f\n", networkLoad, securityLevel, stakeConcentration)
		consensusManager.EvaluateNetworkConditions(networkLoad, securityLevel, stakeConcentration)
	}
}
