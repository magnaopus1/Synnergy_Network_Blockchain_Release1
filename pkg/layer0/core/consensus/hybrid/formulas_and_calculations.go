package synthron_coin

import (
	"errors"
	"math"
	"math/rand"
	"time"
)

// NetworkParameters holds the dynamic values that affect consensus mechanism transitions.
type NetworkParameters struct {
	TransactionVolume  int
	BlockTime          float64
	NetworkHashRate    float64
	SecurityThreats    bool
	StakeDistribution  map[string]float64
}

// ConsensusSystem manages the state and operations of the consensus mechanisms.
type ConsensusSystem struct {
	CurrentConsensus string
	Params           NetworkParameters
}

// NewConsensusSystem initializes a consensus system with default values.
func NewConsensusSystem() *ConsensusSystem {
	return &ConsensusSystem{
		CurrentConsensus: "PoW", // Start with Proof of Work
		Params: NetworkParameters{
			StakeDistribution: make(map[string]float64),
		},
	}
}

// AdjustConsensus transitions the consensus mechanism based on network conditions.
func (cs *ConsensusSystem) AdjustConsensus() {
	alpha := 0.6  // Emphasis on network demand
	beta := 0.4   // Emphasis on stake concentration
	networkDemand := cs.calculateNetworkDemand()
	stakeConcentration := cs.calculateStakeConcentration()

	threshold := alpha*networkDemand + beta*stakeConcentration

	if threshold > 100 || cs.Params.SecurityThreats {
		cs.CurrentConsensus = "PoW"
	} else if stakeConcentration > 50 {
		cs.CurrentConsensus = "PoS"
	} else {
		cs.CurrentConsensus = "PoH"
	}

	cs.logConsensusState()
}

// calculateNetworkDemand computes a metric based on transaction volume and block time.
func (cs *ConsensusSystem) calculateNetworkDemand() float64 {
	// Simplified demand calculation
	return float64(cs.Params.TransactionVolume) / cs.Params.BlockTime
}

// calculateStakeConcentration calculates the proportion of coins staked.
func (cs *ConsensusSystem) calculateStakeConcentration() float64 {
	totalStaked := 0.0
	for _, stake := range cs.Params.StakeDistribution {
		totalStaked += stake
	}
	return totalStaked / 500000000 // total supply
}

// logConsensusState prints the current state of the consensus mechanism.
func (cs *ConsensusSystem) logConsensusState() {
	println("Current Consensus Mechanism:", cs.CurrentConsensus)
}

// SimulateNetworkConditions changes network parameters to simulate real-world scenarios.
func (cs *ConsensusSystem) SimulateNetworkConditions() {
	// Example of adjusting network conditions
	cs.Params.TransactionVolume = rand.Intn(1000)
	cs.Params.BlockTime = rand.Float64() * 10
	cs.Params.SecurityThreats = (rand.Int31n(2) == 1)
}

func main() {
	consensus := NewConsensusSystem()

	// Simulating changes in network conditions and adjusting consensus every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		consensus.SimulateNetworkConditions()
		consensus.AdjustConsensus()
	}
}
