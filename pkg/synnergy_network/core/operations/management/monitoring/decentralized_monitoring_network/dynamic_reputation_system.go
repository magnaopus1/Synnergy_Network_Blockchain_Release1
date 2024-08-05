package decentralized_monitoring_network

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// Node represents a network node participating in the reputation system
type Node struct {
	ID           string
	Reputation   float64
	LastActivity time.Time
	Reports      int
}

// ReputationSystem manages the reputation scores of nodes
type ReputationSystem struct {
	Nodes          map[string]*Node
	DecayRate      float64
	Threshold      float64
	PenaltyFactor  float64
	RewardFactor   float64
	UpdateInterval time.Duration
}

// NewReputationSystem initializes a new ReputationSystem
func NewReputationSystem(decayRate, threshold, penaltyFactor, rewardFactor float64, updateInterval time.Duration) *ReputationSystem {
	return &ReputationSystem{
		Nodes:          make(map[string]*Node),
		DecayRate:      decayRate,
		Threshold:      threshold,
		PenaltyFactor:  penaltyFactor,
		RewardFactor:   rewardFactor,
		UpdateInterval: updateInterval,
	}
}

// AddNode adds a new node to the reputation system
func (rs *ReputationSystem) AddNode(nodeID string) {
	rs.Nodes[nodeID] = &Node{
		ID:           nodeID,
		Reputation:   1.0, // Default initial reputation
		LastActivity: time.Now(),
		Reports:      0,
	}
}

// ReportActivity updates the last activity timestamp for a node
func (rs *ReputationSystem) ReportActivity(nodeID string) error {
	node, exists := rs.Nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}
	node.LastActivity = time.Now()
	node.Reports++
	return nil
}

// PenalizeNode decreases the reputation of a node based on the penalty factor
func (rs *ReputationSystem) PenalizeNode(nodeID string) error {
	node, exists := rs.Nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}
	node.Reputation -= rs.PenaltyFactor
	if node.Reputation < 0 {
		node.Reputation = 0
	}
	return nil
}

// RewardNode increases the reputation of a node based on the reward factor
func (rs *ReputationSystem) RewardNode(nodeID string) error {
	node, exists := rs.Nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}
	node.Reputation += rs.RewardFactor
	if node.Reputation > 1 {
		node.Reputation = 1
	}
	return nil
}

// DecayReputation decays the reputation of all nodes over time
func (rs *ReputationSystem) DecayReputation() {
	for _, node := range rs.Nodes {
		timeSinceLastActivity := time.Since(node.LastActivity).Hours() / 24 // Convert to days
		decay := math.Exp(-rs.DecayRate * timeSinceLastActivity)
		node.Reputation *= decay
		if node.Reputation < rs.Threshold {
			node.Reputation = 0
		}
	}
}

// UpdateReputations periodically updates the reputation of all nodes
func (rs *ReputationSystem) UpdateReputations() {
	ticker := time.NewTicker(rs.UpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rs.DecayReputation()
		}
	}
}

// GetReputation returns the reputation score of a node
func (rs *ReputationSystem) GetReputation(nodeID string) (float64, error) {
	node, exists := rs.Nodes[nodeID]
	if !exists {
		return 0, errors.New("node not found")
	}
	return node.Reputation, nil
}

// Example usage (not to be included in production code)
func main() {
	rs := NewReputationSystem(0.1, 0.5, 0.2, 0.1, time.Hour)
	rs.AddNode("node1")
	rs.ReportActivity("node1")
	rs.RewardNode("node1")
	rs.PenalizeNode("node1")

	go rs.UpdateReputations()

	time.Sleep(2 * time.Hour)
	rep, _ := rs.GetReputation("node1")
	fmt.Println("Reputation of node1:", rep)
}
