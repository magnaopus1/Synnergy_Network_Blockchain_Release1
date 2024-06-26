// Package decentralized_storage handles the incentivization strategy for network participants.
// This file includes functionalities to reward nodes for their storage and bandwidth contributions.
package decentralized_storage

import (
	"sync"
	"time"

	"synthron_blockchain/pkg/crypto"
	"synthron_blockchain/pkg/network"
)

// IncentivizationManager manages the distribution of rewards to nodes participating in the decentralized storage system.
type IncentivizationManager struct {
	nodeRewards      map[string]uint64
	mutex            sync.Mutex
	rewardCalculator RewardCalculator
	networkManager   *network.Manager
}

// RewardCalculator defines the logic to calculate the rewards based on storage and network contribution.
type RewardCalculator interface {
	CalculateReward(storageSize uint64, bandwidthUsage uint64) uint64
}

// SimpleRewardCalculator calculates rewards based purely on storage size and bandwidth.
type SimpleRewardCalculator struct {
	storageRate uint64 // Reward coins per gigabyte stored per month
	bandwidthRate uint64 // Reward coins per gigabyte of data transferred
}

// CalculateReward implements the RewardCalculator interface.
func (calc *SimpleRewardCalculator) CalculateReward(storageSize uint64, bandwidthUsage uint64) uint64 {
	return (storageSize * calc.storageRate) + (bandwidthUsage * calc.bandwidthRate)
}

// NewIncentivizationManager creates an instance of IncentivizationManager.
func NewIncentivizationManager(networkManager *network.Manager) *IncentivizationManager {
	return &IncentivizationManager{
		nodeRewards:    make(map[string]uint64),
		rewardCalculator: &SimpleRewardCalculator{storageRate: 1, bandwidthRate: 2},
		networkManager: networkManager,
	}
}

// RewardNode calculates and updates the reward for a node based on its storage and bandwidth usage.
func (im *IncentivizationManager) RewardNode(nodeID string, storageUsed uint64, bandwidthUsed uint64) {
	reward := im.rewardCalculator.CalculateReward(storageUsed, bandwidthUsed)

	im.mutex.Lock()
	im.nodeRewards[nodeID] += reward
	im.mutex.Unlock()

	// Log the reward for auditing purposes
	im.networkManager.LogEvent("Reward Node", nodeID, reward)
}

// DistributeRewards triggers the distribution of stored Synthron coins to all participating nodes.
func (im *IncentivizationManager) DistributeRewards() {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	for nodeID, reward := range im.nodeRewards {
		if reward > 0 {
			// Assuming a function to transfer coins to the node's wallet
			if err := im.networkManager.TransferCoins(nodeID, reward); err != nil {
				continue // log and handle errors appropriately
			}
			// Reset the reward after distribution
			im.nodeRewards[nodeID] = 0
			im.networkManager.LogEvent("Distributed Reward", nodeID, reward)
		}
	}
}

// PeriodicRewardDistribution starts the periodic distribution of rewards.
func (im *IncentivizationManager) PeriodicRewardDistribution(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			im.DistributeRewards()
		}
	}
}

// Example usage
func main() {
	networkManager := network.NewManager() // Assuming a network manager setup
	incentManager := NewIncentivizationManager(networkManager)
	go incentManager.PeriodicRewardDistribution(time.Hour * 24) // Distribute daily

	// Simulating node activity
	incentManager.RewardNode("node1", 1024, 500) // 1024 GB stored, 500 GB transferred
	incentManager.RewardNode("node2", 2048, 1000) // 2048 GB stored, 1000 GB transferred
}
