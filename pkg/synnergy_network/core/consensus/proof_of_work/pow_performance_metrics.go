package consensus

import (
    "sync"
    "time"
    "math/big"
)

// PerformanceMetrics encapsulates monitoring tools for the blockchain's mining process
type PerformanceMetrics struct {
    Blockchain *Blockchain
    lock       sync.Mutex
}

// NewPerformanceMetrics initializes a new instance with a blockchain reference
func NewPerformanceMetrics(blockchain *Blockchain) *PerformanceMetrics {
    return &PerformanceMetrics{
        Blockchain: blockchain,
    }
}

// MonitorHashRate calculates and reports the current hash rate of the blockchain
func (pm *PerformanceMetrics) MonitorHashRate() float64 {
    pm.lock.Lock()
    defer pm.lock.Unlock()

    lastBlock := pm.Blockchain.Blocks[len(pm.Blockchain.Blocks)-1]
    if len(pm.Blockchain.Blocks) < 2 {
        return 0
    }

    previousBlock := pm.Blockchain.Blocks[len(pm.Blockchain.Blocks)-2]
    timeDiff := lastBlock.Timestamp - previousBlock.Timestamp
    if timeDiff == 0 {
        return float64(infinity)
    }

    // Hash rate as hashes per second
    return float64(1) / float64(timeDiff)
}

// CalculateMiningEfficiency evaluates the energy cost versus reward gained per block
func (pm *PerformanceMetrics) CalculateMiningEfficiency() float64 {
    pm.lock.Lock()
    defer pm.lock.Unlock()

    totalEnergyCost := 0.0
    totalRewards := 0.0

    for _, block := range pm.Blockchain.Blocks {
        totalEnergyCost += calculateEnergyCostForBlock(block)
        totalRewards += float64(block.Reward)
    }

    if totalEnergyCost == 0 {
        return float64(infinity)
    }

    return totalRewards / totalEnergyCost
}

// calculateEnergyCostForBlock estimates the energy used to mine a specific block
func calculateEnergyCostForBlock(block *Block) float64 {
    // Energy cost can be calculated based on the difficulty and time spent
    return float64(block.Difficulty) * 0.1 // Simplified example
}

// TrackRewardDistribution monitors how rewards are distributed among miners to ensure fairness
func (pm *PerformanceMetrics) TrackRewardDistribution() map[string]float64 {
    pm.lock.Lock()
    defer pm.lock.Unlock()

    distribution := make(map[string]float64)
    for _, block := range pm.Blockchain.Blocks {
        miner := block.MinerAddress
        distribution[miner] += float64(block.Reward)
    }
    return distribution
}

// ReportNetworkHealth calculates and reports various metrics to gauge the overall health of the blockchain network
func (pm *PerformanceMetrics) ReportNetworkHealth() map[string]float64 {
    healthMetrics := make(map[string]float64)
    healthMetrics["hashRate"] = pm.MonitorHashRate()
    healthMetrics["efficiency"] = pm.CalculateMiningEfficiency()
    healthMetrics["rewardEquality"] = calculateGiniCoefficient(pm.TrackRewardDistribution())

    return healthMetrics
}

// calculateGiniCoefficient computes the Gini coefficient for reward distribution to assess economic inequality
func calculateGiniCoefficient(distribution map[string]float64) float64 {
    var totalRewards, sumOfAbsoluteDifferences, mean float64
    for _, reward := range distribution {
        totalRewards += reward
    }
    mean = totalRewards / float64(len(distribution))

    for _, rewardA := range distribution {
        for _, rewardB := range distribution {
            sumOfAbsoluteDifferences += abs(rewardA - rewardB)
        }
    }

    return sumOfAbsoluteDifferences / (2 * float64(len(distribution)) * totalRewards)
}

// abs calculates the absolute value of a float64
func abs(x float64) float64 {
    if x < 0 {
        return -x
    }
    return x
}

