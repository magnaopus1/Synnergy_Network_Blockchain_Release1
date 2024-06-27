package consensus

import (
    "math/big"
    "time"
    "fmt"
)

// PerformanceMetrics encapsulates the performance evaluation metrics for the PoS system
type PerformanceMetrics struct {
    BlockTimeAverage          time.Duration
    TransactionThroughput     float64
    NetworkParticipationRate  float64
    HistoricalBlockTimes      []time.Duration
}

// NewPerformanceMetrics initializes the performance metrics with default values
func NewPerformanceMetrics() *PerformanceMetrics {
    return &PerformanceMetrics{
        BlockTimeAverage: 10 * time.Second, // Assume initial average block time
        TransactionThroughput: 0,
        NetworkParticipationRate: 0,
        HistoricalBlockTimes: make([]time.Duration, 0),
    }
}

// UpdateBlockTime recalculates the average block time with the new block time
func (pm *PerformanceMetrics) UpdateBlockTime(newTime time.Duration) {
    pm.HistoricalBlockTimes = append(pm.HistoricalBlockTimes, newTime)
    var total time.Duration
    for _, t := range pm.HistoricalBlockTimes {
        total += t
    }
    pm.BlockTimeAverage = total / time.Duration(len(pm.HistoricalBlockTimes))
}

// CalculateThroughput updates the transaction throughput based on total transactions and the elapsed time
func (pm *PerformanceMetrics) CalculateThroughput(totalTransactions int, elapsedTime time.Duration) {
    if elapsedTime > 0 {
        pm.TransactionThroughput = float64(totalTransactions) / elapsedTime.Seconds()
    }
}

// UpdateParticipationRate updates the network participation rate based on the count of active and total validators
func (pm *PerformanceMetrics) UpdateParticipationRate(activeValidators, totalValidators int) {
    if totalValidators > 0 {
        pm.NetworkParticipationRate = (float64(activeValidators) / float64(totalValidators)) * 100
    }
}

// EvaluateNetworkHealth assesses overall network performance and returns a status report
func (pm *PerformanceMetrics) EvaluateNetworkHealth() string {
    // Simple logic to determine network health based on performance metrics
    if pm.NetworkParticipationRate > 75 && pm.BlockTimeAverage < 12*time.Second {
        return "Healthy"
    } else if pm.NetworkParticipationRate > 50 || pm.BlockTimeAverage < 20*time.Second {
        return "Moderate"
    }
    return "Critical"
}

// PrintMetrics provides a formatted output of the current network performance metrics
func (pm *PerformanceMetrics) PrintMetrics() {
    fmt.Printf("Block Time Average: %s\n", pm.BlockTimeAverage)
    fmt.Printf("Transaction Throughput: %.2f tx/sec\n", pm.TransactionThroughput)
    fmt.Printf("Network Participation Rate: %.2f%%\n", pm.NetworkParticipationRate)
}

