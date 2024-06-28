package synthron_coin

import (
	"time"

	"synnergy_network_blockchain/pkg/synnergy_network/core/utils"
)

// PerformanceMetrics encapsulates various performance metrics of the Synthron Coin within the network.
type PerformanceMetrics struct {
	TransactionThroughput      float64 // Transactions per second
	CirculationVelocity        float64 // Rate at which coins change hands
	NetworkParticipationRate   float64 // Percentage of active nodes relative to total nodes
	AverageTransactionValue    float64 // Average value of transactions
	BlockchainGrowthRate       float64 // Rate at which the size of the blockchain is increasing
	StakeParticipationRatio    float64 // Ratio of staked coins to total circulating supply
	TransactionConfirmationTime float64 // Average time it takes to confirm a transaction
}

// CalculateTransactionThroughput calculates the number of transactions per unit time.
func (pm *PerformanceMetrics) CalculateTransactionThroughput(transactions int, duration time.Duration) {
	pm.TransactionThroughput = float64(transactions) / duration.Seconds()
}

// UpdateCirculationVelocity updates the rate at which coins change hands within the network.
func (pm *PerformanceMetrics) UpdateCirculationVelocity(transactions []Transaction, totalSupply float64) {
	var totalTransactionVolume float64
	for _, tx := range transactions {
		totalTransactionVolume += tx.Amount
	}
	pm.CirculationVelocity = totalTransactionVolume / totalSupply
}

// EvaluateNetworkParticipation evaluates the active participation of nodes in the network.
func (pm *PerformanceMetrics) EvaluateNetworkParticipation(activeNodes, totalNodes int) {
	pm.NetworkParticipationRate = float64(activeNodes) / float64(totalNodes) * 100
}

// AssessTransactionValue calculates the average value of transactions processed.
func (pm *PerformanceMetrics) AssessTransactionValue(transactions []Transaction) {
	var totalValue float64
	for _, tx := range transactions {
		totalValue += tx.Amount
	}
	pm.AverageTransactionValue = totalValue / float64(len(transactions))
}

// MonitorBlockchainGrowth monitors the growth rate of the blockchain's size.
func (pm *PerformanceMetrics) MonitorBlockchainGrowth(currentSize, previousSize float64, duration time.Duration) {
	pm.BlockchainGrowthRate = (currentSize - previousSize) / previousSize / duration.Hours()
}

// CalculateStakeParticipation calculates the ratio of staked coins to the total circulating supply.
func (pm *PerformanceMetrics) CalculateStakeParticipation(stakedCoins, totalSupply float64) {
	pm.StakeParticipationRatio = stakedCoins / totalSupply
}

// MeasureTransactionConfirmationTime measures the average time taken for transactions to be confirmed.
func (pm *PerformanceMetrics) MeasureTransactionConfirmationTime(transactions []Transaction) {
	var totalTime float64
	for _, tx := range transactions {
		totalTime += time.Since(tx.Timestamp).Seconds()
	}
	pm.TransactionConfirmationTime = totalTime / float64(len(transactions))
}

// Report generates a comprehensive report on all the performance metrics.
func (pm *PerformanceMetrics) Report() {
	utils.Log("Transaction Throughput:", pm.TransactionThroughput)
	utils.Log("Circulation Velocity:", pm.CirculationVelocity)
	utils.Log("Network Participation Rate:", pm.NetworkParticipationRate)
	utils.Log("Average Transaction Value:", pm.AverageTransactionValue)
	utils.Log("Blockchain Growth Rate:", pm.BlockchainGrowthRate)
	utils.Log("Stake Participation Ratio:", pm.StakeParticipationRatio)
	utils.Log("Transaction Confirmation Time:", pm.TransactionConfirmationTime)
}