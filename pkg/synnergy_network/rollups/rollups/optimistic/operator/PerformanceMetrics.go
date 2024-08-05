package operator

import (
	"fmt"
	"sync"
	"time"
)

type PerformanceMetrics struct {
	mu                 sync.Mutex
	transactions       int
	batchesProcessed   int
	processingTimes    []time.Duration
	nodeStatus         map[string]bool
	lastSync           time.Time
	startTime          time.Time
}

func NewPerformanceMetrics() *PerformanceMetrics {
	return &PerformanceMetrics{
		nodeStatus:      make(map[string]bool),
		processingTimes: []time.Duration{},
		startTime:       time.Now(),
	}
}

func (pm *PerformanceMetrics) RecordTransaction() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.transactions++
}

func (pm *PerformanceMetrics) RecordBatchProcessingTime(duration time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.batchesProcessed++
	pm.processingTimes = append(pm.processingTimes, duration)
}

func (pm *PerformanceMetrics) UpdateNodeStatus(nodeID string, status bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.nodeStatus[nodeID] = status
}

func (pm *PerformanceMetrics) SyncCompleted() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.lastSync = time.Now()
}

func (pm *PerformanceMetrics) AverageProcessingTime() time.Duration {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.processingTimes) == 0 {
		return 0
	}

	var total time.Duration
	for _, t := range pm.processingTimes {
		total += t
	}

	return total / time.Duration(len(pm.processingTimes))
}

func (pm *PerformanceMetrics) TransactionsPerSecond() float64 {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	elapsed := time.Since(pm.startTime).Seconds()
	if elapsed == 0 {
		return 0
	}

	return float64(pm.transactions) / elapsed
}

func (pm *PerformanceMetrics) BatchesPerSecond() float64 {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	elapsed := time.Since(pm.startTime).Seconds()
	if elapsed == 0 {
		return 0
	}

	return float64(pm.batchesProcessed) / elapsed
}

func (pm *PerformanceMetrics) PrintSummary() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	fmt.Println("Performance Metrics Summary")
	fmt.Printf("Transactions: %d\n", pm.transactions)
	fmt.Printf("Batches Processed: %d\n", pm.batchesProcessed)
	fmt.Printf("Average Processing Time: %s\n", pm.AverageProcessingTime())
	fmt.Printf("Transactions Per Second: %.2f\n", pm.TransactionsPerSecond())
	fmt.Printf("Batches Per Second: %.2f\n", pm.BatchesPerSecond())
	fmt.Printf("Last Sync Time: %s\n", pm.lastSync)
	fmt.Println("Node Status:")
	for node, status := range pm.nodeStatus {
		fmt.Printf("Node %s: %t\n", node, status)
	}
}

func (pm *PerformanceMetrics) ResetMetrics() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.transactions = 0
	pm.batchesProcessed = 0
	pm.processingTimes = []time.Duration{}
	pm.nodeStatus = make(map[string]bool)
	pm.lastSync = time.Time{}
	pm.startTime = time.Now()
}

func (pm *PerformanceMetrics) ExportMetrics() map[string]interface{} {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return map[string]interface{}{
		"transactions":           pm.transactions,
		"batchesProcessed":       pm.batchesProcessed,
		"averageProcessingTime":  pm.AverageProcessingTime().Seconds(),
		"transactionsPerSecond":  pm.TransactionsPerSecond(),
		"batchesPerSecond":       pm.BatchesPerSecond(),
		"lastSync":               pm.lastSync,
		"nodeStatus":             pm.nodeStatus,
	}
}
