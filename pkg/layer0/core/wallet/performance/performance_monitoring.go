package performance

import (
	"log"
	"sync"
	"time"
)

// PerformanceMetrics holds various metrics for performance monitoring
type PerformanceMetrics struct {
	TransactionCount    int64
	TransactionRate     float64
	BlockGenerationTime float64
	NodeUptime          time.Duration
	mu                  sync.RWMutex
	startTime           time.Time
}

// NewPerformanceMetrics initializes and returns a new PerformanceMetrics instance
func NewPerformanceMetrics() *PerformanceMetrics {
	return &PerformanceMetrics{
		startTime: time.Now(),
	}
}

// RecordTransaction increments the transaction count and updates the transaction rate
func (pm *PerformanceMetrics) RecordTransaction() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.TransactionCount++
	elapsed := time.Since(pm.startTime).Seconds()
	pm.TransactionRate = float64(pm.TransactionCount) / elapsed
}

// UpdateBlockGenerationTime updates the average block generation time
func (pm *PerformanceMetrics) UpdateBlockGenerationTime(newTime float64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Using exponential moving average for smooth updates
	alpha := 0.1
	pm.BlockGenerationTime = alpha*newTime + (1-alpha)*pm.BlockGenerationTime
}

// UpdateUptime updates the node uptime
func (pm *PerformanceMetrics) UpdateUptime() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.NodeUptime = time.Since(pm.startTime)
}

// GetMetrics returns the current performance metrics
func (pm *PerformanceMetrics) GetMetrics() PerformanceMetrics {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return PerformanceMetrics{
		TransactionCount:    pm.TransactionCount,
		TransactionRate:     pm.TransactionRate,
		BlockGenerationTime: pm.BlockGenerationTime,
		NodeUptime:          pm.NodeUptime,
	}
}

// PerformanceMonitor manages the performance monitoring operations
type PerformanceMonitor struct {
	metrics *PerformanceMetrics
	ticker  *time.Ticker
	done    chan bool
}

// NewPerformanceMonitor initializes and returns a new PerformanceMonitor instance
func NewPerformanceMonitor(interval time.Duration) *PerformanceMonitor {
	pm := &PerformanceMonitor{
		metrics: NewPerformanceMetrics(),
		ticker:  time.NewTicker(interval),
		done:    make(chan bool),
	}
	go pm.start()
	return pm
}

// start begins the periodic performance monitoring
func (pm *PerformanceMonitor) start() {
	for {
		select {
		case <-pm.ticker.C:
			pm.logPerformanceMetrics()
		case <-pm.done:
			return
		}
	}
}

// logPerformanceMetrics logs the current performance metrics
func (pm *PerformanceMonitor) logPerformanceMetrics() {
	metrics := pm.metrics.GetMetrics()
	log.Printf("Transaction Count: %d, Transaction Rate: %.2f tx/s, Block Generation Time: %.2f s, Node Uptime: %s\n",
		metrics.TransactionCount, metrics.TransactionRate, metrics.BlockGenerationTime, metrics.NodeUptime)
}

// Stop stops the performance monitoring
func (pm *PerformanceMonitor) Stop() {
	pm.ticker.Stop()
	pm.done <- true
}

// Example usage of PerformanceMonitor
func main() {
	performanceMonitor := NewPerformanceMonitor(10 * time.Second)

	// Simulate recording transactions and updating metrics
	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(1 * time.Second)
			performanceMonitor.metrics.RecordTransaction()
			performanceMonitor.metrics.UpdateBlockGenerationTime(float64(i%10 + 1))
			performanceMonitor.metrics.UpdateUptime()
		}
	}()

	// Stop performance monitoring after 2 minutes
	time.Sleep(2 * time.Minute)
	performanceMonitor.Stop()
}
