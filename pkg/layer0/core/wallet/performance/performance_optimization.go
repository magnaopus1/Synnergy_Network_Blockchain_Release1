package performance

import (
	"log"
	"sync"
	"time"
)

// OptimizationMetrics holds various metrics for performance optimization
type OptimizationMetrics struct {
	TransactionCount      int64
	TransactionRate       float64
	BlockGenerationTime   float64
	MemoryUsage           uint64
	CPUUsage              float64
	NetworkLatency        float64
	mu                    sync.RWMutex
	startTime             time.Time
}

// NewOptimizationMetrics initializes and returns a new OptimizationMetrics instance
func NewOptimizationMetrics() *OptimizationMetrics {
	return &OptimizationMetrics{
		startTime: time.Now(),
	}
}

// RecordTransaction increments the transaction count and updates the transaction rate
func (om *OptimizationMetrics) RecordTransaction() {
	om.mu.Lock()
	defer om.mu.Unlock()

	om.TransactionCount++
	elapsed := time.Since(om.startTime).Seconds()
	om.TransactionRate = float64(om.TransactionCount) / elapsed
}

// UpdateBlockGenerationTime updates the average block generation time
func (om *OptimizationMetrics) UpdateBlockGenerationTime(newTime float64) {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Using exponential moving average for smooth updates
	alpha := 0.1
	om.BlockGenerationTime = alpha*newTime + (1-alpha)*om.BlockGenerationTime
}

// UpdateMemoryUsage updates the memory usage
func (om *OptimizationMetrics) UpdateMemoryUsage(newUsage uint64) {
	om.mu.Lock()
	defer om.mu.Unlock()

	om.MemoryUsage = newUsage
}

// UpdateCPUUsage updates the CPU usage
func (om *OptimizationMetrics) UpdateCPUUsage(newUsage float64) {
	om.mu.Lock()
	defer om.mu.Unlock()

	om.CPUUsage = newUsage
}

// UpdateNetworkLatency updates the network latency
func (om *OptimizationMetrics) UpdateNetworkLatency(newLatency float64) {
	om.mu.Lock()
	defer om.mu.Unlock()

	om.NetworkLatency = newLatency
}

// GetMetrics returns the current optimization metrics
func (om *OptimizationMetrics) GetMetrics() OptimizationMetrics {
	om.mu.RLock()
	defer om.mu.RUnlock()

	return OptimizationMetrics{
		TransactionCount:    om.TransactionCount,
		TransactionRate:     om.TransactionRate,
		BlockGenerationTime: om.BlockGenerationTime,
		MemoryUsage:         om.MemoryUsage,
		CPUUsage:            om.CPUUsage,
		NetworkLatency:      om.NetworkLatency,
	}
}

// OptimizationMonitor manages the performance optimization monitoring operations
type OptimizationMonitor struct {
	metrics *OptimizationMetrics
	ticker  *time.Ticker
	done    chan bool
}

// NewOptimizationMonitor initializes and returns a new OptimizationMonitor instance
func NewOptimizationMonitor(interval time.Duration) *OptimizationMonitor {
	om := &OptimizationMonitor{
		metrics: NewOptimizationMetrics(),
		ticker:  time.NewTicker(interval),
		done:    make(chan bool),
	}
	go om.start()
	return om
}

// start begins the periodic performance optimization monitoring
func (om *OptimizationMonitor) start() {
	for {
		select {
		case <-om.ticker.C:
			om.logOptimizationMetrics()
		case <-om.done:
			return
		}
	}
}

// logOptimizationMetrics logs the current optimization metrics
func (om *OptimizationMonitor) logOptimizationMetrics() {
	metrics := om.metrics.GetMetrics()
	log.Printf("Transaction Count: %d, Transaction Rate: %.2f tx/s, Block Generation Time: %.2f s, Memory Usage: %d bytes, CPU Usage: %.2f%%, Network Latency: %.2f ms\n",
		metrics.TransactionCount, metrics.TransactionRate, metrics.BlockGenerationTime, metrics.MemoryUsage, metrics.CPUUsage, metrics.NetworkLatency)
}

// Stop stops the performance optimization monitoring
func (om *OptimizationMonitor) Stop() {
	om.ticker.Stop()
	om.done <- true
}

// Example usage of OptimizationMonitor
func main() {
	optimizationMonitor := NewOptimizationMonitor(10 * time.Second)

	// Simulate recording transactions and updating metrics
	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(1 * time.Second)
			optimizationMonitor.metrics.RecordTransaction()
			optimizationMonitor.metrics.UpdateBlockGenerationTime(float64(i%10 + 1))
			optimizationMonitor.metrics.UpdateMemoryUsage(uint64(i * 1000))
			optimizationMonitor.metrics.UpdateCPUUsage(float64(i % 100))
			optimizationMonitor.metrics.UpdateNetworkLatency(float64(i % 200))
		}
	}()

	// Stop optimization monitoring after 2 minutes
	time.Sleep(2 * time.Minute)
	optimizationMonitor.Stop()
}
