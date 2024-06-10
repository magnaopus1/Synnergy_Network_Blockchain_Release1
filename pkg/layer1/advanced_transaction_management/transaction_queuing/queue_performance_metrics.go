package transaction_queuing

import (
	"sync"
	"time"
)

// PerformanceMetrics stores metrics related to queue performance
type PerformanceMetrics struct {
	lock           sync.Mutex
	enqueueCount   int
	dequeueCount   int
	failureCount   int
	totalWaitTime  time.Duration
	totalProcessTime time.Duration
}

// NewPerformanceMetrics initializes a new instance of PerformanceMetrics
func NewPerformanceMetrics() *PerformanceMetrics {
	return &PerformanceMetrics{}
}

// IncrementEnqueueCount increments the count of transactions added to the queue
func (pm *PerformanceMetrics) IncrementEnqueueCount() {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	pm.enqueueCount++
}

// IncrementDequeueCount increments the count of transactions processed from the queue
func (pm *PerformanceMetrics) IncrementDequeueCount() {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	pm.dequeueCount++
}

// IncrementFailureCount increments the count of failed transaction processing attempts
func (pm *PerformanceMetrics) IncrementFailureCount() {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	pm.failureCount++
}

// AddWaitTime adds to the total wait time of all transactions
func (pm *PerformanceMetrics) AddWaitTime(duration time.Duration) {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	pm.totalWaitTime += duration
}

// AddProcessTime adds to the total processing time of all transactions
func (pm *PerformanceMetrics) AddProcessTime(duration time.Duration) {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	pm.totalProcessTime += duration
}

// GetMetrics returns the current performance metrics
func (pm *PerformanceMetrics) GetMetrics() (int, int, int, time.Duration, time.Duration) {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	return pm.enqueueCount, pm.dequeueCount, pm.failureCount, pm.totalWaitTime, pm.totalProcessTime
}

// CalculateAverageWaitTime calculates the average wait time per transaction
func (pm *PerformanceMetrics) CalculateAverageWaitTime() time.Duration {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	if pm.dequeueCount == 0 {
		return 0
	}
	return time.Duration(int64(pm.totalWaitTime) / int64(pm.dequeueCount))
}

// CalculateAverageProcessTime calculates the average processing time per transaction
func (pm *PerformanceMetrics) CalculateAverageProcessTime() time.Duration {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	if pm.dequeueCount == 0 {
		return 0
	}
	return time.Duration(int64(pm.totalProcessTime) / int64(pm.dequeueCount))
}
