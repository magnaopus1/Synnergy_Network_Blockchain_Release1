package monitoring

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"sync"
	"time"
)

// NodeMetrics represents the performance metrics of a node.
type NodeMetrics struct {
	Address         string
	TransactionRate float64
	BlockTime       float64
	Uptime          time.Duration
	LastUpdated     time.Time
}

// PerformanceMetrics handles monitoring and reporting of performance metrics.
type PerformanceMetrics struct {
	metrics       map[string]NodeMetrics
	mu            sync.RWMutex
	updateFreq    time.Duration
	alertFunc     func(NodeMetrics)
	shutdownCh    chan struct{}
}

// NewPerformanceMetrics initializes a new PerformanceMetrics.
func NewPerformanceMetrics(updateFreq time.Duration, alertFunc func(NodeMetrics)) *PerformanceMetrics {
	return &PerformanceMetrics{
		metrics:    make(map[string]NodeMetrics),
		updateFreq: updateFreq,
		alertFunc:  alertFunc,
		shutdownCh: make(chan struct{}),
	}
}

// AddNodeMetrics adds a new node to the performance metrics monitor.
func (pm *PerformanceMetrics) AddNodeMetrics(address string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.metrics[address] = NodeMetrics{
		Address:     address,
		LastUpdated: time.Now(),
	}
}

// RemoveNodeMetrics removes a node from the performance metrics monitor.
func (pm *PerformanceMetrics) RemoveNodeMetrics(address string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	delete(pm.metrics, address)
}

// Start begins the performance metrics monitoring process.
func (pm *PerformanceMetrics) Start() {
	go pm.monitorPerformance()
}

// Stop stops the performance metrics monitoring process.
func (pm *PerformanceMetrics) Stop() {
	close(pm.shutdownCh)
}

// monitorPerformance periodically updates and checks the performance metrics of all nodes.
func (pm *PerformanceMetrics) monitorPerformance() {
	ticker := time.NewTicker(pm.updateFreq)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.updateMetrics()
		case <-pm.shutdownCh:
			return
		}
	}
}

// updateMetrics updates the performance metrics for each node.
func (pm *PerformanceMetrics) updateMetrics() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for address, metrics := range pm.metrics {
		// Simulated data for demonstration purposes
		metrics.TransactionRate = math.Round(randFloat(0, 1000)*100) / 100
		metrics.BlockTime = math.Round(randFloat(0.5, 10)*100) / 100
		metrics.Uptime = time.Since(metrics.LastUpdated)
		metrics.LastUpdated = time.Now()

		pm.metrics[address] = metrics

		if pm.alertFunc != nil {
			pm.alertFunc(metrics)
		}
	}
}

// Export exports the performance metrics to a JSON file.
func (pm *PerformanceMetrics) Export(filename string) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	data, err := json.Marshal(pm.metrics)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports the performance metrics from a JSON file.
func (pm *PerformanceMetrics) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	var metrics map[string]NodeMetrics
	if err := json.Unmarshal(data, &metrics); err != nil {
		return err
	}

	pm.mu.Lock()
	pm.metrics = metrics
	pm.mu.Unlock()

	return nil
}

// randFloat generates a random float number within a specified range.
func randFloat(min, max float64) float64 {
	return min + (max-min)*rand.Float64()
}

// saveToFile saves the data to a file.
func saveToFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}

// loadFromFile loads the data from a file.
func loadFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}
