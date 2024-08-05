package dataprocessing

import (
	"encoding/json"
	"log"
	"math"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/operations/utils"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/operations/management/monitoring/network_monitoring"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/operations/management/monitoring/network_monitoring/alerts"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/operations/management/monitoring/network_monitoring/latency_metrics"
)

// PropagationAnalysis is a structure for analyzing data propagation metrics
type PropagationAnalysis struct {
	mutex            sync.Mutex
	latencyMetrics   map[string]latency_metrics.LatencyMetric
	alertSystem      *alerts.AlertSystem
	analysisInterval time.Duration
}

// NewPropagationAnalysis creates a new instance of PropagationAnalysis
func NewPropagationAnalysis(interval time.Duration, alertSys *alerts.AlertSystem) *PropagationAnalysis {
	return &PropagationAnalysis{
		latencyMetrics:   make(map[string]latency_metrics.LatencyMetric),
		alertSystem:      alertSys,
		analysisInterval: interval,
	}
}

// AddLatencyMetric adds a new latency metric to be analyzed
func (pa *PropagationAnalysis) AddLatencyMetric(nodeID string, metric latency_metrics.LatencyMetric) {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()
	pa.latencyMetrics[nodeID] = metric
}

// AnalyzeLatency calculates the average, variance, and standard deviation of latency across nodes
func (pa *PropagationAnalysis) AnalyzeLatency() {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	var sum, sumSquares, count float64
	for _, metric := range pa.latencyMetrics {
		sum += metric.Latency
		sumSquares += metric.Latency * metric.Latency
		count++
	}

	if count == 0 {
		log.Println("No latency metrics available for analysis")
		return
	}

	mean := sum / count
	variance := (sumSquares / count) - (mean * mean)
	stdDev := math.Sqrt(variance)

	log.Printf("Latency Analysis - Mean: %f, Variance: %f, StdDev: %f", mean, variance, stdDev)

	pa.alertSystem.CheckAndSendAlerts(mean, variance, stdDev)
}

// StartPeriodicAnalysis starts the periodic analysis of latency metrics
func (pa *PropagationAnalysis) StartPeriodicAnalysis() {
	ticker := time.NewTicker(pa.analysisInterval)
	go func() {
		for range ticker.C {
			pa.AnalyzeLatency()
		}
	}()
}

// EncryptAndStoreMetrics securely stores the latency metrics using encryption
func (pa *PropagationAnalysis) EncryptAndStoreMetrics() error {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	data, err := json.Marshal(pa.latencyMetrics)
	if err != nil {
		return err
	}

	encryptedData, err := utils.EncryptData(data)
	if err != nil {
		return err
	}

	err = utils.StoreData("latency_metrics.enc", encryptedData)
	if err != nil {
		return err
	}

	log.Println("Latency metrics securely stored")
	return nil
}

// LoadAndDecryptMetrics loads and decrypts the latency metrics
func (pa *PropagationAnalysis) LoadAndDecryptMetrics() error {
	data, err := utils.LoadData("latency_metrics.enc")
	if err != nil {
		return err
	}

	decryptedData, err := utils.DecryptData(data)
	if err != nil {
		return err
	}

	err = json.Unmarshal(decryptedData, &pa.latencyMetrics)
	if err != nil {
		return err
	}

	log.Println("Latency metrics successfully loaded and decrypted")
	return nil
}

// TriggerAlerts checks latency metrics and triggers alerts if conditions are met
func (pa *PropagationAnalysis) TriggerAlerts() {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	for nodeID, metric := range pa.latencyMetrics {
		if metric.Latency > latency_metrics.Threshold {
			alert := alerts.NewAlert(nodeID, "High Latency Detected", metric.Latency)
			pa.alertSystem.SendAlert(alert)
		}
	}
}

// PruneOldMetrics removes metrics older than a specified duration
func (pa *PropagationAnalysis) PruneOldMetrics(maxAge time.Duration) {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	thresholdTime := time.Now().Add(-maxAge)
	for nodeID, metric := range pa.latencyMetrics {
		if metric.Timestamp.Before(thresholdTime) {
			delete(pa.latencyMetrics, nodeID)
		}
	}
}

func main() {
	// Initialize the alert system
	alertSystem := alerts.NewAlertSystem()
	propagationAnalysis := NewPropagationAnalysis(10*time.Minute, alertSystem)

	// Load existing metrics from storage
	err := propagationAnalysis.LoadAndDecryptMetrics()
	if err != nil {
		log.Fatalf("Error loading metrics: %v", err)
	}

	// Start periodic analysis
	propagationAnalysis.StartPeriodicAnalysis()

	// Example of adding a new latency metric
	propagationAnalysis.AddLatencyMetric("node1", latency_metrics.LatencyMetric{
		Latency:   120,
		Timestamp: time.Now(),
	})

	// Encrypt and store metrics periodically (example with an interval)
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for range ticker.C {
			err := propagationAnalysis.EncryptAndStoreMetrics()
			if err != nil {
				log.Printf("Error storing metrics: %v", err)
			}
		}
	}()

	select {}
}
