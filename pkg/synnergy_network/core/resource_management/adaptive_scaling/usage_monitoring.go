package adaptive_scaling

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// ResourceMetrics holds data related to resource usage
type ResourceMetrics struct {
	CPUUsage        float64 `json:"cpu_usage"`
	MemoryUsage     float64 `json:"memory_usage"`
	NetworkUsage    float64 `json:"network_usage"`
	StorageUsage    float64 `json:"storage_usage"`
	TransactionRate float64 `json:"transaction_rate"`
	Timestamp       time.Time `json:"timestamp"`
}

// UsageMonitoring provides methods to monitor and analyze resource usage
type UsageMonitoring struct {
	mu             sync.Mutex
	metricsHistory []ResourceMetrics
	alertThresholds AlertThresholds
}

// AlertThresholds defines the thresholds for generating alerts
type AlertThresholds struct {
	CPUUsageHigh    float64
	MemoryUsageHigh float64
	NetworkUsageHigh float64
	StorageUsageHigh float64
}

// NewUsageMonitoring initializes the UsageMonitoring instance
func NewUsageMonitoring(thresholds AlertThresholds) *UsageMonitoring {
	return &UsageMonitoring{
		metricsHistory: []ResourceMetrics{},
		alertThresholds: thresholds,
	}
}

// RecordMetrics records the current resource metrics
func (um *UsageMonitoring) RecordMetrics(metrics ResourceMetrics) {
	um.mu.Lock()
	defer um.mu.Unlock()
	um.metricsHistory = append(um.metricsHistory, metrics)
	if len(um.metricsHistory) > 1000 {
		um.metricsHistory = um.metricsHistory[1:]
	}
	um.checkForAlerts(metrics)
}

// checkForAlerts checks if any metric exceeds the threshold and generates an alert
func (um *UsageMonitoring) checkForAlerts(metrics ResourceMetrics) {
	if metrics.CPUUsage > um.alertThresholds.CPUUsageHigh {
		um.generateAlert("CPU usage high", metrics)
	}
	if metrics.MemoryUsage > um.alertThresholds.MemoryUsageHigh {
		um.generateAlert("Memory usage high", metrics)
	}
	if metrics.NetworkUsage > um.alertThresholds.NetworkUsageHigh {
		um.generateAlert("Network usage high", metrics)
	}
	if metrics.StorageUsage > um.alertThresholds.StorageUsageHigh {
		um.generateAlert("Storage usage high", metrics)
	}
}

// generateAlert logs the alert and can notify administrators
func (um *UsageMonitoring) generateAlert(message string, metrics ResourceMetrics) {
	alert := fmt.Sprintf("%s at %s: %v", message, metrics.Timestamp, metrics)
	log.Println(alert)
	// Implement notification logic, e.g., sending an email or SMS
}

// GetMetricsHistory returns the historical metrics data
func (um *UsageMonitoring) GetMetricsHistory() []ResourceMetrics {
	um.mu.Lock()
	defer um.mu.Unlock()
	return um.metricsHistory
}

// ServeMetrics provides an HTTP interface to access the metrics data
func (um *UsageMonitoring) ServeMetrics(w http.ResponseWriter, r *http.Request) {
	um.mu.Lock()
	defer um.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(um.metricsHistory); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// PredictUsage trends based on historical data
func (um *UsageMonitoring) PredictUsage() (ResourceMetrics, error) {
	um.mu.Lock()
	defer um.mu.Unlock()

	if len(um.metricsHistory) < 2 {
		return ResourceMetrics{}, errors.New("not enough data for prediction")
	}

	var totalCPU, totalMemory, totalNetwork, totalStorage float64
	for _, metric := range um.metricsHistory {
		totalCPU += metric.CPUUsage
		totalMemory += metric.MemoryUsage
		totalNetwork += metric.NetworkUsage
		totalStorage += metric.StorageUsage
	}

	n := float64(len(um.metricsHistory))
	return ResourceMetrics{
		CPUUsage:     totalCPU / n,
		MemoryUsage:  totalMemory / n,
		NetworkUsage: totalNetwork / n,
		StorageUsage: totalStorage / n,
		Timestamp:    time.Now(),
	}, nil
}

// ExportMetricsToCSV exports the metrics data to a CSV file
func (um *UsageMonitoring) ExportMetricsToCSV(filePath string) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Timestamp", "CPU Usage", "Memory Usage", "Network Usage", "Storage Usage", "Transaction Rate"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, metric := range um.metricsHistory {
		record := []string{
			metric.Timestamp.Format(time.RFC3339),
			fmt.Sprintf("%.2f", metric.CPUUsage),
			fmt.Sprintf("%.2f", metric.MemoryUsage),
			fmt.Sprintf("%.2f", metric.NetworkUsage),
			fmt.Sprintf("%.2f", metric.StorageUsage),
			fmt.Sprintf("%.2f", metric.TransactionRate),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}
