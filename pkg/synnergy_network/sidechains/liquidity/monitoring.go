package liquidity

import (
	"fmt"
	"sync"
	"time"
)

// Monitor represents the monitoring system for the liquidity sidechain
type Monitor struct {
	mu          sync.RWMutex
	metrics     map[string]float64
	alerts      []Alert
	alertCh     chan Alert
	stopCh      chan struct{}
	alertConfig AlertConfig
}

// Alert represents an alert in the monitoring system
type Alert struct {
	Timestamp time.Time
	Message   string
	Severity  string
}

// AlertConfig represents the configuration for alerts
type AlertConfig struct {
	Thresholds map[string]float64
	Severity   map[string]string
}

// NewMonitor creates a new Monitor instance
func NewMonitor(alertConfig AlertConfig) *Monitor {
	return &Monitor{
		metrics:     make(map[string]float64),
		alerts:      []Alert{},
		alertCh:     make(chan Alert),
		stopCh:      make(chan struct{}),
		alertConfig: alertConfig,
	}
}

// AddMetric adds a new metric to the monitor
func (m *Monitor) AddMetric(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics[name] = value
	m.checkAlert(name, value)
}

// GetMetrics retrieves all metrics from the monitor
func (m *Monitor) GetMetrics() map[string]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	metricsCopy := make(map[string]float64)
	for k, v := range m.metrics {
		metricsCopy[k] = v
	}
	return metricsCopy
}

// ListAlerts lists all alerts
func (m *Monitor) ListAlerts() []Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	alertsCopy := make([]Alert, len(m.alerts))
	copy(alertsCopy, m.alerts)
	return alertsCopy
}

// StartMonitoring starts the monitoring process
func (m *Monitor) StartMonitoring(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.collectMetrics()
			case alert := <-m.alertCh:
				m.mu.Lock()
				m.alerts = append(m.alerts, alert)
				m.mu.Unlock()
				fmt.Printf("Alert: %s - %s\n", alert.Severity, alert.Message)
			case <-m.stopCh:
				return
			}
		}
	}()
}

// StopMonitoring stops the monitoring process
func (m *Monitor) StopMonitoring() {
	close(m.stopCh)
}

// collectMetrics collects metrics from various sources
func (m *Monitor) collectMetrics() {
	// Example: Collecting random metrics for demonstration
	m.AddMetric("cpu_usage", float64(rand.Intn(100)))
	m.AddMetric("memory_usage", float64(rand.Intn(100)))
}

// checkAlert checks if the metric value exceeds the threshold and triggers an alert if necessary
func (m *Monitor) checkAlert(name string, value float64) {
	threshold, exists := m.alertConfig.Thresholds[name]
	if !exists {
		return
	}

	if value > threshold {
		severity, exists := m.alertConfig.Severity[name]
		if !exists {
			severity = "info"
		}
		m.alertCh <- Alert{
			Timestamp: time.Now(),
			Message:   fmt.Sprintf("%s value %f exceeded threshold %f", name, value, threshold),
			Severity:  severity,
		}
	}
}

// NewAlertConfig creates a new AlertConfig instance
func NewAlertConfig(thresholds map[string]float64, severity map[string]string) AlertConfig {
	return AlertConfig{
		Thresholds: thresholds,
		Severity:   severity,
	}
}
