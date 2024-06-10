package metrics

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// AlertManager manages the configuration and triggering of alerts based on collected metrics.
type AlertManager struct {
	alertRules   map[string]AlertRule
	alertChannel chan Alert
	mu           sync.RWMutex
}

// AlertRule defines the conditions and actions for an alert.
type AlertRule struct {
	MetricName   string
	Threshold    float64
	Comparison   string // Possible values: "greater_than", "less_than"
	AlertMessage string
	Triggered    bool
}

// Alert represents an alert that has been triggered.
type Alert struct {
	MetricName   string
	CurrentValue float64
	AlertMessage string
	Timestamp    time.Time
}

// NewAlertManager creates a new AlertManager.
func NewAlertManager() *AlertManager {
	return &AlertManager{
		alertRules:   make(map[string]AlertRule),
		alertChannel: make(chan Alert, 100),
	}
}

// AddAlertRule adds a new alert rule to the AlertManager.
func (am *AlertManager) AddAlertRule(name string, rule AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.alertRules[name] = rule
}

// RemoveAlertRule removes an alert rule from the AlertManager.
func (am *AlertManager) RemoveAlertRule(name string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.alertRules, name)
}

// CheckAlerts checks all alert rules and triggers alerts if conditions are met.
func (am *AlertManager) CheckAlerts(metricName string, currentValue float64) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	for _, rule := range am.alertRules {
		if rule.MetricName == metricName {
			shouldTrigger := false
			if rule.Comparison == "greater_than" && currentValue > rule.Threshold {
				shouldTrigger = true
			} else if rule.Comparison == "less_than" && currentValue < rule.Threshold {
				shouldTrigger = true
			}

			if shouldTrigger && !rule.Triggered {
				alert := Alert{
					MetricName:   metricName,
					CurrentValue: currentValue,
					AlertMessage: rule.AlertMessage,
					Timestamp:    time.Now(),
				}
				am.alertChannel <- alert
				rule.Triggered = true
				am.alertRules[metricName] = rule
			} else if !shouldTrigger && rule.Triggered {
				rule.Triggered = false
				am.alertRules[metricName] = rule
			}
		}
	}
}

// GetAlertChannel returns the alert channel for listening to triggered alerts.
func (am *AlertManager) GetAlertChannel() <-chan Alert {
	return am.alertChannel
}

// MonitorMetrics sets up a Prometheus HTTP handler for exposing metrics and starts monitoring.
func (am *AlertManager) MonitorMetrics(port int) {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
			fmt.Printf("Error starting HTTP server: %v\n", err)
		}
	}()
}

// Example of setting up and using the AlertManager.
func main() {
	alertManager := NewAlertManager()

	cpuUsage := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cpu_usage",
		Help: "Current CPU usage",
	})

	prometheus.MustRegister(cpuUsage)

	alertManager.AddAlertRule("HighCPUUsage", AlertRule{
		MetricName:   "cpu_usage",
		Threshold:    80.0,
		Comparison:   "greater_than",
		AlertMessage: "CPU usage is above 80%",
	})

	alertManager.MonitorMetrics(9090)

	go func() {
		for alert := range alertManager.GetAlertChannel() {
			fmt.Printf("ALERT: %s - %f at %s\n", alert.AlertMessage, alert.CurrentValue, alert.Timestamp)
		}
	}()

	// Simulate metrics update
	for {
		cpuUsage.Set(float64(time.Now().UnixNano()%100))
		alertManager.CheckAlerts("cpu_usage", cpuUsage)
		time.Sleep(5 * time.Second)
	}
}
