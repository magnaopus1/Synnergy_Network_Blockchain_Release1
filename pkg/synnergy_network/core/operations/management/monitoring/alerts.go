package monitoring

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Alert represents a single alert
type Alert struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
}

// AlertSystem represents the alert system
type AlertSystem struct {
	mu             sync.Mutex
	alerts         map[string]Alert
	alertChannels  map[string]chan Alert
	alertRules     map[string]AlertRule
	prometheusGauge prometheus.Gauge
}

// AlertRule represents a rule for triggering alerts
type AlertRule struct {
	ID           string                 `json:"id"`
	Description  string                 `json:"description"`
	Severity     string                 `json:"severity"`
	Condition    func() bool            `json:"-"`
	Actions      []func(alert Alert)    `json:"-"`
}

// NewAlertSystem creates a new alert system
func NewAlertSystem() *AlertSystem {
	as := &AlertSystem{
		alerts:         make(map[string]Alert),
		alertChannels:  make(map[string]chan Alert),
		alertRules:     make(map[string]AlertRule),
		prometheusGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "synnergy_alerts_total",
			Help: "Total number of alerts generated.",
		}),
	}

	prometheus.MustRegister(as.prometheusGauge)

	return as
}

// RegisterAlertRule registers a new alert rule
func (as *AlertSystem) RegisterAlertRule(rule AlertRule) {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.alertRules[rule.ID] = rule
}

// GenerateAlert generates a new alert
func (as *AlertSystem) GenerateAlert(id, severity, message string) {
	as.mu.Lock()
	defer as.mu.Unlock()

	alert := Alert{
		ID:        id,
		Timestamp: time.Now(),
		Severity:  severity,
		Message:   message,
	}

	as.alerts[id] = alert
	as.prometheusGauge.Inc()

	for _, channel := range as.alertChannels {
		channel <- alert
	}

	for _, rule := range as.alertRules {
		if rule.Condition() {
			for _, action := range rule.Actions {
				action(alert)
			}
		}
	}
}

// AddAlertChannel adds a new alert channel
func (as *AlertSystem) AddAlertChannel(id string, channel chan Alert) {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.alertChannels[id] = channel
}

// RemoveAlertChannel removes an alert channel
func (as *AlertSystem) RemoveAlertChannel(id string) {
	as.mu.Lock()
	defer as.mu.Unlock()

	delete(as.alertChannels, id)
}

// SerializeAlerts serializes the alerts to JSON
func (as *AlertSystem) SerializeAlerts() (string, error) {
	as.mu.Lock()
	defer as.mu.Unlock()

	data, err := json.Marshal(as.alerts)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// DeserializeAlerts deserializes the alerts from JSON
func (as *AlertSystem) DeserializeAlerts(data string) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	var alerts map[string]Alert
	if err := json.Unmarshal([]byte(data), &alerts); err != nil {
		return err
	}

	as.alerts = alerts
	return nil
}

// ListAlerts returns a list of all current alerts
func (as *AlertSystem) ListAlerts() []Alert {
	as.mu.Lock()
	defer as.mu.Unlock()

	alertList := make([]Alert, 0, len(as.alerts))
	for _, alert := range as.alerts {
		alertList = append(alertList, alert)
	}
	return alertList
}

// GetAlert retrieves a specific alert by ID
func (as *AlertSystem) GetAlert(id string) (Alert, error) {
	as.mu.Lock()
	defer as.mu.Unlock()

	alert, exists := as.alerts[id]
	if !exists {
		return Alert{}, errors.New("alert not found")
	}

	return alert, nil
}

// DeleteAlert removes a specific alert by ID
func (as *AlertSystem) DeleteAlert(id string) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	if _, exists := as.alerts[id]; !exists {
		return errors.New("alert not found")
	}

	delete(as.alerts, id)
	as.prometheusGauge.Dec()
	return nil
}

// ClearAllAlerts removes all alerts from the system
func (as *AlertSystem) ClearAllAlerts() {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.alerts = make(map[string]Alert)
	as.prometheusGauge.Set(0)
}

// Example usage of the alert system
func exampleUsage() {
	alertSystem := NewAlertSystem()

	// Register an alert rule
	alertSystem.RegisterAlertRule(AlertRule{
		ID:          "high_cpu_usage",
		Description: "Triggers when CPU usage exceeds 90%",
		Severity:    "high",
		Condition: func() bool {
			// Example condition
			return false
		},
		Actions: []func(alert Alert){
			func(alert Alert) {
				fmt.Println("Action 1 for alert:", alert)
			},
			func(alert Alert) {
				fmt.Println("Action 2 for alert:", alert)
			},
		},
	})

	// Generate an alert
	alertSystem.GenerateAlert("alert_1", "medium", "CPU usage at 85%")

	// Serialize alerts to JSON
	jsonData, _ := alertSystem.SerializeAlerts()
	fmt.Println("Serialized alerts:", jsonData)

	// Deserialize alerts from JSON
	_ = alertSystem.DeserializeAlerts(jsonData)
}
