package customizable_alert_system

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"synnergy_network/core/utils"
	"synnergy_network/core/monitoring"
	"synnergy_network/core/operations/management/monitoring"
)

// HistoricalAlert represents a single historical alert entry.
type HistoricalAlert struct {
	ID            string    `json:"id"`
	ConditionID   string    `json:"condition_id"`
	Timestamp     time.Time `json:"timestamp"`
	AlertType     string    `json:"alert_type"`
	Message       string    `json:"message"`
	Severity      string    `json:"severity"`
	Resolved      bool      `json:"resolved"`
	ResolvedAt    time.Time `json:"resolved_at,omitempty"`
	ResolutionMsg string    `json:"resolution_msg,omitempty"`
}

// HistoricalAlertManager manages historical alerts.
type HistoricalAlertManager struct {
	alerts map[string]HistoricalAlert
	mu     sync.Mutex
}

// NewHistoricalAlertManager creates a new HistoricalAlertManager.
func NewHistoricalAlertManager() *HistoricalAlertManager {
	return &HistoricalAlertManager{
		alerts: make(map[string]HistoricalAlert),
	}
}

// LogAlert logs a new alert into the historical alerts.
func (ham *HistoricalAlertManager) LogAlert(conditionID, alertType, message, severity string) (string, error) {
	ham.mu.Lock()
	defer ham.mu.Unlock()

	id := utils.GenerateUUID()
	alert := HistoricalAlert{
		ID:          id,
		ConditionID: conditionID,
		Timestamp:   time.Now(),
		AlertType:   alertType,
		Message:     message,
		Severity:    severity,
		Resolved:    false,
	}

	ham.alerts[id] = alert
	return id, nil
}

// ResolveAlert marks an alert as resolved.
func (ham *HistoricalAlertManager) ResolveAlert(id, resolutionMsg string) error {
	ham.mu.Lock()
	defer ham.mu.Unlock()

	if alert, exists := ham.alerts[id]; exists {
		alert.Resolved = true
		alert.ResolvedAt = time.Now()
		alert.ResolutionMsg = resolutionMsg

		ham.alerts[id] = alert
		return nil
	}

	return errors.New("alert not found")
}

// GetAlert retrieves a historical alert by ID.
func (ham *HistoricalAlertManager) GetAlert(id string) (HistoricalAlert, error) {
	ham.mu.Lock()
	defer ham.mu.Unlock()

	if alert, exists := ham.alerts[id]; exists {
		return alert, nil
	}

	return HistoricalAlert{}, errors.New("alert not found")
}

// ListAlerts lists all historical alerts.
func (ham *HistoricalAlertManager) ListAlerts() []HistoricalAlert {
	ham.mu.Lock()
	defer ham.mu.Unlock()

	alerts := make([]HistoricalAlert, 0, len(ham.alerts))
	for _, alert := range ham.alerts {
		alerts = append(alerts, alert)
	}
	return alerts
}

// AnalyzeAlerts analyzes historical alerts to identify patterns and improve future alert accuracy.
func (ham *HistoricalAlertManager) AnalyzeAlerts() monitoring.AlertAnalysis {
	ham.mu.Lock()
	defer ham.mu.Unlock()

	analysis := monitoring.AlertAnalysis{
		TotalAlerts:        len(ham.alerts),
		ResolvedAlerts:     0,
		UnresolvedAlerts:   0,
		AlertsBySeverity:   make(map[string]int),
		ResolutionDuration: make(map[string]time.Duration),
	}

	severityDurations := make(map[string]time.Duration)

	for _, alert := range ham.alerts {
		if alert.Resolved {
			analysis.ResolvedAlerts++
			duration := alert.ResolvedAt.Sub(alert.Timestamp)
			analysis.ResolutionDuration[alert.ID] = duration
			severityDurations[alert.Severity] += duration
		} else {
			analysis.UnresolvedAlerts++
		}
		analysis.AlertsBySeverity[alert.Severity]++
	}

	for severity, totalDuration := range severityDurations {
		analysis.AverageResolutionDuration[severity] = totalDuration / time.Duration(analysis.AlertsBySeverity[severity])
	}

	return analysis
}

// SaveAlerts saves the historical alerts to a file.
func (ham *HistoricalAlertManager) SaveAlerts(filepath string) error {
	ham.mu.Lock()
	defer ham.mu.Unlock()

	data, err := json.Marshal(ham.alerts)
	if err != nil {
		return err
	}

	return utils.WriteToFile(filepath, data)
}

// LoadAlerts loads the historical alerts from a file.
func (ham *HistoricalAlertManager) LoadAlerts(filepath string) error {
	ham.mu.Lock()
	defer ham.mu.Unlock()

	data, err := utils.ReadFromFile(filepath)
	if err != nil {
		return err
	}

	var alerts map[string]HistoricalAlert
	if err := json.Unmarshal(data, &alerts); err != nil {
		return err
	}

	ham.alerts = alerts
	return nil
}
