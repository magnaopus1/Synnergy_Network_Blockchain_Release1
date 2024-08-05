package customizable_alert_system

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
	
	"synnergy_network/core/utils"
	"synnergy_network/core/monitoring"
)

// AlertCondition defines the structure of an alert condition.
type AlertCondition struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Threshold      float64   `json:"threshold"`
	ComparisonType string    `json:"comparison_type"` // "greater_than", "less_than", "equal_to"
	Metric         string    `json:"metric"`          // Metric to monitor, e.g., "cpu_usage", "memory_usage"
	Active         bool      `json:"active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AlertManager manages alert conditions and checks.
type AlertManager struct {
	alertConditions map[string]AlertCondition
	mu              sync.Mutex
}

// NewAlertManager creates a new AlertManager.
func NewAlertManager() *AlertManager {
	return &AlertManager{
		alertConditions: make(map[string]AlertCondition),
	}
}

// AddAlertCondition adds a new alert condition.
func (am *AlertManager) AddAlertCondition(name, description, comparisonType, metric string, threshold float64) (string, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	id := utils.GenerateUUID()
	condition := AlertCondition{
		ID:             id,
		Name:           name,
		Description:    description,
		Threshold:      threshold,
		ComparisonType: comparisonType,
		Metric:         metric,
		Active:         true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	am.alertConditions[id] = condition
	return id, nil
}

// UpdateAlertCondition updates an existing alert condition.
func (am *AlertManager) UpdateAlertCondition(id, name, description, comparisonType, metric string, threshold float64, active bool) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if condition, exists := am.alertConditions[id]; exists {
		condition.Name = name
		condition.Description = description
		condition.Threshold = threshold
		condition.ComparisonType = comparisonType
		condition.Metric = metric
		condition.Active = active
		condition.UpdatedAt = time.Now()

		am.alertConditions[id] = condition
		return nil
	}

	return errors.New("alert condition not found")
}

// DeleteAlertCondition deletes an alert condition.
func (am *AlertManager) DeleteAlertCondition(id string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.alertConditions[id]; exists {
		delete(am.alertConditions, id)
		return nil
	}

	return errors.New("alert condition not found")
}

// GetAlertCondition retrieves an alert condition by ID.
func (am *AlertManager) GetAlertCondition(id string) (AlertCondition, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if condition, exists := am.alertConditions[id]; exists {
		return condition, nil
	}

	return AlertCondition{}, errors.New("alert condition not found")
}

// ListAlertConditions lists all alert conditions.
func (am *AlertManager) ListAlertConditions() []AlertCondition {
	am.mu.Lock()
	defer am.mu.Unlock()

	conditions := make([]AlertCondition, 0, len(am.alertConditions))
	for _, condition := range am.alertConditions {
		conditions = append(conditions, condition)
	}
	return conditions
}

// CheckAlertConditions checks all alert conditions against the given metrics.
func (am *AlertManager) CheckAlertConditions(metrics monitoring.Metrics) ([]string, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	triggeredAlerts := []string{}
	for id, condition := range am.alertConditions {
		if !condition.Active {
			continue
		}

		metricValue, exists := metrics[condition.Metric]
		if !exists {
			continue
		}

		if condition.isTriggered(metricValue) {
			triggeredAlerts = append(triggeredAlerts, id)
		}
	}

	return triggeredAlerts, nil
}

// isTriggered checks if the alert condition is triggered based on the comparison type and threshold.
func (condition *AlertCondition) isTriggered(metricValue float64) bool {
	switch condition.ComparisonType {
	case "greater_than":
		return metricValue > condition.Threshold
	case "less_than":
		return metricValue < condition.Threshold
	case "equal_to":
		return metricValue == condition.Threshold
	default:
		return false
	}
}

// SaveConditions saves the alert conditions to a file.
func (am *AlertManager) SaveConditions(filepath string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	data, err := json.Marshal(am.alertConditions)
	if err != nil {
		return err
	}

	return utils.WriteToFile(filepath, data)
}

// LoadConditions loads the alert conditions from a file.
func (am *AlertManager) LoadConditions(filepath string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	data, err := utils.ReadFromFile(filepath)
	if err != nil {
		return err
	}

	var conditions map[string]AlertCondition
	if err := json.Unmarshal(data, &conditions); err != nil {
		return err
	}

	am.alertConditions = conditions
	return nil
}
