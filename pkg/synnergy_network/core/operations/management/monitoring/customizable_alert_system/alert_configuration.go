package customizable_alert_system

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"synnergy_network/core/utils"
	"synnergy_network/core/monitoring"
)

// AlertConfig defines the structure of an alert configuration.
type AlertConfig struct {
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

// AlertConfigurationManager manages alert configurations.
type AlertConfigurationManager struct {
	configs map[string]AlertConfig
	mu      sync.Mutex
}

// NewAlertConfigurationManager creates a new AlertConfigurationManager.
func NewAlertConfigurationManager() *AlertConfigurationManager {
	return &AlertConfigurationManager{
		configs: make(map[string]AlertConfig),
	}
}

// AddAlertConfig adds a new alert configuration.
func (acm *AlertConfigurationManager) AddAlertConfig(name, description, comparisonType, metric string, threshold float64) (string, error) {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	id := utils.GenerateUUID()
	config := AlertConfig{
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

	acm.configs[id] = config
	return id, nil
}

// UpdateAlertConfig updates an existing alert configuration.
func (acm *AlertConfigurationManager) UpdateAlertConfig(id, name, description, comparisonType, metric string, threshold float64, active bool) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if config, exists := acm.configs[id]; exists {
		config.Name = name
		config.Description = description
		config.Threshold = threshold
		config.ComparisonType = comparisonType
		config.Metric = metric
		config.Active = active
		config.UpdatedAt = time.Now()

		acm.configs[id] = config
		return nil
	}

	return errors.New("alert configuration not found")
}

// DeleteAlertConfig deletes an alert configuration.
func (acm *AlertConfigurationManager) DeleteAlertConfig(id string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if _, exists := acm.configs[id]; exists {
		delete(acm.configs, id)
		return nil
	}

	return errors.New("alert configuration not found")
}

// GetAlertConfig retrieves an alert configuration by ID.
func (acm *AlertConfigurationManager) GetAlertConfig(id string) (AlertConfig, error) {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if config, exists := acm.configs[id]; exists {
		return config, nil
	}

	return AlertConfig{}, errors.New("alert configuration not found")
}

// ListAlertConfigs lists all alert configurations.
func (acm *AlertConfigurationManager) ListAlertConfigs() []AlertConfig {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	configs := make([]AlertConfig, 0, len(acm.configs))
	for _, config := range acm.configs {
		configs = append(configs, config)
	}
	return configs
}

// CheckAlertConfigs checks all alert configurations against the given metrics.
func (acm *AlertConfigurationManager) CheckAlertConfigs(metrics monitoring.Metrics) ([]string, error) {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	triggeredAlerts := []string{}
	for id, config := range acm.configs {
		if !config.Active {
			continue
		}

		metricValue, exists := metrics[config.Metric]
		if !exists {
			continue
		}

		if config.isTriggered(metricValue) {
			triggeredAlerts = append(triggeredAlerts, id)
		}
	}

	return triggeredAlerts, nil
}

// isTriggered checks if the alert configuration is triggered based on the comparison type and threshold.
func (config *AlertConfig) isTriggered(metricValue float64) bool {
	switch config.ComparisonType {
	case "greater_than":
		return metricValue > config.Threshold
	case "less_than":
		return metricValue < config.Threshold
	case "equal_to":
		return metricValue == config.Threshold
	default:
		return false
	}
}

// SaveConfigs saves the alert configurations to a file.
func (acm *AlertConfigurationManager) SaveConfigs(filepath string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	data, err := json.Marshal(acm.configs)
	if err != nil {
		return err
	}

	return utils.WriteToFile(filepath, data)
}

// LoadConfigs loads the alert configurations from a file.
func (acm *AlertConfigurationManager) LoadConfigs(filepath string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	data, err := utils.ReadFromFile(filepath)
	if err != nil {
		return err
	}

	var configs map[string]AlertConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return err
	}

	acm.configs = configs
	return nil
}
