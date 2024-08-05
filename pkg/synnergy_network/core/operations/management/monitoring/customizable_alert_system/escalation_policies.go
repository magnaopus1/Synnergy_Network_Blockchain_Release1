package customizable_alert_system

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"synnergy_network/core/utils"
	"synnergy_network/core/monitoring"
)

// EscalationPolicy defines the structure of an escalation policy.
type EscalationPolicy struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	AlertConditions []string  `json:"alert_conditions"` // List of alert condition IDs
	EscalationSteps []Step    `json:"escalation_steps"`
	Active         bool      `json:"active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Step defines a single step in an escalation policy.
type Step struct {
	Delay        time.Duration `json:"delay"`          // Delay before this step is executed
	Notification string        `json:"notification"`   // Notification method, e.g., "email", "sms", "slack"
	Recipients   []string      `json:"recipients"`     // List of recipient IDs
	Action       string        `json:"action"`         // Action to be taken, e.g., "notify", "auto-resolve"
}

// EscalationPolicyManager manages escalation policies.
type EscalationPolicyManager struct {
	policies map[string]EscalationPolicy
	mu       sync.Mutex
}

// NewEscalationPolicyManager creates a new EscalationPolicyManager.
func NewEscalationPolicyManager() *EscalationPolicyManager {
	return &EscalationPolicyManager{
		policies: make(map[string]EscalationPolicy),
	}
}

// AddEscalationPolicy adds a new escalation policy.
func (epm *EscalationPolicyManager) AddEscalationPolicy(name, description string, alertConditions []string, escalationSteps []Step) (string, error) {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	id := utils.GenerateUUID()
	policy := EscalationPolicy{
		ID:             id,
		Name:           name,
		Description:    description,
		AlertConditions: alertConditions,
		EscalationSteps: escalationSteps,
		Active:         true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	epm.policies[id] = policy
	return id, nil
}

// UpdateEscalationPolicy updates an existing escalation policy.
func (epm *EscalationPolicyManager) UpdateEscalationPolicy(id, name, description string, alertConditions []string, escalationSteps []Step, active bool) error {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	if policy, exists := epm.policies[id]; exists {
		policy.Name = name
		policy.Description = description
		policy.AlertConditions = alertConditions
		policy.EscalationSteps = escalationSteps
		policy.Active = active
		policy.UpdatedAt = time.Now()

		epm.policies[id] = policy
		return nil
	}

	return errors.New("escalation policy not found")
}

// DeleteEscalationPolicy deletes an escalation policy.
func (epm *EscalationPolicyManager) DeleteEscalationPolicy(id string) error {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	if _, exists := epm.policies[id]; exists {
		delete(epm.policies, id)
		return nil
	}

	return errors.New("escalation policy not found")
}

// GetEscalationPolicy retrieves an escalation policy by ID.
func (epm *EscalationPolicyManager) GetEscalationPolicy(id string) (EscalationPolicy, error) {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	if policy, exists := epm.policies[id]; exists {
		return policy, nil
	}

	return EscalationPolicy{}, errors.New("escalation policy not found")
}

// ListEscalationPolicies lists all escalation policies.
func (epm *EscalationPolicyManager) ListEscalationPolicies() []EscalationPolicy {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	policies := make([]EscalationPolicy, 0, len(epm.policies))
	for _, policy := range epm.policies {
		policies = append(policies, policy)
	}
	return policies
}

// TriggerEscalation triggers the escalation process for a given alert condition.
func (epm *EscalationPolicyManager) TriggerEscalation(alertConditionID string, metrics monitoring.Metrics) error {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	for _, policy := range epm.policies {
		if policy.Active && contains(policy.AlertConditions, alertConditionID) {
			for _, step := range policy.EscalationSteps {
				time.Sleep(step.Delay)
				epm.executeStep(step, metrics)
			}
		}
	}

	return nil
}

// executeStep executes a single step in an escalation policy.
func (epm *EscalationPolicyManager) executeStep(step Step, metrics monitoring.Metrics) {
	switch step.Action {
	case "notify":
		epm.sendNotification(step.Notification, step.Recipients, metrics)
	case "auto-resolve":
		// Implement auto-resolve logic here
	}
}

// sendNotification sends a notification to the specified recipients.
func (epm *EscalationPolicyManager) sendNotification(method string, recipients []string, metrics monitoring.Metrics) {
	message := buildNotificationMessage(metrics)
	for _, recipient := range recipients {
		// Implement different notification methods (email, sms, slack, etc.)
		switch method {
		case "email":
			utils.SendEmail(recipient, message)
		case "sms":
			utils.SendSMS(recipient, message)
		case "slack":
			utils.SendSlackMessage(recipient, message)
		}
	}
}

// buildNotificationMessage builds a notification message based on the metrics.
func buildNotificationMessage(metrics monitoring.Metrics) string {
	// Implement message building logic based on metrics
	return "Alert: An issue has been detected."
}

// SavePolicies saves the escalation policies to a file.
func (epm *EscalationPolicyManager) SavePolicies(filepath string) error {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	data, err := json.Marshal(epm.policies)
	if err != nil {
		return err
	}

	return utils.WriteToFile(filepath, data)
}

// LoadPolicies loads the escalation policies from a file.
func (epm *EscalationPolicyManager) LoadPolicies(filepath string) error {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	data, err := utils.ReadFromFile(filepath)
	if err != nil {
		return err
	}

	var policies map[string]EscalationPolicy
	if err := json.Unmarshal(data, &policies); err != nil {
		return err
	}

	epm.policies = policies
	return nil
}

// contains checks if a slice contains a specific element.
func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
