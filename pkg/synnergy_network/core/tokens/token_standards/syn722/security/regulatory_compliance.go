package security

import (
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"
)

// ComplianceRule defines a single compliance rule
type ComplianceRule struct {
	ID          string
	Description string
	Check       func(transaction map[string]interface{}) bool
}

// ComplianceManager handles the regulatory compliance checks
type ComplianceManager struct {
	mu    sync.Mutex
	Rules map[string]ComplianceRule
}

// NewComplianceManager creates a new ComplianceManager instance
func NewComplianceManager() *ComplianceManager {
	return &ComplianceManager{
		Rules: make(map[string]ComplianceRule),
	}
}

// AddRule adds a new compliance rule
func (cm *ComplianceManager) AddRule(rule ComplianceRule) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.Rules[rule.ID] = rule
}

// RemoveRule removes an existing compliance rule
func (cm *ComplianceManager) RemoveRule(ruleID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.Rules, ruleID)
}

// CheckCompliance checks a transaction against all compliance rules
func (cm *ComplianceManager) CheckCompliance(transaction map[string]interface{}) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for _, rule := range cm.Rules {
		if !rule.Check(transaction) {
			return errors.New("transaction does not comply with rule: " + rule.Description)
		}
	}
	return nil
}

// AuditLog represents an audit log entry
type AuditLog struct {
	Timestamp   time.Time
	UserID      string
	Action      string
	Description string
}

// AuditManager handles logging and retrieving audit logs
type AuditManager struct {
	mu   sync.Mutex
	Logs []AuditLog
}

// NewAuditManager creates a new AuditManager instance
func NewAuditManager() *AuditManager {
	return &AuditManager{
		Logs: make([]AuditLog, 0),
	}
}

// LogAction logs a compliance-related action
func (am *AuditManager) LogAction(userID, action, description string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	logEntry := AuditLog{
		Timestamp:   time.Now(),
		UserID:      userID,
		Action:      action,
		Description: description,
	}
	am.Logs = append(am.Logs, logEntry)
}

// GetLogs retrieves all audit logs
func (am *AuditManager) GetLogs() []AuditLog {
	am.mu.Lock()
	defer am.mu.Unlock()
	return am.Logs
}

// ComplianceData stores regulatory compliance data and audit logs
type ComplianceData struct {
	ComplianceManager *ComplianceManager
	AuditManager      *AuditManager
}

// NewComplianceData creates a new ComplianceData instance
func NewComplianceData() *ComplianceData {
	return &ComplianceData{
		ComplianceManager: NewComplianceManager(),
		AuditManager:      NewAuditManager(),
	}
}

// AddComplianceRule adds a new compliance rule
func (cd *ComplianceData) AddComplianceRule(rule ComplianceRule) {
	cd.ComplianceManager.AddRule(rule)
	cd.AuditManager.LogAction("system", "add_rule", "Added compliance rule: "+rule.Description)
}

// RemoveComplianceRule removes an existing compliance rule
func (cd *ComplianceData) RemoveComplianceRule(ruleID string) {
	cd.ComplianceManager.RemoveRule(ruleID)
	cd.AuditManager.LogAction("system", "remove_rule", "Removed compliance rule: "+ruleID)
}

// CheckTransactionCompliance checks a transaction against all compliance rules
func (cd *ComplianceData) CheckTransactionCompliance(transaction map[string]interface{}) error {
	err := cd.ComplianceManager.CheckCompliance(transaction)
	if err != nil {
		cd.AuditManager.LogAction(transaction["userID"].(string), "check_compliance", "Transaction failed compliance check: "+err.Error())
		return err
	}
	cd.AuditManager.LogAction(transaction["userID"].(string), "check_compliance", "Transaction passed compliance check")
	return nil
}

// GetComplianceLogs retrieves all compliance-related audit logs
func (cd *ComplianceData) GetComplianceLogs() []AuditLog {
	return cd.AuditManager.GetLogs()
}

// Serialization and deserialization methods

// ToJSON serializes the compliance data to JSON
func (cd *ComplianceData) ToJSON() (string, error) {
	data, err := json.Marshal(cd)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes the JSON string to compliance data
func (cd *ComplianceData) FromJSON(data string) error {
	return json.Unmarshal([]byte(data), cd)
}

// Example compliance rule: KYC check
func kycCheck(transaction map[string]interface{}) bool {
	userID := transaction["userID"].(string)
	return strings.HasPrefix(userID, "KYC-")
}

