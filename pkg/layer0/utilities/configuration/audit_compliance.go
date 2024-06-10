package configuration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/synthron_blockchain/pkg/layer0/utilities/encryption_utils"
	"github.com/synthron_blockchain/pkg/layer0/utilities/logging_utils"
)

// AuditLogEntry represents a single audit log entry
type AuditLogEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Actor       string    `json:"actor"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	Hash        string    `json:"hash"`
}

// AuditLog represents the audit log with entries
type AuditLog struct {
	Entries []AuditLogEntry `json:"entries"`
}

// ComplianceConfig holds compliance configuration details
type ComplianceConfig struct {
	AuditLogPath    string `json:"audit_log_path"`
	EncryptionKey   string `json:"encryption_key"`
	ComplianceRules string `json:"compliance_rules"`
}

// NewComplianceConfig creates a new ComplianceConfig
func NewComplianceConfig(auditLogPath, encryptionKey, complianceRules string) *ComplianceConfig {
	return &ComplianceConfig{
		AuditLogPath:    auditLogPath,
		EncryptionKey:   encryptionKey,
		ComplianceRules: complianceRules,
	}
}

// LogAction logs an action to the audit log
func (cc *ComplianceConfig) LogAction(actor, action, description string) error {
	timestamp := time.Now()
	hash := cc.generateHash(actor, action, description, timestamp)

	entry := AuditLogEntry{
		Timestamp:   timestamp,
		Actor:       actor,
		Action:      action,
		Description: description,
		Hash:        hash,
	}

	return cc.appendAuditLog(entry)
}

// GenerateHash generates a hash for the audit log entry
func (cc *ComplianceConfig) generateHash(actor, action, description string, timestamp time.Time) string {
	data := fmt.Sprintf("%s:%s:%s:%s", actor, action, description, timestamp.String())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// AppendAuditLog appends an entry to the audit log
func (cc *ComplianceConfig) appendAuditLog(entry AuditLogEntry) error {
	auditLog, err := cc.loadAuditLog()
	if err != nil {
		return err
	}

	auditLog.Entries = append(auditLog.Entries, entry)

	return cc.saveAuditLog(auditLog)
}

// LoadAuditLog loads the audit log from file
func (cc *ComplianceConfig) loadAuditLog() (*AuditLog, error) {
	if _, err := os.Stat(cc.AuditLogPath); os.IsNotExist(err) {
		return &AuditLog{}, nil
	}

	encryptedData, err := ioutil.ReadFile(cc.AuditLogPath)
	if err != nil {
		return nil, err
	}

	data, err := encryption_utils.Decrypt(encryptedData, cc.EncryptionKey)
	if err != nil {
		return nil, err
	}

	var auditLog AuditLog
	if err := json.Unmarshal(data, &auditLog); err != nil {
		return nil, err
	}

	return &auditLog, nil
}

// SaveAuditLog saves the audit log to file
func (cc *ComplianceConfig) saveAuditLog(auditLog *AuditLog) error {
	data, err := json.Marshal(auditLog)
	if err != nil {
		return err
	}

	encryptedData, err := encryption_utils.Encrypt(data, cc.EncryptionKey)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(cc.AuditLogPath, encryptedData, 0644)
}

// VerifyCompliance verifies the compliance of the audit log against the rules
func (cc *ComplianceConfig) VerifyCompliance() error {
	auditLog, err := cc.loadAuditLog()
	if err != nil {
		return err
	}

	for _, entry := range auditLog.Entries {
		hash := cc.generateHash(entry.Actor, entry.Action, entry.Description, entry.Timestamp)
		if hash != entry.Hash {
			return errors.New("audit log has been tampered with")
		}
	}

	// Additional compliance checks based on cc.ComplianceRules can be added here

	return nil
}

// AuditCompliance initializes audit compliance and verifies the initial compliance
func AuditCompliance(configPath string) (*ComplianceConfig, error) {
	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config ComplianceConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, err
	}

	if err := config.VerifyCompliance(); err != nil {
		logging_utils.LogError("Compliance verification failed: %v", err)
		return nil, err
	}

	return &config, nil
}
