package audit_trails

import (
	"errors"
	"time"

	"go.uber.org/zap"
)

// ComplianceMetrics represents the metrics collected for compliance
type ComplianceMetrics struct {
	AuditTrail *AuditTrail
	logger     *zap.Logger
}

// NewComplianceMetrics creates a new instance of ComplianceMetrics
func NewComplianceMetrics(auditTrail *AuditTrail, logger *zap.Logger) *ComplianceMetrics {
	return &ComplianceMetrics{
		AuditTrail: auditTrail,
		logger:     logger,
	}
}

// MetricsData represents the data structure for compliance metrics
type MetricsData struct {
	TotalTransactions     int                       `json:"total_transactions"`
	TransactionTypes      map[string]int            `json:"transaction_types"`
	AverageTransactionTime float64                   `json:"average_transaction_time"`
	AuditLogIntegrity     bool                      `json:"audit_log_integrity"`
}

// GetMetrics returns the compliance metrics
func (cm *ComplianceMetrics) GetMetrics() (*MetricsData, error) {
	if cm.AuditTrail == nil {
		return nil, errors.New("audit trail is not initialized")
	}

	logs := cm.AuditTrail.GetLogs()
	totalTransactions := len(logs)
	transactionTypes := make(map[string]int)
	var totalTransactionTime float64

	for _, log := range logs {
		transactionTypes[log.TransactionType]++
		totalTransactionTime += log.TransactionTime.Seconds()
	}

	averageTransactionTime := totalTransactionTime / float64(totalTransactions)

	// Assuming we have a method to verify audit log integrity
	auditLogIntegrity, err := cm.verifyAuditLogIntegrity()
	if err != nil {
		return nil, err
	}

	metrics := &MetricsData{
		TotalTransactions:     totalTransactions,
		TransactionTypes:      transactionTypes,
		AverageTransactionTime: averageTransactionTime,
		AuditLogIntegrity:     auditLogIntegrity,
	}

	return metrics, nil
}

// verifyAuditLogIntegrity verifies the integrity of the audit logs
func (cm *ComplianceMetrics) verifyAuditLogIntegrity() (bool, error) {
	if cm.AuditTrail == nil {
		return false, errors.New("audit trail is not initialized")
	}

	// Example logic for verifying audit log integrity
	logs := cm.AuditTrail.GetLogs()
	for _, log := range logs {
		if !cm.AuditTrail.VerifyLog(log) {
			return false, nil
		}
	}

	return true, nil
}

// StartMetricsServer starts the web server for the compliance metrics
func (cm *ComplianceMetrics) StartMetricsServer() {
	r := gin.Default()

	r.GET("/metrics", func(c *gin.Context) {
		data, err := cm.GetMetrics()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, data)
	})

	r.Run(":8081")
}

// AuditLog represents a single audit log entry
type AuditLog struct {
	TransactionID    string    `json:"transaction_id"`
	TransactionType  string    `json:"transaction_type"`
	Participant      string    `json:"participant"`
	Details          string    `json:"details"`
	Timestamp        time.Time `json:"timestamp"`
	TransactionTime  time.Duration `json:"transaction_time"`
}

// AuditTrail represents the audit trail of transactions
type AuditTrail struct {
	Logs []AuditLog
}

// GetLogs returns the audit logs
func (at *AuditTrail) GetLogs() []AuditLog {
	return at.Logs
}

// VerifyLog verifies the integrity of a single audit log
func (at *AuditTrail) VerifyLog(log AuditLog) bool {
	// Example logic for verifying a log entry
	return log.TransactionID != "" && log.Timestamp.Before(time.Now())
}

// AddLog adds a new log entry to the audit trail
func (at *AuditTrail) AddLog(log AuditLog) {
	at.Logs = append(at.Logs, log)
}
