package audit_trails

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// AuditLog represents a single audit log entry
type AuditLog struct {
	Timestamp       time.Time `json:"timestamp"`
	TransactionID   string    `json:"transaction_id"`
	TransactionType string    `json:"transaction_type"`
	Participant     string    `json:"participant"`
	Details         string    `json:"details"`
}

// AuditTrail manages the collection of audit logs
type AuditTrail struct {
	logs []AuditLog
	logger *zap.Logger
}

// NewAuditTrail creates a new AuditTrail instance with customizable logging mechanism
func NewAuditTrail(logLevel zapcore.Level) (*AuditTrail, error) {
	cfg := zap.Config{
		Level:       zap.NewAtomicLevelAt(logLevel),
		Development: true,
		Sampling:    &zap.SamplingConfig{Initial: 100, Thereafter: 100},
		Encoding:    "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout", "audit_trail.log"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %v", err)
	}

	return &AuditTrail{
		logs:   []AuditLog{},
		logger: logger,
	}, nil
}

// AddLog adds a new log entry to the audit trail
func (at *AuditTrail) AddLog(transactionID, transactionType, participant, details string) {
	log := AuditLog{
		Timestamp:       time.Now(),
		TransactionID:   transactionID,
		TransactionType: transactionType,
		Participant:     participant,
		Details:         details,
	}

	at.logs = append(at.logs, log)
	at.logger.Info("New audit log entry added", zap.String("transaction_id", transactionID),
		zap.String("transaction_type", transactionType), zap.String("participant", participant),
		zap.String("details", details))
}

// GetLogs returns all audit logs
func (at *AuditTrail) GetLogs() []AuditLog {
	return at.logs
}

// SmartContract represents a simplified smart contract interface for generating audit logs
type SmartContract struct {
	AuditTrail *AuditTrail
}

// NewSmartContract creates a new SmartContract instance
func NewSmartContract(auditTrail *AuditTrail) *SmartContract {
	return &SmartContract{AuditTrail: auditTrail}
}

// ExecuteTransaction simulates the execution of a smart contract transaction
func (sc *SmartContract) ExecuteTransaction(transactionID, transactionType, participant, details string) error {
	if transactionID == "" || transactionType == "" || participant == "" {
		return errors.New("invalid transaction parameters")
	}

	sc.AuditTrail.AddLog(transactionID, transactionType, participant, details)
	return nil
}

// DecentralizedAuditVerification represents a framework for decentralized audit verification
type DecentralizedAuditVerification struct {
	Auditors []string
}

// NewDecentralizedAuditVerification creates a new instance of DecentralizedAuditVerification
func NewDecentralizedAuditVerification(auditors []string) *DecentralizedAuditVerification {
	return &DecentralizedAuditVerification{Auditors: auditors}
}

// VerifyLogs simulates the decentralized verification of audit logs
func (dav *DecentralizedAuditVerification) VerifyLogs(auditTrail *AuditTrail) (bool, error) {
	logs := auditTrail.GetLogs()
	if len(logs) == 0 {
		return false, errors.New("no logs to verify")
	}

	logsJSON, err := json.Marshal(logs)
	if err != nil {
		return false, fmt.Errorf("failed to marshal logs: %v", err)
	}

	fmt.Printf("Logs to be verified by auditors %v: %s\n", dav.Auditors, string(logsJSON))

	// Simulate consensus among auditors
	for _, auditor := range dav.Auditors {
		fmt.Printf("Auditor %s verifying logs...\n", auditor)
	}

	return true, nil
}

// CloseLogger closes the logger
func (at *AuditTrail) CloseLogger() {
	at.logger.Sync()
}
