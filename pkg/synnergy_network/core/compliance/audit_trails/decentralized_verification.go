package audit_trails

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DecentralizedVerification represents the structure for decentralized audit trail verification
type DecentralizedVerification struct {
	AuditTrail *AuditTrail
	Verifiers  []Verifier
	logger     *zap.Logger
	mutex      sync.Mutex
}

// Verifier represents an entity that verifies audit logs
type Verifier struct {
	ID        string
	PublicKey string
}

// VerificationResult represents the result of an audit log verification
type VerificationResult struct {
	TransactionID string `json:"transaction_id"`
	VerifierID    string `json:"verifier_id"`
	IsValid       bool   `json:"is_valid"`
	Timestamp     int64  `json:"timestamp"`
}

// NewDecentralizedVerification creates a new instance of DecentralizedVerification
func NewDecentralizedVerification(auditTrail *AuditTrail, verifiers []Verifier, logger *zap.Logger) *DecentralizedVerification {
	return &DecentralizedVerification{
		AuditTrail: auditTrail,
		Verifiers:  verifiers,
		logger:     logger,
	}
}

// verifyLog verifies the integrity of a single audit log
func (dv *DecentralizedVerification) verifyLog(log AuditLog) bool {
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	hash := sha256.New()
	hash.Write([]byte(log.TransactionID + log.TransactionType + log.Participant + log.Details + log.Timestamp.String()))
	expectedHash := hex.EncodeToString(hash.Sum(nil))

	return log.Hash == expectedHash
}

// verifyLogs initiates the verification process for all audit logs
func (dv *DecentralizedVerification) verifyLogs() []VerificationResult {
	var results []VerificationResult
	logs := dv.AuditTrail.GetLogs()

	for _, log := range logs {
		for _, verifier := range dv.Verifiers {
			isValid := dv.verifyLog(log)
			result := VerificationResult{
				TransactionID: log.TransactionID,
				VerifierID:    verifier.ID,
				IsValid:       isValid,
				Timestamp:     time.Now().Unix(),
			}
			results = append(results, result)
			dv.logger.Info("Verification Result", zap.Any("result", result))
		}
	}

	return results
}

// AddVerifier adds a new verifier to the decentralized verification system
func (dv *DecentralizedVerification) AddVerifier(verifier Verifier) {
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	dv.Verifiers = append(dv.Verifiers, verifier)
	dv.logger.Info("New Verifier Added", zap.String("verifier_id", verifier.ID))
}

// VerifyAuditTrails performs decentralized verification of the audit trails
func (dv *DecentralizedVerification) VerifyAuditTrails() ([]VerificationResult, error) {
	if dv.AuditTrail == nil {
		return nil, errors.New("audit trail is not initialized")
	}
	if len(dv.Verifiers) == 0 {
		return nil, errors.New("no verifiers available for decentralized verification")
	}

	results := dv.verifyLogs()
	return results, nil
}

// AuditLog represents a single audit log entry
type AuditLog struct {
	TransactionID    string        `json:"transaction_id"`
	TransactionType  string        `json:"transaction_type"`
	Participant      string        `json:"participant"`
	Details          string        `json:"details"`
	Timestamp        time.Time     `json:"timestamp"`
	TransactionTime  time.Duration `json:"transaction_time"`
	Hash             string        `json:"hash"`
}

// AuditTrail represents the audit trail of transactions
type AuditTrail struct {
	Logs []AuditLog
}

// GetLogs returns the audit logs
func (at *AuditTrail) GetLogs() []AuditLog {
	return at.Logs
}

// AddLog adds a new log entry to the audit trail
func (at *AuditTrail) AddLog(log AuditLog) {
	hash := sha256.New()
	hash.Write([]byte(log.TransactionID + log.TransactionType + log.Participant + log.Details + log.Timestamp.String()))
	log.Hash = hex.EncodeToString(hash.Sum(nil))

	at.Logs = append(at.Logs, log)
}
