package verifiers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// AuditRecord represents an audit record in the transparency audit log.
type AuditRecord struct {
	Timestamp time.Time
	NodeID    string
	Action    string
	Details   string
	Hash      string
}

// TransparencyAudit handles the transparency audit log for decentralized verification.
type TransparencyAudit struct {
	mu          sync.Mutex
	auditLog    []*AuditRecord
	recordIndex map[string]*AuditRecord
}

// NewTransparencyAudit initializes a new TransparencyAudit instance.
func NewTransparencyAudit() *TransparencyAudit {
	return &TransparencyAudit{
		auditLog:    []*AuditRecord{},
		recordIndex: make(map[string]*AuditRecord),
	}
}

// AddRecord adds a new record to the transparency audit log.
func (ta *TransparencyAudit) AddRecord(nodeID, action, details string) (string, error) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	timestamp := time.Now()
	record := &AuditRecord{
		Timestamp: timestamp,
		NodeID:    nodeID,
		Action:    action,
		Details:   details,
		Hash:      ta.generateHash(nodeID, action, details, timestamp),
	}

	ta.auditLog = append(ta.auditLog, record)
	ta.recordIndex[record.Hash] = record

	return record.Hash, nil
}

// GetRecord retrieves a record by its hash.
func (ta *TransparencyAudit) GetRecord(hash string) (*AuditRecord, error) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	record, exists := ta.recordIndex[hash]
	if !exists {
		return nil, errors.New("record not found")
	}

	return record, nil
}

// ListRecords lists all records in the transparency audit log.
func (ta *TransparencyAudit) ListRecords() []*AuditRecord {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	return ta.auditLog
}

// VerifyRecord verifies the integrity of a record by its hash.
func (ta *TransparencyAudit) VerifyRecord(hash string) (bool, error) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	record, exists := ta.recordIndex[hash]
	if !exists {
		return false, errors.New("record not found")
	}

	expectedHash := ta.generateHash(record.NodeID, record.Action, record.Details, record.Timestamp)
	return record.Hash == expectedHash, nil
}

// generateHash generates a unique hash for an audit record using Argon2.
func (ta *TransparencyAudit) generateHash(nodeID, action, details string, timestamp time.Time) string {
	data := fmt.Sprintf("%s:%s:%s:%s", nodeID, action, details, timestamp.String())
	salt := []byte(fmt.Sprintf("%d", timestamp.UnixNano()))
	hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// PrintAuditLog prints the transparency audit log.
func (ta *TransparencyAudit) PrintAuditLog() {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	fmt.Println("Transparency Audit Log:")
	for _, record := range ta.auditLog {
		fmt.Printf("Timestamp: %s, NodeID: %s, Action: %s, Details: %s, Hash: %s\n",
			record.Timestamp.String(), record.NodeID, record.Action, record.Details, record.Hash)
	}
}

// ExportAuditMetrics exports audit metrics for monitoring tools.
func (ta *TransparencyAudit) ExportAuditMetrics() map[string]interface{} {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	totalRecords := len(ta.auditLog)
	totalNodes := make(map[string]bool)
	for _, record := range ta.auditLog {
		totalNodes[record.NodeID] = true
	}

	metrics := map[string]interface{}{
		"totalRecords": totalRecords,
		"uniqueNodes":  len(totalNodes),
	}

	return metrics
}
