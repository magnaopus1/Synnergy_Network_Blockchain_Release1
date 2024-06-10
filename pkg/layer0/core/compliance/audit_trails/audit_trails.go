package audit_trails

import (
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "time"

    "github.com/sirupsen/logrus" // Logrus is used for structured, pluggable logging.
)

// AuditRecord defines the structure for an audit trail record.
type AuditRecord struct {
    Timestamp   time.Time
    TransactionID string
    Data        string
    Hash        string
}

// AuditTrail manages the collection and storage of audit records.
type AuditTrail struct {
    records []*AuditRecord
    lock    sync.Mutex
}

// NewAuditTrail initializes a new audit trail system.
func NewAuditTrail() *AuditTrail {
    return &AuditTrail{
        records: make([]*AuditRecord, 0),
    }
}

// LogTransaction logs a transaction to the audit trail.
func (at *AuditTrail) LogTransaction(txID string, data string) {
    at.lock.Lock()
    defer at.lock.Unlock()

    record := &AuditRecord{
        Timestamp:   time.Now(),
        TransactionID: txID,
        Data:        data,
        Hash:        at.generateHash(txID, data),
    }
    at.records = append(at.records, record)
    at.saveRecord(record)
}

// generateHash creates a hash for the audit record to ensure integrity.
func (at *AuditTrail) generateHash(txID, data string) string {
    input := txID + data + time.Now().String()
    hash := sha256.Sum256([]byte(input))
    return hex.EncodeToString(hash[:])
}

// saveRecord saves an audit record to a persistent storage.
func (at *AuditTrail) saveRecord(record *AuditRecord) {
    // This function would interface with a database or a decentralized storage system.
    logrus.WithFields(logrus.Fields{
        "timestamp":   record.Timestamp,
        "transaction": record.TransactionID,
        "data":        record.Data,
        "hash":        record.Hash,
    }).Info("Audit record saved")
}

// VerifyAuditTrail verifies the integrity of the audit trail.
func (at *AuditTrail) VerifyAuditTrail() bool {
    for i, record := range at.records {
        if record.Hash != at.generateHash(record.TransactionID, record.Data) {
            logrus.WithFields(logrus.Fields{
                "index": i,
                "hash":  record.Hash,
            }).Error("Audit trail integrity check failed")
            return false
        }
    }
    return true
}

