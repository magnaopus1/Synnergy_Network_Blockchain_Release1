package audit_trails

import (
    "crypto/sha256"
    "encoding/json"
    "sync"
    "time"

    "github.com/sirupsen/logrus"
)

// AuditRecord defines the structure for storing audit information.
type AuditRecord struct {
    Timestamp   time.Time
    TransactionID string
    Data        string
    Hash        string
}

// DecentralizedVerifier manages the verification of audit trails in a decentralized manner.
type DecentralizedVerifier struct {
    records []*AuditRecord
    lock    sync.Mutex
}

// NewDecentralizedVerifier initializes a new verifier for decentralized audit trails.
func NewDecentralizedVerifier() *DecentralizedVerifier {
    return &DecentralizedVerifier{
        records: make([]*AuditRecord, 0),
    }
}

// AddRecord adds a new audit record and broadcasts it for decentralized verification.
func (dv *DecentralizedVerifier) AddRecord(txID, data string) error {
    dv.lock.Lock()
    defer dv.lock.Unlock()

    record := &AuditRecord{
        Timestamp:   time.Now(),
        TransactionID: txID,
        Data:        data,
        Hash:        dv.generateHash(txID, data),
    }
    dv.records = append(dv.records, record)

    // Broadcast the record for decentralized verification
    if err := dv.broadcastForVerification(record); err != nil {
        return err
    }

    logrus.WithFields(logrus.Fields{
        "timestamp": record.Timestamp,
        "txID":      record.TransactionID,
        "hash":      record.Hash,
    }).Info("Audit record added and broadcasted for verification")
    
    return nil
}

// generateHash generates a SHA-256 hash of the audit record.
func (dv *DecentralizedVerifier) generateHash(txID, data string) string {
    input := txID + data + time.Now().String()
    hash := sha256.Sum256([]byte(input))
    return string(hash[:])
}

// broadcastForVerification simulates broadcasting the audit record to a network of auditors.
func (dv *DecentralizedVerifier) broadcastForVerification(record *AuditRecord) error {
    // This would interface with a network layer to send the record to other nodes.
    // For simulation, this just logs the action.
    logrus.WithFields(logrus.Fields{
        "txID": record.TransactionID,
        "hash": record.Hash,
    }).Info("Broadcasting record for decentralized verification")
    return nil
}

// VerifyRecord allows external auditors to verify the hash of the record.
func (dv *DecentralizedVerifier) VerifyRecord(record *AuditRecord, expectedHash string) bool {
    return record.Hash == expectedHash
}
