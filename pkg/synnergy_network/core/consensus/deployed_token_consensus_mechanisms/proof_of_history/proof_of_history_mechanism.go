package proof_of_history

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// HistoricalRecord represents a single record in the blockchain's history.
type HistoricalRecord struct {
	Timestamp   int64  // Unix timestamp of the record
	Transaction string // Transaction data or details
	Hash        string // Hash of the record including the previous record's hash
	PreviousHash string // Hash of the previous record
}

// PoHGenerator is responsible for creating and validating the historical records using PoH.
type PoHGenerator struct {
	lastRecord *HistoricalRecord
}

// NewPoHGenerator initializes a new PoH generator with an initial record.
func NewPoHGenerator(initialTransaction string) *PoHGenerator {
	initialRecord := &HistoricalRecord{
		Timestamp:   time.Now().Unix(),
		Transaction: initialTransaction,
		Hash:        "",
		PreviousHash: "",
	}
	initialRecord.Hash = hashRecord(initialRecord)

	return &PoHGenerator{
		lastRecord: initialRecord,
	}
}

// CreateRecord creates a new historical record linked to the last record in the chain.
func (p *PoHGenerator) CreateRecord(transaction string) *HistoricalRecord {
	newRecord := &HistoricalRecord{
		Timestamp:   time.Now().Unix(),
		Transaction: transaction,
		PreviousHash: p.lastRecord.Hash,
	}
	newRecord.Hash = hashRecord(newRecord)
	p.lastRecord = newRecord

	return newRecord
}

// VerifyRecord validates that a record's hash is correct and fits in the chain correctly.
func (p *PoHGenerator) VerifyRecord(record *HistoricalRecord) bool {
	expectedHash := hashRecord(record)
	return record.Hash == expectedHash && record.PreviousHash == p.lastRecord.Hash
}

// hashRecord generates a SHA-256 hash for a HistoricalRecord.
func hashRecord(record *HistoricalRecord) string {
	recordString := string(record.Timestamp) + record.Transaction + record.PreviousHash
	hashBytes := sha256.Sum256([]byte(recordString))
	return hex.EncodeToString(hashBytes[:])
}

// RetrieveLastRecord returns the most recent record in the history.
func (p *PoHGenerator) RetrieveLastRecord() *HistoricalRecord {
	return p.lastRecord
}
