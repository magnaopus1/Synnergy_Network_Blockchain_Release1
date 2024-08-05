package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// AuditRecord represents an individual audit record
type AuditRecord struct {
	AuditID        string    `json:"audit_id"`
	Timestamp      time.Time `json:"timestamp"`
	PerformedBy    string    `json:"performed_by"`
	Action         string    `json:"action"`
	TransactionID  string    `json:"transaction_id"`
	Details        string    `json:"details"`
	ComplianceStatus string  `json:"compliance_status"`
}

// AuditComplianceManager manages audit records and compliance checks
type AuditComplianceManager struct {
	auditRecords map[string]AuditRecord
	transactionLedger *ledger.TransactionRecords
}

// NewAuditComplianceManager initializes a new AuditComplianceManager
func NewAuditComplianceManager(transactionLedger *ledger.TransactionRecords) *AuditComplianceManager {
	return &AuditComplianceManager{
		auditRecords: make(map[string]AuditRecord),
		transactionLedger: transactionLedger,
	}
}

// AddAuditRecord adds a new audit record to the manager
func (acm *AuditComplianceManager) AddAuditRecord(auditID, performedBy, action, transactionID, details, complianceStatus string) error {
	timestamp := time.Now()
	auditRecord := AuditRecord{
		AuditID:        auditID,
		Timestamp:      timestamp,
		PerformedBy:    performedBy,
		Action:         action,
		TransactionID:  transactionID,
		Details:        details,
		ComplianceStatus: complianceStatus,
	}

	if _, exists := acm.auditRecords[auditID]; exists {
		return errors.New("audit record already exists")
	}

	acm.auditRecords[auditID] = auditRecord
	return nil
}

// GetAuditRecord retrieves a specific audit record by its ID
func (acm *AuditComplianceManager) GetAuditRecord(auditID string) (AuditRecord, error) {
	if record, exists := acm.auditRecords[auditID]; exists {
		return record, nil
	}
	return AuditRecord{}, errors.New("audit record not found")
}

// GetAuditRecordsByTransaction retrieves all audit records for a specific transaction
func (acm *AuditComplianceManager) GetAuditRecordsByTransaction(transactionID string) ([]AuditRecord, error) {
	var records []AuditRecord
	for _, record := range acm.auditRecords {
		if record.TransactionID == transactionID {
			records = append(records, record)
		}
	}
	if len(records) == 0 {
		return nil, errors.New("no audit records found for the transaction")
	}
	return records, nil
}

// PerformComplianceCheck performs a compliance check on a transaction and adds an audit record
func (acm *AuditComplianceManager) PerformComplianceCheck(auditID, performedBy, transactionID, details string) error {
	transaction, err := acm.transactionLedger.GetTransactionRecord(transactionID)
	if err != nil {
		return err
	}

	complianceStatus := "compliant" // Simplified compliance check logic

	if transaction.Amount > 10000 { // Example condition for non-compliance
		complianceStatus = "non-compliant"
		details = fmt.Sprintf("%s | Reason: Transaction amount exceeds limit", details)
	}

	err = acm.AddAuditRecord(auditID, performedBy, "compliance_check", transactionID, details, complianceStatus)
	if err != nil {
		return err
	}

	return nil
}

// EncryptAuditData encrypts the audit data for secure storage
func (acm *AuditComplianceManager) EncryptAuditData(auditID, password string) (string, error) {
	if record, exists := acm.auditRecords[auditID]; exists {
		dataBytes, err := json.Marshal(record)
		if err != nil {
			return "", err
		}

		encryptedData, err := security.EncryptData(dataBytes, password)
		if err != nil {
			return "", err
		}

		return encryptedData, nil
	}
	return "", errors.New("audit record not found")
}

// DecryptAuditData decrypts the audit data
func (acm *AuditComplianceManager) DecryptAuditData(encryptedData, password string) (AuditRecord, error) {
	decryptedData, err := security.DecryptData(encryptedData, password)
	if err != nil {
		return AuditRecord{}, err
	}

	var record AuditRecord
	err = json.Unmarshal([]byte(decryptedData), &record)
	if err != nil {
		return AuditRecord{}, err
	}

	return record, nil
}

