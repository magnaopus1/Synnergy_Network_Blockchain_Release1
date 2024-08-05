package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"strings"
)

// SmartContract represents a basic structure of a smart contract
type SmartContract struct {
	ID        string
	Code      string
	Owner     string
	Signature string
}

// AuditReport represents the report generated after auditing a smart contract
type AuditReport struct {
	ContractID     string
	Owner          string
	IsValid        bool
	DetectedIssues []string
	Signature      string
}

// Auditor represents the smart contract auditor
type Auditor struct {
	auditedContracts map[string]AuditReport
}

// NewAuditor initializes a new Auditor
func NewAuditor() *Auditor {
	return &Auditor{
		auditedContracts: make(map[string]AuditReport),
	}
}

// AuditSmartContract audits a given smart contract and generates an audit report
func (a *Auditor) AuditSmartContract(contract SmartContract) (AuditReport, error) {
	log.Printf("Auditing smart contract: %s", contract.ID)
	isValid, issues := a.validateSmartContract(contract)
	report := AuditReport{
		ContractID:     contract.ID,
		Owner:          contract.Owner,
		IsValid:        isValid,
		DetectedIssues: issues,
		Signature:      generateAuditSignature(contract),
	}

	a.auditedContracts[contract.ID] = report
	return report, nil
}

// validateSmartContract validates the smart contract code for potential issues
func (a *Auditor) validateSmartContract(contract SmartContract) (bool, []string) {
	var issues []string
	code := contract.Code

	// Check for common vulnerabilities
	if strings.Contains(code, "call.value") {
		issues = append(issues, "Use of call.value() is insecure and can lead to reentrancy attacks")
	}

	if strings.Contains(code, "tx.origin") {
		issues = append(issues, "Use of tx.origin is insecure and can lead to phishing attacks")
	}

	if len(issues) > 0 {
		return false, issues
	}

	return true, issues
}

// generateAuditSignature generates a unique signature for the audit report
func generateAuditSignature(contract SmartContract) string {
	h := hmac.New(sha256.New, []byte(contract.Owner))
	h.Write([]byte(contract.Code))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyAuditReport verifies the authenticity and integrity of an audit report
func (a *Auditor) VerifyAuditReport(report AuditReport) bool {
	contract, exists := a.auditedContracts[report.ContractID]
	if !exists {
		log.Printf("Audit report verification failed: Contract %s not found", report.ContractID)
		return false
	}

	expectedSignature := generateAuditSignature(SmartContract{
		ID:    report.ContractID,
		Code:  contract.Signature,
		Owner: report.Owner,
	})

	if report.Signature != expectedSignature {
		log.Printf("Audit report verification failed: Signature mismatch")
		return false
	}

	log.Printf("Audit report verification succeeded for contract: %s", report.ContractID)
	return true
}

// ListAuditedContracts lists all audited contracts
func (a *Auditor) ListAuditedContracts() []AuditReport {
	reports := make([]AuditReport, 0, len(a.auditedContracts))
	for _, report := range a.auditedContracts {
		reports = append(reports, report)
	}
	return reports
}

// GetAuditReport retrieves the audit report for a given contract ID
func (a *Auditor) GetAuditReport(contractID string) (AuditReport, error) {
	report, exists := a.auditedContracts[contractID]
	if !exists {
		return AuditReport{}, errors.New("audit report not found")
	}
	return report, nil
}
