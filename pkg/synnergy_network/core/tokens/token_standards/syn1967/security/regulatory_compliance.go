package security

import (
	"errors"
	"sync"
	"time"
)

// ComplianceStatus represents the compliance status of a token
type ComplianceStatus struct {
	TokenID     string
	IsCompliant bool
	Reason      string
	Timestamp   time.Time
}

// RegulatoryCompliance manages the compliance status of tokens
type RegulatoryCompliance struct {
	mu                 sync.RWMutex
	tokenCompliance    map[string]ComplianceStatus
	compliancePolicies []CompliancePolicy
}

// CompliancePolicy represents a policy that needs to be checked for compliance
type CompliancePolicy struct {
	Name        string
	Description string
	Check       func(tokenID string) (bool, string)
}

// NewRegulatoryCompliance creates a new instance of RegulatoryCompliance
func NewRegulatoryCompliance() *RegulatoryCompliance {
	return &RegulatoryCompliance{
		tokenCompliance: make(map[string]ComplianceStatus),
	}
}

// RegisterCompliancePolicy registers a new compliance policy
func (r *RegulatoryCompliance) RegisterCompliancePolicy(policy CompliancePolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.compliancePolicies = append(r.compliancePolicies, policy)
}

// CheckCompliance checks if a token is compliant based on registered policies
func (r *RegulatoryCompliance) CheckCompliance(tokenID string) ComplianceStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, policy := range r.compliancePolicies {
		isCompliant, reason := policy.Check(tokenID)
		if !isCompliant {
			status := ComplianceStatus{
				TokenID:     tokenID,
				IsCompliant: false,
				Reason:      reason,
				Timestamp:   time.Now(),
			}
			r.tokenCompliance[tokenID] = status
			return status
		}
	}

	status := ComplianceStatus{
		TokenID:     tokenID,
		IsCompliant: true,
		Reason:      "All policies passed",
		Timestamp:   time.Now(),
	}
	r.tokenCompliance[tokenID] = status
	return status
}

// GetComplianceStatus retrieves the compliance status of a token
func (r *RegulatoryCompliance) GetComplianceStatus(tokenID string) (ComplianceStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	status, exists := r.tokenCompliance[tokenID]
	if !exists {
		return ComplianceStatus{}, errors.New("compliance status not found")
	}
	return status, nil
}

// GenerateComplianceReport generates a compliance report for a token
func (r *RegulatoryCompliance) GenerateComplianceReport(tokenID string) (string, error) {
	status, err := r.GetComplianceStatus(tokenID)
	if err != nil {
		return "", err
	}

	report := "Compliance Report\n"
	report += "================\n"
	report += "Token ID: " + status.TokenID + "\n"
	report += "Compliance Status: " + complianceStatusString(status.IsCompliant) + "\n"
	report += "Reason: " + status.Reason + "\n"
	report += "Timestamp: " + status.Timestamp.String() + "\n"

	return report, nil
}

// complianceStatusString converts a compliance status to a string
func complianceStatusString(isCompliant bool) string {
	if isCompliant {
		return "Compliant"
	}
	return "Non-Compliant"
}

// Example policies
func examplePolicyCheck(tokenID string) (bool, string) {
	// Implement real-world logic here
	return true, ""
}

func exampleNonComplianceCheck(tokenID string) (bool, string) {
	// Example non-compliance for demonstration
	if tokenID == "noncompliant" {
		return false, "Example non-compliance reason"
	}
	return true, ""
}

func main() {
	// Example usage
	regComp := NewRegulatoryCompliance()
	regComp.RegisterCompliancePolicy(CompliancePolicy{
		Name:        "Example Policy",
		Description: "An example compliance policy check",
		Check:       examplePolicyCheck,
	})

	regComp.RegisterCompliancePolicy(CompliancePolicy{
		Name:        "Example Non-Compliance Policy",
		Description: "An example non-compliance policy check",
		Check:       exampleNonComplianceCheck,
	})

	// Check compliance for a token
	status := regComp.CheckCompliance("token1")
	println("Compliance Status:", status.IsCompliant, status.Reason)

	// Generate a compliance report
	report, _ := regComp.GenerateComplianceReport("token1")
	println(report)
}
