package security

import (
	"errors"
	"time"
)

// RegulatoryCompliance defines the structure for managing regulatory compliance
type RegulatoryCompliance struct {
	KYCRequirements     map[string]KYCInfo
	AMLRequirements     map[string]AMLInfo
	TransactionLimits   map[string]TransactionLimit
	ApprovedJurisdictions []string
}

// KYCInfo holds the Know Your Customer information for a user
type KYCInfo struct {
	Verified       bool
	VerificationDate time.Time
}

// AMLInfo holds the Anti-Money Laundering information for a user
type AMLInfo struct {
	Verified       bool
	VerificationDate time.Time
	RiskLevel      string
}

// TransactionLimit defines limits on transaction amounts for compliance purposes
type TransactionLimit struct {
	MaxAmount float64
	TimeFrame time.Duration
}

// NewRegulatoryCompliance creates a new RegulatoryCompliance instance
func NewRegulatoryCompliance(approvedJurisdictions []string) *RegulatoryCompliance {
	return &RegulatoryCompliance{
		KYCRequirements:       make(map[string]KYCInfo),
		AMLRequirements:       make(map[string]AMLInfo),
		TransactionLimits:     make(map[string]TransactionLimit),
		ApprovedJurisdictions: approvedJurisdictions,
	}
}

// AddKYCInfo adds or updates KYC information for a user
func (rc *RegulatoryCompliance) AddKYCInfo(userID string, verified bool, verificationDate time.Time) {
	rc.KYCRequirements[userID] = KYCInfo{Verified: verified, VerificationDate: verificationDate}
}

// AddAMLInfo adds or updates AML information for a user
func (rc *RegulatoryCompliance) AddAMLInfo(userID string, verified bool, verificationDate time.Time, riskLevel string) {
	rc.AMLRequirements[userID] = AMLInfo{Verified: verified, VerificationDate: verificationDate, RiskLevel: riskLevel}
}

// SetTransactionLimit sets a transaction limit for a user
func (rc *RegulatoryCompliance) SetTransactionLimit(userID string, maxAmount float64, timeFrame time.Duration) {
	rc.TransactionLimits[userID] = TransactionLimit{MaxAmount: maxAmount, TimeFrame: timeFrame}
}

// VerifyKYC checks if a user meets KYC requirements
func (rc *RegulatoryCompliance) VerifyKYC(userID string) error {
	kyc, exists := rc.KYCRequirements[userID]
	if !exists || !kyc.Verified {
		return errors.New("KYC verification required")
	}
	return nil
}

// VerifyAML checks if a user meets AML requirements
func (rc *RegulatoryCompliance) VerifyAML(userID string) error {
	aml, exists := rc.AMLRequirements[userID]
	if !exists || !aml.Verified {
		return errors.New("AML verification required")
	}
	return nil
}

// CheckTransactionLimit verifies if a transaction is within the set limit
func (rc *RegulatoryCompliance) CheckTransactionLimit(userID string, amount float64) error {
	limit, exists := rc.TransactionLimits[userID]
	if !exists {
		return nil // No limit set
	}

	if amount > limit.MaxAmount {
		return errors.New("transaction amount exceeds limit")
	}
	return nil
}

// IsJurisdictionApproved checks if a jurisdiction is approved
func (rc *RegulatoryCompliance) IsJurisdictionApproved(jurisdiction string) bool {
	for _, approved := range rc.ApprovedJurisdictions {
		if approved == jurisdiction {
			return true
		}
	}
	return false
}

// EnsureCompliance verifies all compliance requirements for a transaction
func (rc *RegulatoryCompliance) EnsureCompliance(userID string, amount float64, jurisdiction string) error {
	if err := rc.VerifyKYC(userID); err != nil {
		return err
	}

	if err := rc.VerifyAML(userID); err != nil {
		return err
	}

	if !rc.IsJurisdictionApproved(jurisdiction) {
		return errors.New("transaction jurisdiction not approved")
	}

	if err := rc.CheckTransactionLimit(userID, amount); err != nil {
		return err
	}

	return nil
}
