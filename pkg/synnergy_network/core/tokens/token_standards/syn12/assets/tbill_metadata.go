package assets

import (
	"errors"
	"time"
)

// IssuerInfo represents the details about the issuing government or central bank.
type IssuerInfo struct {
	Name         string // Name of the issuing authority
	Location     string // Location of the issuing authority
	ContactInfo  string // Contact information for the issuer
	Verification string // Verification status or credentials of the issuer
}

// LegalInfo contains legal and compliance information related to the token.
type LegalInfo struct {
	RegulatoryStatus string   // Current regulatory status of the token
	Licenses         []string // Licenses and approvals obtained
	Compliance       []string // Compliance requirements met
}

// TBillMetadata represents the metadata associated with a SYN12 Treasury Bill token.
type TBillMetadata struct {
	TokenID           string     // Unique identifier for the token
	TBillCode         string     // Internationally recognized T-Bill code
	Issuer            IssuerInfo // Information about the issuer
	MaturityDate      time.Time  // Date on which the T-Bill matures
	DiscountRate      float64    // Discount rate at which the T-Bill is issued
	CreationDate      time.Time  // Timestamp of token creation
	TotalSupply       uint64     // Total supply of tokens
	CirculatingSupply uint64     // Tokens currently in circulation
	LegalCompliance   LegalInfo  // Legal and compliance information
}

// NewTBillMetadata initializes a new TBillMetadata object.
func NewTBillMetadata(tokenID, tbillCode string, issuer IssuerInfo, maturityDate time.Time, discountRate float64, totalSupply uint64) (*TBillMetadata, error) {
	// Validate inputs
	if tokenID == "" || tbillCode == "" || totalSupply == 0 || discountRate < 0 {
		return nil, errors.New("invalid parameters for TBillMetadata")
	}

	return &TBillMetadata{
		TokenID:           tokenID,
		TBillCode:         tbillCode,
		Issuer:            issuer,
		MaturityDate:      maturityDate,
		DiscountRate:      discountRate,
		CreationDate:      time.Now(),
		TotalSupply:       totalSupply,
		CirculatingSupply: totalSupply,
		LegalCompliance:   LegalInfo{}, // To be defined based on implementation
	}, nil
}

// UpdateDiscountRate updates the discount rate for the T-Bill token.
func (tm *TBillMetadata) UpdateDiscountRate(newRate float64) error {
	if newRate < 0 {
		return errors.New("discount rate cannot be negative")
	}
	tm.DiscountRate = newRate
	return nil
}

// AddComplianceInfo adds new compliance records to the T-Bill's metadata.
func (tm *TBillMetadata) AddComplianceInfo(regulatoryStatus string, licenses, compliance []string) {
	tm.LegalCompliance = LegalInfo{
		RegulatoryStatus: regulatoryStatus,
		Licenses:         licenses,
		Compliance:       compliance,
	}
}

// GetMaturityDate returns the maturity date of the T-Bill token.
func (tm *TBillMetadata) GetMaturityDate() time.Time {
	return tm.MaturityDate
}

// IsMature checks if the T-Bill token has reached its maturity date.
func (tm *TBillMetadata) IsMature() bool {
	return time.Now().After(tm.MaturityDate)
}
