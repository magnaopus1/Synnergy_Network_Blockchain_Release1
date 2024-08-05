package assets

import (
	"time"
	"errors"
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

// GiltMetadata represents the metadata associated with a SYN11 gilt token.
type GiltMetadata struct {
	TokenID          string     // Unique identifier for the token
	GiltCode         string     // Internationally recognized gilt code
	Issuer           IssuerInfo // Information about the issuer
	MaturityDate     time.Time  // Date on which the gilt matures
	CouponRate       float64    // Interest rate paid to gilt holders
	CreationDate     time.Time  // Timestamp of token creation
	TotalSupply      uint64     // Total supply of tokens
	CirculatingSupply uint64    // Tokens currently in circulation
	LegalCompliance  LegalInfo  // Legal and compliance information
}

// NewGiltMetadata initializes a new GiltMetadata object.
func NewGiltMetadata(tokenID, giltCode string, issuer IssuerInfo, maturityDate time.Time, couponRate float64, totalSupply uint64) (*GiltMetadata, error) {
	// Validate inputs
	if tokenID == "" || giltCode == "" || totalSupply == 0 || couponRate < 0 {
		return nil, errors.New("invalid parameters for GiltMetadata")
	}

	return &GiltMetadata{
		TokenID:          tokenID,
		GiltCode:         giltCode,
		Issuer:           issuer,
		MaturityDate:     maturityDate,
		CouponRate:       couponRate,
		CreationDate:     time.Now(),
		TotalSupply:      totalSupply,
		CirculatingSupply: totalSupply,
		LegalCompliance:  LegalInfo{}, // To be defined based on implementation
	}, nil
}

// UpdateCouponRate updates the coupon rate for the gilt token.
func (gm *GiltMetadata) UpdateCouponRate(newRate float64) error {
	if newRate < 0 {
		return errors.New("coupon rate cannot be negative")
	}
	gm.CouponRate = newRate
	return nil
}

// AddComplianceInfo adds new compliance records to the gilt's metadata.
func (gm *GiltMetadata) AddComplianceInfo(regulatoryStatus string, licenses, compliance []string) {
	gm.LegalCompliance = LegalInfo{
		RegulatoryStatus: regulatoryStatus,
		Licenses:         licenses,
		Compliance:       compliance,
	}
}

// GetMaturityDate returns the maturity date of the gilt token.
func (gm *GiltMetadata) GetMaturityDate() time.Time {
	return gm.MaturityDate
}

// IsMature checks if the gilt token has reached its maturity date.
func (gm *GiltMetadata) IsMature() bool {
	return time.Now().After(gm.MaturityDate)
}
