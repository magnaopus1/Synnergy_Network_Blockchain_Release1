package syn11

import (
	"errors"
	"time"

	"synnergy_network/core/tokens/token_standards/syn11/compliance"
	"synnergy_network/core/tokens/token_standards/syn11/ledger"
	"synnergy_network/core/tokens/token_standards/syn11/security"
	"synnergy_network/core/tokens/token_standards/syn11/storage"
	"synnergy_network/core/tokens/token_standards/syn11/transactions"
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
	TokenID           string     // Unique identifier for the token
	GiltCode          string     // Internationally recognized gilt code
	Issuer            IssuerInfo // Information about the issuer
	MaturityDate      time.Time  // Date on which the gilt matures
	CouponRate        float64    // Interest rate paid to gilt holders
	CreationDate      time.Time  // Timestamp of token creation
	TotalSupply       uint64     // Total supply of tokens
	CirculatingSupply uint64     // Tokens currently in circulation
	LegalCompliance   LegalInfo  // Legal and compliance information
}

// Syn11Token represents a SYN11 token, including its metadata and state.
type Syn11Token struct {
	Name        string       // Name of the token
	Value       float64      // Value of the token in fiat currency
	Metadata    GiltMetadata // Metadata about the token
	CurrentOwner string       // Current owner's address
	IsActive    bool         // Status of the token (active or inactive)
}

// NewGiltMetadata initializes a new GiltMetadata object.
func NewGiltMetadata(tokenID, giltCode string, issuer IssuerInfo, maturityDate time.Time, couponRate float64, totalSupply uint64) (*GiltMetadata, error) {
	// Validate inputs
	if tokenID == "" || giltCode == "" || totalSupply == 0 || couponRate < 0 {
		return nil, errors.New("invalid parameters for GiltMetadata")
	}

	return &GiltMetadata{
		TokenID:           tokenID,
		GiltCode:          giltCode,
		Issuer:            issuer,
		MaturityDate:      maturityDate,
		CouponRate:        couponRate,
		CreationDate:      time.Now(),
		TotalSupply:       totalSupply,
		CirculatingSupply: totalSupply,
		LegalCompliance:   LegalInfo{}, // To be defined based on implementation
	}, nil
}

// NewSyn11Token creates a new Syn11Token.
func NewSyn11Token(name string, value float64, metadata GiltMetadata, owner string) *Syn11Token {
	return &Syn11Token{
		Name:         name,
		Value:        value,
		Metadata:     metadata,
		CurrentOwner: owner,
		IsActive:     true,
	}
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

// SYN11Manager manages SYN11 tokens, including issuance, transfers, and compliance.
type SYN11Manager struct {
	ledger       *ledger.LedgerManager
	storage      *storage.StorageManager
	compliance   *compliance.ComplianceManager
	security     *security.SecurityManager
	transactions *transactions.TransactionManager
}

// NewSYN11Manager creates a new SYN11Manager instance.
func NewSYN11Manager() *SYN11Manager {
	ledgerManager := ledger.NewLedgerManager()
	storageManager := storage.NewStorageManager()
	complianceManager := compliance.NewComplianceManager()
	securityManager := security.NewSecurityManager()
	transactionManager := transactions.NewTransactionManager(ledgerManager, storageManager, complianceManager)

	return &SYN11Manager{
		ledger:       ledgerManager,
		storage:      storageManager,
		compliance:   complianceManager,
		security:     securityManager,
		transactions: transactionManager,
	}
}

// IssueToken issues a new SYN11 token with the provided metadata.
func (manager *SYN11Manager) IssueToken(name string, value float64, metadata *GiltMetadata, owner string) (*Syn11Token, error) {
	if metadata == nil {
		return nil, errors.New("metadata is required")
	}

	// Ensure compliance and security checks
	if err := manager.compliance.ValidateIssuance(metadata); err != nil {
		return nil, err
	}
	if err := manager.security.VerifyIssuer(metadata.Issuer); err != nil {
		return nil, err
	}

	// Store the metadata and create the token
	token := NewSyn11Token(name, value, *metadata, owner)
	if err := manager.ledger.RecordNewToken(token); err != nil {
		return nil, err
	}
	if err := manager.storage.SaveMetadata(metadata); err != nil {
		return nil, err
	}

	return token, nil
}

// TransferToken transfers ownership of a SYN11 token.
func (manager *SYN11Manager) TransferToken(tokenID, newOwner string) error {
	token, err := manager.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if err := manager.security.ValidateTransfer(token, newOwner); err != nil {
		return err
	}

	token.CurrentOwner = newOwner
	if err := manager.ledger.UpdateToken(token); err != nil {
		return err
	}

	return nil
}
