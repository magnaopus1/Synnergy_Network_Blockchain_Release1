package integration

import (
	"errors"
	"fmt"
	"time"
	"sync"
)

// Syn130 represents a token with comprehensive attributes for interoperability.
type Syn130 struct {
	ID                    string
	Name                  string
	Owner                 string
	Value                 float64
	OwnershipProof		 OwnershipProof
	Metadata              map[string]string
	SaleHistory           []SaleRecord
	LeaseTerms            []LeaseTerms
	LicenseTerms          []LicenseTerms
	RentalTerms           []RentalTerms
	CoOwnershipAgreements []CoOwnershipAgreement
	AssetType             string
	Classification        string
	IoTData               map[string]string
	CreationDate          time.Time
	LastUpdated           time.Time
	TransactionHistory    []TransactionRecord
	Provenance            []ProvenanceRecord
	Interoperability      InteroperabilityDetails
	Scalability           ScalabilityDetails
	AssetCategory         string
	AssetClassification   string
	AssetMetadata         AssetMetadata
	PeggedAsset           PeggedAsset
	TrackedAsset          TrackedAsset
	AssetStatus           AssetStatus
	AssetValuation        AssetValuation
	IoTDevice             IoTDevice
	LeaseAgreement        LeaseAgreement
	LicenseAgreement      LicenseAgreement
	RentalAgreement       RentalAgreement
	Lock                  sync.RWMutex
}


// SaleRecord represents a sale record of a token.
type SaleRecord struct {
	Buyer   string
	Seller  string
	Price   float64
	Date    time.Time
}

// LeaseTerms represents the lease terms for a token.
type LeaseTerms struct {
	Leasee        string
	StartDate     time.Time
	EndDate       time.Time
	PaymentTerms  string
	Notifications []Notification
}

// LicenseTerms represents the licensing terms for a token.
type LicenseTerms struct {
	Licensee      string
	StartDate     time.Time
	EndDate       time.Time
	LicenseScope  string
	PaymentTerms  string
	Notifications []Notification
}

// RentalTerms represents the rental terms for a token.
type RentalTerms struct {
	Renter        string
	StartDate     time.Time
	EndDate       time.Time
	RentalRate    float64
	PaymentTerms  string
	Notifications []Notification
}

// TransactionRecord represents a transaction record for the token.
type TransactionRecord struct {
	From    string
	To      string
	Amount  float64
	Date    time.Time
	Details string
}

// ProvenanceRecord represents the provenance record for the token.
type ProvenanceRecord struct {
	Owner   string
	Date    time.Time
	Details string
}

// Notification represents a notification related to lease, license, or rental terms.
type Notification struct {
	Message          string
	Date             time.Time
	NotificationType string
}

// InteroperabilityDetails represents the interoperability details for the token.
type InteroperabilityDetails struct {
	ConnectedChains []string
	BridgeStatus    map[string]bool
}

// TokenInteroperabilityTools provides tools for managing token interoperability.
type TokenInteroperabilityTools struct{}

// NewTokenInteroperabilityTools creates a new instance of TokenInteroperabilityTools.
func NewTokenInteroperabilityTools() *TokenInteroperabilityTools {
	return &TokenInteroperabilityTools{}
}

// EnableInteroperability enables interoperability with another blockchain.
func (tit *TokenInteroperabilityTools) EnableInteroperability(token *Syn130, blockchain string) error {
	token.Lock.Lock()
	defer token.Lock.Unlock()
	
	if token.Interoperability.BridgeStatus == nil {
		token.Interoperability.BridgeStatus = make(map[string]bool)
	}

	if _, exists := token.Interoperability.BridgeStatus[blockchain]; exists {
		return errors.New("interoperability already enabled for this blockchain")
	}

	token.Interoperability.ConnectedChains = append(token.Interoperability.ConnectedChains, blockchain)
	token.Interoperability.BridgeStatus[blockchain] = true
	token.LastUpdated = time.Now()

	return nil
}

// DisableInteroperability disables interoperability with another blockchain.
func (tit *TokenInteroperabilityTools) DisableInteroperability(token *Syn130, blockchain string) error {
	token.Lock.Lock()
	defer token.Lock.Unlock()

	if token.Interoperability.BridgeStatus == nil {
		return errors.New("no interoperability settings found")
	}

	if _, exists := token.Interoperability.BridgeStatus[blockchain]; !exists {
		return errors.New("interoperability not enabled for this blockchain")
	}

	delete(token.Interoperability.BridgeStatus, blockchain)
	for i, chain := range token.Interoperability.ConnectedChains {
		if chain == blockchain {
			token.Interoperability.ConnectedChains = append(token.Interoperability.ConnectedChains[:i], token.Interoperability.ConnectedChains[i+1:]...)
			break
		}
	}
	token.LastUpdated = time.Now()

	return nil
}

// IsInteroperable checks if the token is interoperable with a specific blockchain.
func (tit *TokenInteroperabilityTools) IsInteroperable(token *Syn130, blockchain string) bool {
	token.Lock.RLock()
	defer token.Lock.RUnlock()

	if token.Interoperability.BridgeStatus == nil {
		return false
	}

	status, exists := token.Interoperability.BridgeStatus[blockchain]
	return exists && status
}

// ListInteroperableChains lists all blockchains the token is interoperable with.
func (tit *TokenInteroperabilityTools) ListInteroperableChains(token *Syn130) []string {
	token.Lock.RLock()
	defer token.Lock.RUnlock()

	return token.Interoperability.ConnectedChains
}

// GenerateInteroperabilityProof generates proof of interoperability for cross-chain transactions.
func (tit *TokenInteroperabilityTools) GenerateInteroperabilityProof(token *Syn130, blockchain string) (string, error) {
	token.Lock.RLock()
	defer token.Lock.RUnlock()

	if !tit.IsInteroperable(token, blockchain) {
		return "", errors.New("interoperability not enabled for this blockchain")
	}

	// Simulate proof generation (in reality, this would involve more complex cryptographic operations)
	proof := fmt.Sprintf("Proof-of-Interoperability for Token %s on Blockchain %s", token.ID, blockchain)
	return proof, nil
}

