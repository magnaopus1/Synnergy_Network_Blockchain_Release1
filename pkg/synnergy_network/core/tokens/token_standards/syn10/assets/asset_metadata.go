package assets

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "time"
)

// AssetMetadata represents the metadata associated with a SYN10 token.
type AssetMetadata struct {
    TokenID         string  // Unique identifier for the token
    CurrencyCode    string  // ISO 4217 currency code
    Issuer          IssuerInfo // Information about the issuer
    ExchangeRate    float64 // Current exchange rate relative to fiat currency
    CreationDate    time.Time // Timestamp of token creation
    TotalSupply     uint64  // Total supply of tokens
    CirculatingSupply uint64 // Tokens currently in circulation
    PeggingMechanism PeggingInfo // Details on how the token is pegged to fiat currency
    LegalCompliance LegalInfo  // Legal and compliance information
}

// IssuerInfo holds information about the token issuer.
type IssuerInfo struct {
    Name        string // Issuer name
    Location    string // Issuer location
    ContactInfo string // Issuer contact information
    Verified    bool   // Verification status of the issuer
}

// PeggingInfo contains details about the pegging mechanism.
type PeggingInfo struct {
    Type             string  // Type of pegging (fiat-backed, crypto-backed, algorithmic)
    CollateralAssets string  // Information on collateral backing the token
    StabilityMechanisms string // Mechanisms for maintaining peg stability
}

// LegalInfo contains information regarding the legal compliance of the token.
type LegalInfo struct {
    RegulatoryStatus   string  // Regulatory status and jurisdictions
    ComplianceHistory  string  // History of compliance audits and results
    LicensingDetails   string  // Licensing and certification information
}

// NewAssetMetadata creates a new AssetMetadata object with the provided details.
func NewAssetMetadata(tokenID, currencyCode string, issuer IssuerInfo, exchangeRate float64, totalSupply uint64, pegging PeggingInfo, legal LegalInfo) AssetMetadata {
    return AssetMetadata{
        TokenID:          generateTokenID(tokenID, currencyCode),
        CurrencyCode:     currencyCode,
        Issuer:           issuer,
        ExchangeRate:     exchangeRate,
        CreationDate:     time.Now(),
        TotalSupply:      totalSupply,
        CirculatingSupply: totalSupply,
        PeggingMechanism: pegging,
        LegalCompliance:  legal,
    }
}

// generateTokenID creates a unique identifier for the token based on input parameters.
func generateTokenID(base, currencyCode string) string {
    hasher := sha256.New()
    hasher.Write([]byte(base + currencyCode + time.Now().String()))
    return hex.EncodeToString(hasher.Sum(nil))
}

// UpdateExchangeRate updates the exchange rate of the token.
func (am *AssetMetadata) UpdateExchangeRate(newRate float64) {
    am.ExchangeRate = newRate
}

// MintTokens increases the total and circulating supply of the token.
func (am *AssetMetadata) MintTokens(amount uint64) {
    am.TotalSupply += amount
    am.CirculatingSupply += amount
}

// BurnTokens reduces the total and circulating supply of the token.
func (am *AssetMetadata) BurnTokens(amount uint64) error {
    if amount > am.CirculatingSupply {
        return fmt.Errorf("insufficient circulating supply to burn")
    }
    am.TotalSupply -= amount
    am.CirculatingSupply -= amount
    return nil
}

// VerifyIssuer checks if the issuer information matches the expected details.
func (am *AssetMetadata) VerifyIssuer(issuer IssuerInfo) bool {
    return am.Issuer.Name == issuer.Name && am.Issuer.Location == issuer.Location && am.Issuer.ContactInfo == issuer.ContactInfo
}

// IsCompliant returns true if the token meets all legal and regulatory requirements.
func (am *AssetMetadata) IsCompliant() bool {
    return am.LegalCompliance.RegulatoryStatus == "Compliant"
}

// GetAuditTrail provides a summary of changes and updates to the token's metadata.
func (am *AssetMetadata) GetAuditTrail() string {
    return fmt.Sprintf("TokenID: %s, Issuer: %s, Total Supply: %d, Circulating Supply: %d, Exchange Rate: %.2f, Compliance: %s",
        am.TokenID, am.Issuer.Name, am.TotalSupply, am.CirculatingSupply, am.ExchangeRate, am.LegalCompliance.RegulatoryStatus)
}
