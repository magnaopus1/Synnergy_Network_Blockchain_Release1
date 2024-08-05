package syn10

import (
	"errors"
	"regexp"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn10/currency_representation"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn10/transactions"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn10/management"
)

// AssetMetadata represents the metadata associated with a SYN10 token.
type AssetMetadata struct {
	TokenID         string                          // Unique identifier for the token
	CurrencyCode    string                          // ISO 4217 currency code
	Issuer          currency_representation.IssuerInfo // Information about the issuer
	ExchangeRate    float64                         // Current exchange rate relative to fiat currency
	CreationDate    time.Time                       // Timestamp of token creation
	TotalSupply     uint64                          // Total supply of tokens
	CirculatingSupply uint64                        // Tokens currently in circulation
	PeggingMechanism currency_representation.PeggingInfo // Details on how the token is pegged to fiat currency
	LegalCompliance currency_representation.LegalInfo  // Legal and compliance information
}

// SYN10Token represents the main structure for SYN10 token standard.
type SYN10Token struct {
	Metadata       AssetMetadata                   // Metadata about the SYN10 token
	Ledger         *ledger.TokenLedger             // Ledger for managing token transactions
	SecurityService *security.EncryptionService     // Service for managing encryption and security
	Validator      *transactions.TransactionValidator // Validator for transaction validation
	Management     *management.TokenManagement     // Management for token-related operations
}

// NewSYN10Token initializes a new SYN10 token.
func NewSYN10Token(tokenID string, issuer currency_representation.IssuerInfo, currencyCode string, initialSupply uint64, securityService *security.EncryptionService) (*SYN10Token, error) {
	if tokenID == "" || currencyCode == "" || initialSupply == 0 {
		return nil, errors.New("invalid token parameters")
	}

	ledger := ledger.NewTokenLedger()
	validator := transactions.NewTransactionValidator(ledger, securityService, initialSupply, []string{currencyCode})
	management := management.NewTokenManagement(ledger)

	token := &SYN10Token{
		Metadata: AssetMetadata{
			TokenID:         tokenID,
			CurrencyCode:    currencyCode,
			Issuer:          issuer,
			ExchangeRate:    1.0, // Initial exchange rate set to 1:1
			CreationDate:    time.Now(),
			TotalSupply:     initialSupply,
			CirculatingSupply: initialSupply,
			PeggingMechanism: currency_representation.PeggingInfo{}, // Placeholder, should be defined based on implementation
			LegalCompliance: currency_representation.LegalInfo{},     // Placeholder, should be defined based on implementation
		},
		Ledger:          ledger,
		SecurityService: securityService,
		Validator:       validator,
		Management:      management,
	}

	return token, nil
}

// Mint allows the issuer to create new tokens.
func (token *SYN10Token) Mint(amount uint64) error {
	if amount == 0 {
		return errors.New("amount must be greater than zero")
	}

	token.Metadata.TotalSupply += amount
	token.Metadata.CirculatingSupply += amount

	return token.Ledger.AddTokens(token.Metadata.Issuer.ID, amount)
}

// Burn allows the issuer to remove tokens from circulation.
func (token *SYN10Token) Burn(amount uint64) error {
	if amount == 0 || amount > token.Metadata.CirculatingSupply {
		return errors.New("invalid burn amount")
	}

	token.Metadata.CirculatingSupply -= amount
	token.Metadata.TotalSupply -= amount

	return token.Ledger.RemoveTokens(token.Metadata.Issuer.ID, amount)
}

// Transfer facilitates the transfer of tokens from one account to another.
func (token *SYN10Token) Transfer(from, to string, amount uint64) error {
	if err := token.Validator.ValidateSender(from); err != nil {
		return err
	}
	if err := token.Validator.ValidateReceiver(to); err != nil {
		return err
	}
	if err := token.Validator.ValidateAmount(amount); err != nil {
		return err
	}

	return token.Ledger.Transfer(from, to, amount)
}

// UpdateExchangeRate updates the exchange rate for the token.
func (token *SYN10Token) UpdateExchangeRate(newRate float64) error {
	if newRate <= 0 {
		return errors.New("exchange rate must be greater than zero")
	}

	token.Metadata.ExchangeRate = newRate
	return nil
}

// GetBalance retrieves the balance of a given address.
func (token *SYN10Token) GetBalance(address string) (uint64, error) {
	return token.Ledger.GetBalance(address)
}

// GetTokenDetails provides comprehensive details about the token.
func (token *SYN10Token) GetTokenDetails() AssetMetadata {
	return token.Metadata
}

// ValidateTransactionID ensures the transaction ID is unique and correctly formatted.
func (token *SYN10Token) ValidateTransactionID(transactionID string) error {
	encryptedID, err := token.SecurityService.Encrypt([]byte(transactionID))
	if err != nil {
		return errors.New("failed to encrypt transaction ID")
	}
	exists, err := token.Ledger.TransactionExists(string(encryptedID))
	if err != nil {
		return errors.New("could not check transaction ID existence")
	}
	if exists {
		return errors.New("duplicate transaction ID")
	}
	if !isValidTransactionID(transactionID) {
		return errors.New("invalid transaction ID format")
	}
	return nil
}

// isValidTransactionID checks if the transaction ID meets formatting criteria.
func isValidTransactionID(transactionID string) bool {
	return len(transactionID) == 64 && regexp.MustCompile("^[a-fA-F0-9]+$").MatchString(transactionID)
}
