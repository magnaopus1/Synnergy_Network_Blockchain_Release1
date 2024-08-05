package transactions

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/synnergy_network/syn10/ledger"
	"github.com/synnergy_network/syn10/security"
)

// TransactionValidator validates transactions according to SYN10 standards.
type TransactionValidator struct {
	ledger             *ledger.TokenLedger
	encryptionService  *security.EncryptionService
	maxTransactionAmount uint64
	allowedCurrencies  []string
}

// NewTransactionValidator initializes a new TransactionValidator.
func NewTransactionValidator(ledger *ledger.TokenLedger, encryptionService *security.EncryptionService, maxTransactionAmount uint64, allowedCurrencies []string) *TransactionValidator {
	return &TransactionValidator{
		ledger:              ledger,
		encryptionService:   encryptionService,
		maxTransactionAmount: maxTransactionAmount,
		allowedCurrencies:   allowedCurrencies,
	}
}

// ValidateSender validates the sender's address and their balance.
func (v *TransactionValidator) ValidateSender(senderAddress string) error {
	if !isValidAddress(senderAddress) {
		return fmt.Errorf("invalid sender address: %s", senderAddress)
	}
	balance, err := v.ledger.GetBalance(senderAddress)
	if err != nil {
		return fmt.Errorf("could not retrieve balance for sender address %s: %w", senderAddress, err)
	}
	if balance <= 0 {
		return errors.New("insufficient balance")
	}
	return nil
}

// ValidateReceiver checks if the receiver's address is valid.
func (v *TransactionValidator) ValidateReceiver(receiverAddress string) error {
	if !isValidAddress(receiverAddress) {
		return fmt.Errorf("invalid receiver address: %s", receiverAddress)
	}
	return nil
}

// ValidateAmount ensures the transaction amount is within allowed limits.
func (v *TransactionValidator) ValidateAmount(amount uint64) error {
	if amount <= 0 {
		return errors.New("amount must be greater than zero")
	}
	if amount > v.maxTransactionAmount {
		return fmt.Errorf("amount exceeds maximum allowed limit of %d", v.maxTransactionAmount)
	}
	return nil
}

// ValidateTransactionID ensures the transaction ID is unique and correctly formatted.
func (v *TransactionValidator) ValidateTransactionID(transactionID string) error {
	encryptedID, err := v.encryptionService.Encrypt([]byte(transactionID))
	if err != nil {
		return fmt.Errorf("failed to encrypt transaction ID: %w", err)
	}
	exists, err := v.ledger.TransactionExists(string(encryptedID))
	if err != nil {
		return fmt.Errorf("could not check transaction ID existence: %w", err)
	}
	if exists {
		return errors.New("duplicate transaction ID")
	}
	if !isValidTransactionID(transactionID) {
		return errors.New("invalid transaction ID format")
	}
	return nil
}

// isValidAddress checks if the address is a valid format.
func isValidAddress(address string) bool {
	// Assuming addresses are alphanumeric and between 26 to 35 characters.
	re := regexp.MustCompile("^[a-zA-Z0-9]{26,35}$")
	return re.MatchString(address)
}

// isValidTransactionID checks if the transaction ID meets formatting criteria.
func isValidTransactionID(transactionID string) bool {
	// Assuming transaction IDs are alphanumeric and 64 characters long.
	return len(transactionID) == 64 && regexp.MustCompile("^[a-fA-F0-9]+$").MatchString(transactionID)
}

// ValidateCurrency ensures that the currency is supported.
func (v *TransactionValidator) ValidateCurrency(currency string) error {
	for _, allowed := range v.allowedCurrencies {
		if currency == allowed {
			return nil
		}
	}
	return fmt.Errorf("currency %s is not supported", currency)
}

// Validate ensures all components of a transaction are valid.
func (v *TransactionValidator) Validate(transaction TransactionFeeFree) error {
	if err := v.ValidateSender(transaction.FromAddress); err != nil {
		return fmt.Errorf("sender validation failed: %w", err)
	}
	if err := v.ValidateReceiver(transaction.ToAddress); err != nil {
		return fmt.Errorf("receiver validation failed: %w", err)
	}
	if err := v.ValidateAmount(transaction.Amount); err != nil {
		return fmt.Errorf("amount validation failed: %w", err)
	}
	if err := v.ValidateTransactionID(transaction.TransactionID); err != nil {
		return fmt.Errorf("transaction ID validation failed: %w", err)
	}
	return nil
}
