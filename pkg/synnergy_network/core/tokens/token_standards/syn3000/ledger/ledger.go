package ledger

import (
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/synnergy_network/blockchain/assets"
    "github.com/synnergy_network/blockchain/payments"
    "github.com/synnergy_network/blockchain/transactions"
)

// Ledger struct represents the ledger for storing and managing tokens and agreements
type Ledger struct {
    sync.Mutex
    tokens        map[string]interface{}
    agreements    map[string]assets.RentalAgreement
    properties    map[string]assets.PropertyMetadata
    payments      map[string][]payments.PaymentRecord
    transactions  map[string]transactions.TransactionRecord
    owners        map[string]string
}

// NewLedger constructor
func NewLedger() *Ledger {
    return &Ledger{
        tokens:        make(map[string]interface{}),
        agreements:    make(map[string]assets.RentalAgreement),
        properties:    make(map[string]assets.PropertyMetadata),
        payments:      make(map[string][]payments.PaymentRecord),
        transactions:  make(map[string]transactions.TransactionRecord),
        owners:        make(map[string]string),
    }
}

// StoreToken stores a new token in the ledger
func (l *Ledger) StoreToken(tokenID string, token interface{}) error {
    l.Lock()
    defer l.Unlock()

    if _, exists := l.tokens[tokenID]; exists {
        return fmt.Errorf("token with ID %s already exists", tokenID)
    }

    l.tokens[tokenID] = token
    return nil
}

// GetToken retrieves a token from the ledger by its ID
func (l *Ledger) GetToken(tokenID string) (interface{}, error) {
    l.Lock()
    defer l.Unlock()

    token, exists := l.tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("token with ID %s not found", tokenID)
    }

    return token, nil
}

// StoreAgreement stores a rental agreement in the ledger
func (l *Ledger) StoreAgreement(tokenID string, agreement assets.RentalAgreement) error {
    l.Lock()
    defer l.Unlock()

    if _, exists := l.agreements[tokenID]; exists {
        return fmt.Errorf("agreement with token ID %s already exists", tokenID)
    }

    l.agreements[tokenID] = agreement
    return nil
}

// GetAgreement retrieves a rental agreement from the ledger by its token ID
func (l *Ledger) GetAgreement(tokenID string) (assets.RentalAgreement, error) {
    l.Lock()
    defer l.Unlock()

    agreement, exists := l.agreements[tokenID]
    if !exists {
        return assets.RentalAgreement{}, fmt.Errorf("agreement with token ID %s not found", tokenID)
    }

    return agreement, nil
}

// UpdateAgreement updates an existing rental agreement in the ledger
func (l *Ledger) UpdateAgreement(tokenID string, agreement assets.RentalAgreement) error {
    l.Lock()
    defer l.Unlock()

    if _, exists := l.agreements[tokenID]; !exists {
        return fmt.Errorf("agreement with token ID %s not found", tokenID)
    }

    l.agreements[tokenID] = agreement
    return nil
}

// StoreProperty stores property metadata in the ledger
func (l *Ledger) StoreProperty(propertyID string, property assets.PropertyMetadata) error {
    l.Lock()
    defer l.Unlock()

    if _, exists := l.properties[propertyID]; exists {
        return fmt.Errorf("property with ID %s already exists", propertyID)
    }

    l.properties[propertyID] = property
    return nil
}

// GetProperty retrieves property metadata from the ledger by its ID
func (l *Ledger) GetProperty(propertyID string) (assets.PropertyMetadata, error) {
    l.Lock()
    defer l.Unlock()

    property, exists := l.properties[propertyID]
    if !exists {
        return assets.PropertyMetadata{}, fmt.Errorf("property with ID %s not found", propertyID)
    }

    return property, nil
}

// UpdateProperty updates existing property metadata in the ledger
func (l *Ledger) UpdateProperty(propertyID string, property assets.PropertyMetadata) error {
    l.Lock()
    defer l.Unlock()

    if _, exists := l.properties[propertyID]; !exists {
        return fmt.Errorf("property with ID %s not found", propertyID)
    }

    l.properties[propertyID] = property
    return nil
}

// DeleteProperty removes a property from the ledger
func (l *Ledger) DeleteProperty(propertyID string) error {
    l.Lock()
    defer l.Unlock()

    if _, exists := l.properties[propertyID]; !exists {
        return fmt.Errorf("property with ID %s not found", propertyID)
    }

    delete(l.properties, propertyID)
    return nil
}

// StoreContract stores a smart contract in the ledger
func (l *Ledger) StoreContract(tokenID string, contract interface{}) error {
    l.Lock()
    defer l.Unlock()

    if _, exists := l.tokens[tokenID]; exists {
        return fmt.Errorf("contract with token ID %s already exists", tokenID)
    }

    l.tokens[tokenID] = contract
    return nil
}

// StorePayment records a payment in the ledger
func (l *Ledger) StorePayment(tokenID string, payment payments.PaymentRecord) error {
    l.Lock()
    defer l.Unlock()

    l.payments[tokenID] = append(l.payments[tokenID], payment)
    return nil
}

// GetPaymentHistory retrieves the payment history for a given token ID
func (l *Ledger) GetPaymentHistory(tokenID string) ([]payments.PaymentRecord, error) {
    l.Lock()
    defer l.Unlock()

    paymentHistory, exists := l.payments[tokenID]
    if !exists {
        return nil, fmt.Errorf("no payment history found for token ID %s", tokenID)
    }

    return paymentHistory, nil
}

// LogTransaction logs a transaction in the ledger
func (l *Ledger) LogTransaction(transaction transactions.TransactionRecord) error {
    l.Lock()
    defer l.Unlock()

    l.transactions[transaction.TransactionID] = transaction
    return nil
}

// ValidateTransaction validates a transaction in the ledger
func (l *Ledger) ValidateTransaction(transactionID string) error {
    l.Lock()
    defer l.Unlock()

    transaction, exists := l.transactions[transactionID]
    if !exists {
        return fmt.Errorf("transaction with ID %s not found", transactionID)
    }

    // Implement transaction validation logic here
    // For example, verify signatures, check for double-spending, etc.
    if transaction.Status != "pending" {
        return fmt.Errorf("transaction with ID %s is not pending", transactionID)
    }

    transaction.Status = "validated"
    l.transactions[transactionID] = transaction

    return nil
}

// MintToken mints a new token and stores it in the ledger
func (l *Ledger) MintToken(tokenID string) error {
    l.Lock()
    defer l.Unlock()

    if _, exists := l.tokens[tokenID]; exists {
        return fmt.Errorf("token with ID %s already exists", tokenID)
    }

    l.tokens[tokenID] = struct{}{} // Representing a generic token
    return nil
}

// BurnToken burns an existing token in the ledger
func (l *Ledger) BurnToken(tokenID string) error {
    l.Lock()
    defer l.Unlock()

    if _, exists := l.tokens[tokenID]; !exists {
        return fmt.Errorf("token with ID %s not found", tokenID)
    }

    delete(l.tokens, tokenID)
    return nil
}

// UpdateOwner updates the ownership of a property in the ledger
func (l *Ledger) UpdateOwner(propertyID, newOwner string) error {
    l.Lock()
    defer l.Unlock()

    l.owners[propertyID] = newOwner
    return nil
}

// GetOwner retrieves the owner of a property from the ledger
func (l *Ledger) GetOwner(propertyID string) (string, error) {
    l.Lock()
    defer l.Unlock()

    owner, exists := l.owners[propertyID]
    if !exists {
        return "", fmt.Errorf("owner for property ID %s not found", propertyID)
    }

    return owner, nil
}
