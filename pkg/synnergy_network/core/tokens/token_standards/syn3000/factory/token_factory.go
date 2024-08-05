package factory

import (
    "errors"
    "fmt"
    "time"

    "github.com/synnergy_network/blockchain/assets"
    "github.com/synnergy_network/blockchain/ledger"
    "github.com/synnergy_network/blockchain/payments"
    "github.com/synnergy_network/blockchain/security"
    "github.com/synnergy_network/blockchain/storage"
    "github.com/synnergy_network/blockchain/transactions"
)

// TokenFactory struct for creating SYN3000 tokens
type TokenFactory struct {
    Ledger          ledger.Ledger
    Security        security.Security
    Storage         storage.Storage
    Payments        payments.Payments
    Transactions    transactions.Transactions
    RentalManager   *assets.RentalAgreementManager
    PropertyManager *assets.PropertyMetadataManager
}

// NewTokenFactory constructor
func NewTokenFactory(ledger ledger.Ledger, security security.Security, storage storage.Storage, payments payments.Payments, transactions transactions.Transactions) *TokenFactory {
    rentalManager := assets.NewRentalAgreementManager(ledger, security, storage, transactions)
    propertyManager := assets.NewPropertyMetadataManager(ledger, security, storage)
    return &TokenFactory{
        Ledger:          ledger,
        Security:        security,
        Storage:         storage,
        Payments:        payments,
        Transactions:    transactions,
        RentalManager:   rentalManager,
        PropertyManager: propertyManager,
    }
}

// CreateRentalToken creates a new rental token
func (tf *TokenFactory) CreateRentalToken(propertyID, tenantID, tenantName, tenantContact string, leaseStartDate, leaseEndDate time.Time, monthlyRent, deposit float64) (string, error) {
    tokenID := tf.generateTokenID()
    issuedDate := time.Now()

    tenant := assets.Tenant{
        TenantID:    tenantID,
        Name:        tenantName,
        ContactInfo: tenantContact,
    }

    rentalAgreement := assets.RentalAgreement{
        TokenID:        tokenID,
        PropertyID:     propertyID,
        TenantInfo:     tenant,
        LeaseStartDate: leaseStartDate,
        LeaseEndDate:   leaseEndDate,
        MonthlyRent:    monthlyRent,
        Deposit:        deposit,
        IssuedDate:     issuedDate,
        ActiveStatus:   true,
        LastUpdateDate: issuedDate,
        RentalMetadata: assets.RentalMetadata{
            PropertyDetails: assets.Property{},
            TransactionHistory: []transactions.TransactionRecord{},
            PaymentHistory: []payments.PaymentRecord{},
        },
    }

    // Add rental agreement to the blockchain
    if err := tf.RentalManager.CreateRentalAgreement(rentalAgreement); err != nil {
        return "", fmt.Errorf("error creating rental agreement: %v", err)
    }

    return tokenID, nil
}

// CreatePropertyToken creates a new property token
func (tf *TokenFactory) CreatePropertyToken(propertyID, address, owner, description string, bedrooms, bathrooms, squareFootage int) error {
    propertyMetadata := assets.PropertyMetadata{
        PropertyID:        propertyID,
        Address:           address,
        Owner:             owner,
        Description:       description,
        Bedrooms:          bedrooms,
        Bathrooms:         bathrooms,
        SquareFootage:     squareFootage,
        AvailabilityStatus: true,
        RentalYield:       0,
        LastUpdateDate:    time.Now(),
    }

    // Add property to the blockchain
    if err := tf.PropertyManager.AddProperty(propertyMetadata); err != nil {
        return fmt.Errorf("error adding property: %v", err)
    }

    return nil
}

// generateTokenID generates a unique token ID
func (tf *TokenFactory) generateTokenID() string {
    return fmt.Sprintf("SYN3000-%d", time.Now().UnixNano())
}

// TransferRentalToken transfers a rental token to a new tenant
func (tf *TokenFactory) TransferRentalToken(tokenID, newTenantID, newTenantName, newTenantContact string) error {
    newTenant := assets.Tenant{
        TenantID:    newTenantID,
        Name:        newTenantName,
        ContactInfo: newTenantContact,
    }

    if err := tf.RentalManager.TransferRentalAgreement(tokenID, newTenant); err != nil {
        return fmt.Errorf("error transferring rental token: %v", err)
    }

    return nil
}

// TerminateRentalToken terminates a rental token
func (tf *TokenFactory) TerminateRentalToken(tokenID string) error {
    if err := tf.RentalManager.TerminateRentalAgreement(tokenID); err != nil {
        return fmt.Errorf("error terminating rental token: %v", err)
    }

    return nil
}

// RecordPayment records a rent payment
func (tf *TokenFactory) RecordPayment(tokenID, tenantID string, amount float64) error {
    paymentRecord := payments.PaymentRecord{
        TokenID:   tokenID,
        TenantID:  tenantID,
        Amount:    amount,
        Timestamp: time.Now(),
    }

    if err := tf.Payments.RecordPayment(paymentRecord); err != nil {
        return fmt.Errorf("error recording payment: %v", err)
    }

    return nil
}

// ValidateTransaction validates a transaction
func (tf *TokenFactory) ValidateTransaction(transactionID string) error {
    if err := tf.Transactions.ValidateTransaction(transactionID); err != nil {
        return fmt.Errorf("error validating transaction: %v", err)
    }

    return nil
}

// MintNewToken mints a new SYN3000 token
func (tf *TokenFactory) MintNewToken() (string, error) {
    tokenID := tf.generateTokenID()
    // Assuming minting logic
    if err := tf.Ledger.MintToken(tokenID); err != nil {
        return "", fmt.Errorf("error minting new token: %v", err)
    }

    return tokenID, nil
}

// BurnToken burns an existing SYN3000 token
func (tf *TokenFactory) BurnToken(tokenID string) error {
    // Assuming burning logic
    if err := tf.Ledger.BurnToken(tokenID); err != nil {
        return fmt.Errorf("error burning token: %v", err)
    }

    return nil
}

// TrackRentalYield tracks the rental yield of a property
func (tf *TokenFactory) TrackRentalYield(propertyID string) (float64, error) {
    yield, err := tf.PropertyManager.TrackRentalYield(propertyID)
    if err != nil {
        return 0, fmt.Errorf("error tracking rental yield: %v", err)
    }

    return yield, nil
}
