package syn3000

import (
    "errors"
    "fmt"
    "time"

    "github.com/synnergy_network/blockchain/crypto"
    "github.com/synnergy_network/blockchain/ledger"
    "github.com/synnergy_network/blockchain/payments"
    "github.com/synnergy_network/blockchain/security"
    "github.com/synnergy_network/blockchain/storage"
    "github.com/synnergy_network/blockchain/transactions"
)

type SYN3000Token struct {
    TokenID          string
    PropertyID       string
    TenantInfo       Tenant
    LeaseStartDate   time.Time
    LeaseEndDate     time.Time
    MonthlyRent      float64
    Deposit          float64
    IssuedDate       time.Time
    ActiveStatus     bool
    LastUpdateDate   time.Time
    RentalMetadata   RentalMetadata
}

type Tenant struct {
    TenantID   string
    Name       string
    ContactInfo string
}

type RentalMetadata struct {
    PropertyDetails Property
    TransactionHistory []transactions.TransactionRecord
    PaymentHistory      []payments.PaymentRecord
}

type Property struct {
    PropertyID     string
    Address        string
    Owner          string
    Description    string
    Bedrooms       int
    Bathrooms      int
    SquareFootage  int
    AvailabilityStatus bool
}

// SYN3000TokenStandard struct that encapsulates the functionality
type SYN3000TokenStandard struct {
    Ledger     ledger.Ledger
    Storage    storage.Storage
    Security   security.Security
    Payments   payments.Payments
    Transactions transactions.Transactions
}

// NewSYN3000TokenStandard constructor
func NewSYN3000TokenStandard() *SYN3000TokenStandard {
    return &SYN3000TokenStandard{
        Ledger:      ledger.NewLedger(),
        Storage:     storage.NewStorage(),
        Security:    security.NewSecurity(),
        Payments:    payments.NewPayments(),
        Transactions: transactions.NewTransactions(),
    }
}

// CreateRentalToken creates a new rental token
func (syn *SYN3000TokenStandard) CreateRentalToken(token SYN3000Token) error {
    // Validate token
    if err := syn.validateRentalToken(token); err != nil {
        return err
    }

    // Encrypt sensitive data
    token.TenantInfo = syn.Security.EncryptTenantInfo(token.TenantInfo)

    // Store token in ledger
    if err := syn.Ledger.StoreToken(token.TokenID, token); err != nil {
        return err
    }

    // Update storage with rental metadata
    if err := syn.Storage.SaveRentalMetadata(token.TokenID, token.RentalMetadata); err != nil {
        return err
    }

    return nil
}

// validateRentalToken ensures the token is valid
func (syn *SYN3000TokenStandard) validateRentalToken(token SYN3000Token) error {
    if token.TokenID == "" || token.PropertyID == "" || token.TenantInfo.TenantID == "" {
        return errors.New("invalid rental token: missing required fields")
    }
    if token.LeaseStartDate.After(token.LeaseEndDate) {
        return errors.New("invalid rental token: lease start date is after lease end date")
    }
    if token.MonthlyRent <= 0 {
        return errors.New("invalid rental token: monthly rent must be positive")
    }
    return nil
}

// TransferRentalToken transfers a rental token to a new tenant
func (syn *SYN3000TokenStandard) TransferRentalToken(tokenID string, newTenant Tenant) error {
    // Retrieve token
    token, err := syn.Ledger.GetToken(tokenID)
    if err != nil {
        return err
    }

    // Update tenant information
    token.TenantInfo = newTenant
    token.LastUpdateDate = time.Now()

    // Encrypt sensitive data
    token.TenantInfo = syn.Security.EncryptTenantInfo(token.TenantInfo)

    // Update token in ledger
    if err := syn.Ledger.UpdateToken(tokenID, token); err != nil {
        return err
    }

    return nil
}

// AutomateRentPayments sets up automated rent payments using smart contracts
func (syn *SYN3000TokenStandard) AutomateRentPayments(tokenID string) error {
    // Retrieve token
    token, err := syn.Ledger.GetToken(tokenID)
    if err != nil {
        return err
    }

    // Create smart contract for automated rent payments
    contract := payments.NewAutomatedRentPaymentContract(token.TenantInfo.TenantID, token.PropertyID, token.MonthlyRent)
    
    // Store contract in ledger
    if err := syn.Ledger.StoreContract(tokenID, contract); err != nil {
        return err
    }

    return nil
}

// HandleLatePayments processes late rent payments
func (syn *SYN3000TokenStandard) HandleLatePayments(tokenID string) error {
    // Retrieve token
    token, err := syn.Ledger.GetToken(tokenID)
    if err != nil {
        return err
    }

    // Process late payment
    latePaymentHandler := payments.NewLatePaymentHandler(token.TenantInfo.TenantID, token.PropertyID)
    if err := latePaymentHandler.ProcessLatePayment(); err != nil {
        return err
    }

    return nil
}

// TransferPropertyOwnership transfers the ownership of a property
func (syn *SYN3000TokenStandard) TransferPropertyOwnership(propertyID string, newOwner string) error {
    // Retrieve property
    property, err := syn.Storage.GetProperty(propertyID)
    if err != nil {
        return err
    }

    // Update property owner
    property.Owner = newOwner

    // Store updated property
    if err := syn.Storage.SaveProperty(propertyID, property); err != nil {
        return err
    }

    return nil
}

// GetRentalTokenDetails retrieves the details of a rental token
func (syn *SYN3000TokenStandard) GetRentalTokenDetails(tokenID string) (SYN3000Token, error) {
    // Retrieve token
    token, err := syn.Ledger.GetToken(tokenID)
    if err != nil {
        return SYN3000Token{}, err
    }

    // Decrypt sensitive data
    token.TenantInfo = syn.Security.DecryptTenantInfo(token.TenantInfo)

    return token, nil
}

// GetPaymentHistory retrieves the payment history for a rental token
func (syn *SYN3000TokenStandard) GetPaymentHistory(tokenID string) ([]payments.PaymentRecord, error) {
    // Retrieve payment history
    paymentHistory, err := syn.Storage.GetPaymentHistory(tokenID)
    if err != nil {
        return nil, err
    }

    return paymentHistory, nil
}

