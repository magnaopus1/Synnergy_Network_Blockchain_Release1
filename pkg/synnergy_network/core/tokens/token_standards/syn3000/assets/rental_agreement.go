package assets

import (
    "errors"
    "fmt"
    "time"

    "github.com/synnergy_network/blockchain/ledger"
    "github.com/synnergy_network/blockchain/security"
    "github.com/synnergy_network/blockchain/storage"
    "github.com/synnergy_network/blockchain/transactions"
)

// RentalAgreement struct contains detailed information about each rental agreement
type RentalAgreement struct {
    TokenID         string
    PropertyID      string
    TenantInfo      Tenant
    LeaseStartDate  time.Time
    LeaseEndDate    time.Time
    MonthlyRent     float64
    Deposit         float64
    IssuedDate      time.Time
    ActiveStatus    bool
    LastUpdateDate  time.Time
    RentalMetadata  RentalMetadata
}

// Tenant struct contains tenant information
type Tenant struct {
    TenantID    string
    Name        string
    ContactInfo string
}

// RentalAgreementManager handles the management of rental agreements
type RentalAgreementManager struct {
    Ledger     ledger.Ledger
    Security   security.Security
    Storage    storage.Storage
    Transactions transactions.Transactions
}

// NewRentalAgreementManager constructor
func NewRentalAgreementManager(ledger ledger.Ledger, security security.Security, storage storage.Storage, transactions transactions.Transactions) *RentalAgreementManager {
    return &RentalAgreementManager{
        Ledger:       ledger,
        Security:     security,
        Storage:      storage,
        Transactions: transactions,
    }
}

// CreateRentalAgreement creates a new rental agreement
func (ram *RentalAgreementManager) CreateRentalAgreement(agreement RentalAgreement) error {
    // Validate rental agreement
    if err := ram.validateRentalAgreement(agreement); err != nil {
        return err
    }

    // Encrypt sensitive data
    agreement.TenantInfo = ram.Security.EncryptTenantInfo(agreement.TenantInfo)

    // Store rental agreement in ledger
    if err := ram.Ledger.StoreAgreement(agreement.TokenID, agreement); err != nil {
        return err
    }

    // Update storage with rental metadata
    if err := ram.Storage.SaveRentalMetadata(agreement.TokenID, agreement.RentalMetadata); err != nil {
        return err
    }

    return nil
}

// validateRentalAgreement ensures the rental agreement is valid
func (ram *RentalAgreementManager) validateRentalAgreement(agreement RentalAgreement) error {
    if agreement.TokenID == "" || agreement.PropertyID == "" || agreement.TenantInfo.TenantID == "" {
        return errors.New("invalid rental agreement: missing required fields")
    }
    if agreement.LeaseStartDate.After(agreement.LeaseEndDate) {
        return errors.New("invalid rental agreement: lease start date is after lease end date")
    }
    if agreement.MonthlyRent <= 0 {
        return errors.New("invalid rental agreement: monthly rent must be positive")
    }
    return nil
}

// TransferRentalAgreement transfers a rental agreement to a new tenant
func (ram *RentalAgreementManager) TransferRentalAgreement(tokenID string, newTenant Tenant) error {
    // Retrieve rental agreement
    agreement, err := ram.Ledger.GetAgreement(tokenID)
    if err != nil {
        return err
    }

    // Update tenant information
    agreement.TenantInfo = newTenant
    agreement.LastUpdateDate = time.Now()

    // Encrypt sensitive data
    agreement.TenantInfo = ram.Security.EncryptTenantInfo(agreement.TenantInfo)

    // Update rental agreement in ledger
    if err := ram.Ledger.UpdateAgreement(tokenID, agreement); err != nil {
        return err
    }

    return nil
}

// TerminateRentalAgreement terminates a rental agreement
func (ram *RentalAgreementManager) TerminateRentalAgreement(tokenID string) error {
    // Retrieve rental agreement
    agreement, err := ram.Ledger.GetAgreement(tokenID)
    if err != nil {
        return err
    }

    // Update active status
    agreement.ActiveStatus = false
    agreement.LastUpdateDate = time.Now()

    // Update rental agreement in ledger
    if err := ram.Ledger.UpdateAgreement(tokenID, agreement); err != nil {
        return err
    }

    return nil
}

// GetRentalAgreementDetails retrieves the details of a rental agreement
func (ram *RentalAgreementManager) GetRentalAgreementDetails(tokenID string) (RentalAgreement, error) {
    // Retrieve rental agreement
    agreement, err := ram.Ledger.GetAgreement(tokenID)
    if err != nil {
        return RentalAgreement{}, err
    }

    // Decrypt sensitive data
    agreement.TenantInfo = ram.Security.DecryptTenantInfo(agreement.TenantInfo)

    return agreement, nil
}

// LogRentalTransaction logs a rental transaction to maintain an immutable record
func (ram *RentalAgreementManager) LogRentalTransaction(transaction transactions.TransactionRecord) error {
    // Log transaction in ledger
    if err := ram.Transactions.LogTransaction(transaction); err != nil {
        return fmt.Errorf("error logging rental transaction: %v", err)
    }

    return nil
}

// EncryptTenantInfo encrypts sensitive tenant information before storing it
func (ram *RentalAgreementManager) EncryptTenantInfo(tenant Tenant) Tenant {
    encryptedName, _ := ram.Security.EncryptData(tenant.Name)
    encryptedContactInfo, _ := ram.Security.EncryptData(tenant.ContactInfo)

    return Tenant{
        TenantID:    tenant.TenantID,
        Name:        encryptedName,
        ContactInfo: encryptedContactInfo,
    }
}

// DecryptTenantInfo decrypts sensitive tenant information for verification purposes
func (ram *RentalAgreementManager) DecryptTenantInfo(tenant Tenant) Tenant {
    decryptedName, _ := ram.Security.DecryptData(tenant.Name)
    decryptedContactInfo, _ := ram.Security.DecryptData(tenant.ContactInfo)

    return Tenant{
        TenantID:    tenant.TenantID,
        Name:        decryptedName,
        ContactInfo: decryptedContactInfo,
    }
}
