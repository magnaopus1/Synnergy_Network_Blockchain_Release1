package assets

import (
    "errors"
    "fmt"
    "time"

    "github.com/synnergy_network/blockchain/ledger"
    "github.com/synnergy_network/blockchain/security"
    "github.com/synnergy_network/blockchain/storage"
)

type OwnershipVerification struct {
    Ledger   ledger.Ledger
    Security security.Security
    Storage  storage.Storage
}

// NewOwnershipVerification constructor
func NewOwnershipVerification(ledger ledger.Ledger, security security.Security, storage storage.Storage) *OwnershipVerification {
    return &OwnershipVerification{
        Ledger:   ledger,
        Security: security,
        Storage:  storage,
    }
}

// VerifyOwnership verifies the ownership of a given property ID and returns the owner's information
func (ov *OwnershipVerification) VerifyOwnership(propertyID string) (string, error) {
    property, err := ov.Storage.GetProperty(propertyID)
    if err != nil {
        return "", fmt.Errorf("error retrieving property: %v", err)
    }

    owner, err := ov.Ledger.GetOwner(propertyID)
    if err != nil {
        return "", fmt.Errorf("error retrieving owner: %v", err)
    }

    return owner, nil
}

// ValidateTransfer checks if the transfer of ownership is valid based on current ownership and other constraints
func (ov *OwnershipVerification) ValidateTransfer(propertyID, newOwner string) error {
    currentOwner, err := ov.VerifyOwnership(propertyID)
    if err != nil {
        return err
    }

    if currentOwner == newOwner {
        return errors.New("new owner is the same as the current owner")
    }

    return nil
}

// TransferOwnership transfers the ownership of a property to a new owner after validation
func (ov *OwnershipVerification) TransferOwnership(propertyID, newOwner string) error {
    if err := ov.ValidateTransfer(propertyID, newOwner); err != nil {
        return err
    }

    property, err := ov.Storage.GetProperty(propertyID)
    if err != nil {
        return fmt.Errorf("error retrieving property: %v", err)
    }

    property.Owner = newOwner
    if err := ov.Storage.SaveProperty(propertyID, property); err != nil {
        return fmt.Errorf("error saving property: %v", err)
    }

    if err := ov.Ledger.UpdateOwner(propertyID, newOwner); err != nil {
        return fmt.Errorf("error updating owner in ledger: %v", err)
    }

    return nil
}

// EncryptOwnershipData encrypts sensitive ownership data before storing it
func (ov *OwnershipVerification) EncryptOwnershipData(owner string) (string, error) {
    encryptedData, err := ov.Security.EncryptData(owner)
    if err != nil {
        return "", fmt.Errorf("error encrypting data: %v", err)
    }
    return encryptedData, nil
}

// DecryptOwnershipData decrypts sensitive ownership data for verification purposes
func (ov *OwnershipVerification) DecryptOwnershipData(encryptedData string) (string, error) {
    decryptedData, err := ov.Security.DecryptData(encryptedData)
    if err != nil {
        return "", fmt.Errorf("error decrypting data: %v", err)
    }
    return decryptedData, nil
}

// LogOwnershipChange logs changes in ownership to maintain an immutable record
func (ov *OwnershipVerification) LogOwnershipChange(propertyID, oldOwner, newOwner string) error {
    logEntry := fmt.Sprintf("Ownership change for property %s: from %s to %s at %s", propertyID, oldOwner, newOwner, time.Now().Format(time.RFC3339))
    if err := ov.Storage.LogEvent(logEntry); err != nil {
        return fmt.Errorf("error logging ownership change: %v", err)
    }
    return nil
}
