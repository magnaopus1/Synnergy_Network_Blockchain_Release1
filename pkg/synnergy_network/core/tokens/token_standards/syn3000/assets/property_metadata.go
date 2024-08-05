package assets

import (
    "errors"
    "fmt"
    "time"

    "github.com/synnergy_network/blockchain/ledger"
    "github.com/synnergy_network/blockchain/security"
    "github.com/synnergy_network/blockchain/storage"
)

// PropertyMetadata contains detailed information about each property
type PropertyMetadata struct {
    PropertyID       string
    Address          string
    Owner            string
    Description      string
    Bedrooms         int
    Bathrooms        int
    SquareFootage    int
    AvailabilityStatus bool
    RentalYield      float64
    LastUpdateDate   time.Time
}

// PropertyMetadataManager handles the management of property metadata
type PropertyMetadataManager struct {
    Ledger   ledger.Ledger
    Security security.Security
    Storage  storage.Storage
}

// NewPropertyMetadataManager constructor
func NewPropertyMetadataManager(ledger ledger.Ledger, security security.Security, storage storage.Storage) *PropertyMetadataManager {
    return &PropertyMetadataManager{
        Ledger:   ledger,
        Security: security,
        Storage:  storage,
    }
}

// AddProperty adds a new property to the blockchain
func (pmm *PropertyMetadataManager) AddProperty(property PropertyMetadata) error {
    // Validate property details
    if err := pmm.validateProperty(property); err != nil {
        return err
    }

    // Encrypt sensitive data
    property.Owner = pmm.Security.EncryptData(property.Owner)

    // Store property in ledger
    if err := pmm.Ledger.StoreProperty(property.PropertyID, property); err != nil {
        return err
    }

    // Update storage with property metadata
    if err := pmm.Storage.SaveProperty(property.PropertyID, property); err != nil {
        return err
    }

    return nil
}

// validateProperty ensures the property metadata is valid
func (pmm *PropertyMetadataManager) validateProperty(property PropertyMetadata) error {
    if property.PropertyID == "" || property.Address == "" || property.Owner == "" {
        return errors.New("invalid property: missing required fields")
    }
    if property.Bedrooms <= 0 || property.Bathrooms <= 0 || property.SquareFootage <= 0 {
        return errors.New("invalid property: invalid physical attributes")
    }
    return nil
}

// UpdateProperty updates the metadata of an existing property
func (pmm *PropertyMetadataManager) UpdateProperty(property PropertyMetadata) error {
    // Validate property details
    if err := pmm.validateProperty(property); err != nil {
        return err
    }

    // Encrypt sensitive data
    property.Owner = pmm.Security.EncryptData(property.Owner)
    property.LastUpdateDate = time.Now()

    // Update property in ledger
    if err := pmm.Ledger.UpdateProperty(property.PropertyID, property); err != nil {
        return err
    }

    // Update storage with property metadata
    if err := pmm.Storage.SaveProperty(property.PropertyID, property); err != nil {
        return err
    }

    return nil
}

// GetProperty retrieves the metadata of a property by its ID
func (pmm *PropertyMetadataManager) GetProperty(propertyID string) (PropertyMetadata, error) {
    // Retrieve property from storage
    property, err := pmm.Storage.GetProperty(propertyID)
    if err != nil {
        return PropertyMetadata{}, fmt.Errorf("error retrieving property: %v", err)
    }

    // Decrypt sensitive data
    property.Owner = pmm.Security.DecryptData(property.Owner)

    return property, nil
}

// DeleteProperty removes a property from the blockchain
func (pmm *PropertyMetadataManager) DeleteProperty(propertyID string) error {
    // Remove property from ledger
    if err := pmm.Ledger.DeleteProperty(propertyID); err != nil {
        return err
    }

    // Remove property from storage
    if err := pmm.Storage.DeleteProperty(propertyID); err != nil {
        return err
    }

    return nil
}

// TrackRentalYield calculates and tracks the rental yield of a property
func (pmm *PropertyMetadataManager) TrackRentalYield(propertyID string) (float64, error) {
    // Retrieve property from storage
    property, err := pmm.Storage.GetProperty(propertyID)
    if err != nil {
        return 0, fmt.Errorf("error retrieving property: %v", err)
    }

    // Assuming rental yield is calculated based on some business logic
    // Here, for example, we calculate it based on a fixed percentage of the square footage
    rentalYield := float64(property.SquareFootage) * 0.1

    // Update rental yield in property metadata
    property.RentalYield = rentalYield
    property.LastUpdateDate = time.Now()

    // Update storage with property metadata
    if err := pmm.Storage.SaveProperty(property.PropertyID, property); err != nil {
        return 0, err
    }

    return rentalYield, nil
}

// EncryptPropertyData encrypts sensitive property data before storing it
func (pmm *PropertyMetadataManager) EncryptPropertyData(owner string) (string, error) {
    encryptedData, err := pmm.Security.EncryptData(owner)
    if err != nil {
        return "", fmt.Errorf("error encrypting data: %v", err)
    }
    return encryptedData, nil
}

// DecryptPropertyData decrypts sensitive property data for verification purposes
func (pmm *PropertyMetadataManager) DecryptPropertyData(encryptedData string) (string, error) {
    decryptedData, err := pmm.Security.DecryptData(encryptedData)
    if err != nil {
        return "", fmt.Errorf("error decrypting data: %v", err)
    }
    return decryptedData, nil
}
