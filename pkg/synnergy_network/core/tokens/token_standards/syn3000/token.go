package syn3000

import (
    "fmt"
    "time"
)

// Property represents the details of the physical property being rented.
type Property struct {
    PropertyID   string    `json:"propertyId"`   // Unique identifier for the property
    Address      string    `json:"address"`      // Physical address of the property
    Owner        string    `json:"owner"`        // Owner's identifier
    Description  string    `json:"description"`  // Description of the property
    Bedrooms     int       `json:"bedrooms"`     // Number of bedrooms
    Bathrooms    int       `json:"bathrooms"`    // Number of bathrooms
    SquareFeet   int       `json:"squareFeet"`   // Total square footage of the property
    Available    bool      `json:"available"`    // Availability status for rental
}

// RentalToken represents a tokenized rental agreement.
type RentalToken struct {
    TokenID         string    `json:"tokenId"`         // Unique identifier for the token
    Property        Property  `json:"property"`        // Property details
    Tenant          string    `json:"tenant"`          // Tenant's identifier
    LeaseStartDate  time.Time `json:"leaseStartDate"`  // Start date of the lease
    LeaseEndDate    time.Time `json:"leaseEndDate"`    // End date of the lease
    MonthlyRent     float64   `json:"monthlyRent"`     // Monthly rent price
    Deposit         float64   `json:"deposit"`         // Security deposit amount
    IssuedDate      time.Time `json:"issuedDate"`      // Date when the token was issued
    Active          bool      `json:"active"`          // Status to indicate if the lease is active
    LastUpdated     time.Time `json:"lastUpdated"`     // Last update to the lease conditions
}

// RentalLedger manages the issuance and lifecycle of rental tokens.
type RentalLedger struct {
    Tokens map[string]RentalToken // Maps Token IDs to RentalTokens
}

// NewRentalLedger initializes a new ledger for managing rental tokens.
func NewRentalLedger() *RentalLedger {
    return &RentalLedger{
        Tokens: make(map[string]RentalToken),
    }
}

// IssueToken issues a new rental token when a lease agreement is established.
func (rl *RentalLedger) IssueToken(property Property, tenant string, leaseStartDate, leaseEndDate time.Time, monthlyRent, deposit float64) (*RentalToken, error) {
    tokenID := fmt.Sprintf("RT-%s-%s", property.PropertyID, tenant) // Generate a unique token ID
    if _, exists := rl.Tokens[tokenID]; exists {
        return nil, fmt.Errorf("a rental token with ID %s already exists", tokenID)
    }

    newToken := RentalToken{
        TokenID:        tokenID,
        Property:       property,
        Tenant:         tenant,
        LeaseStartDate: leaseStartDate,
        LeaseEndDate:   leaseEndDate,
        MonthlyRent:    monthlyRent,
        Deposit:        deposit,
        IssuedDate:     time.Now(),
        Active:         true,
        LastUpdated:    time.Now(),
    }

    rl.Tokens[tokenID] = newToken
    return &newToken, nil
}

// UpdateLeaseConditions allows for updating lease terms such as rent and deposit during the lease period.
func (rl *RentalLedger) UpdateLeaseConditions(tokenID string, newRent, newDeposit float64) error {
    token, exists := rl.Tokens[tokenID]
    if !exists {
        return fmt.Errorf("rental token with ID %s not found", tokenID)
    }

    token.MonthlyRent = newRent
    token.Deposit = newDeposit
    token.LastUpdated = time.Now()
    rl.Tokens[tokenID] = token
    return nil
}

// TerminateLease marks the lease as terminated before the end date, effectively deactivating the token.
func (rl *RentalLedger) TerminateLease(tokenID string) error {
    token, exists := rl.Tokens[tokenID]
    if !exists {
        return fmt.Errorf("rental token with ID %s not found", tokenID)
    }

    if !token.Active {
        return fmt.Errorf("lease %s is already inactive", tokenID)
    }

    token.Active = false
    rl.Tokens[tokenID] = token
    return nil
}

// GetToken retrieves a rental token by its ID.
func (rl *RentalLedger) GetToken(tokenID string) (RentalToken, error) {
    token, exists := rl.Tokens[tokenID]
    if !exists {
        return RentalToken{}, fmt.Errorf("rental token with ID %s not found", tokenID)
    }
    return token, nil
}

// ListActiveLeases returns all active rental agreements for a particular property or tenant.
func (rl *RentalLedger) ListActiveLeases(filterBy string, value string) ([]RentalToken, error) {
    var activeTokens []RentalToken
    for _, token := range rl.Tokens {
        if token.Active && ((filterBy == "property" && token.Property.PropertyID == value) || (filterBy == "tenant" && token.Tenant == value)) {
            activeTokens = append(activeTokens, token)
        }
    }
    if len(activeTokens) == 0 {
        return nil, fmt.Errorf("no active leases found for %s %s", filterBy, value)
    }
    return activeTokens, nil
}
