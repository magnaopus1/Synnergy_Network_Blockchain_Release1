package syn4300

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

// EnergyToken represents assets related to energy such as RECs or carbon credits.
type EnergyToken struct {
    TokenID      string    `json:"tokenId"`
    AssetType    string    `json:"assetType"`    // Type of asset (e.g., REC, carbon credit)
    Owner        string    `json:"owner"`        // Identity of the token owner
    IssuanceDate time.Time `json:"issuanceDate"`
    Quantity     float64   `json:"quantity"`     // Amount of energy or credits represented
    ValidUntil   time.Time `json:"validUntil"`   // Expiry date of the token
    Status       string    `json:"status"`       // Current status (active, traded, retired)
    Location     string    `json:"location"`     // Geographic location of the asset
    Certification string   `json:"certification"`// Certification details if applicable
}

// EnergyRegistry manages all energy tokens.
type EnergyRegistry struct {
    Tokens map[string]*EnergyToken
    mutex  sync.Mutex
}

// NewEnergyRegistry initializes a new registry for managing energy tokens.
func NewEnergyRegistry() *EnergyRegistry {
    return &EnergyRegistry{
        Tokens: make(map[string]*EnergyToken),
    }
}

// GenerateTokenID creates a secure, unique token ID.
func GenerateTokenID() (string, error) {
    b := make([]byte, 16) // 128-bit
    _, err := rand.Read(b)
    if err != nil {
        return "", fmt.Errorf("error generating token ID: %v", err)
    }
    return hex.EncodeToString(b), nil
}

// CreateEnergyToken issues a new energy token for a specified asset.
func (r *EnergyRegistry) CreateEnergyToken(assetType, owner, location, certification string, quantity float64, validUntil time.Time) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    tokenID, err := GenerateTokenID()
    if err != nil {
        return "", err
    }

    energyToken := &EnergyToken{
        TokenID:      tokenID,
        AssetType:    assetType,
        Owner:        owner,
        IssuanceDate: time.Now(),
        Quantity:     quantity,
        ValidUntil:   validUntil,
        Status:       "active",
        Location:     location,
        Certification: certification,
    }

    r.Tokens[tokenID] = energyToken
    return tokenID, nil
}

// UpdateEnergyTokenStatus updates the status of an energy token (e.g., traded, retired).
func (r *EnergyRegistry) UpdateEnergyTokenStatus(tokenID, status string) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("energy token not found")
    }

    token.Status = status
    return nil
}

// GetEnergyTokenDetails retrieves details for a specific energy token.
func (r *EnergyRegistry) GetEnergyTokenDetails(tokenID string) (*EnergyToken, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("energy token not found: %s", tokenID)
    }

    return token, nil
}
