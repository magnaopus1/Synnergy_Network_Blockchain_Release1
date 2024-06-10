package syn2400

import (
	"errors"
	"fmt"
	"time"
)

// DataToken represents a tokenized dataset or data rights within the marketplace.
type DataToken struct {
	TokenID      string    `json:"tokenId"`      // Unique identifier for the token
	Owner        string    `json:"owner"`        // Owner's identifier
	DataHash     string    `json:"dataHash"`     // Hash of the data for integrity validation
	Description  string    `json:"description"`  // Description of the data
	AccessRights string    `json:"accessRights"` // Defines the level of access (e.g., view, edit, full control)
	CreatedAt    time.Time `json:"createdAt"`    // Date when the token was created
	UpdatedAt    time.Time `json:"updatedAt"`    // Date when the token was last updated
	Price        float64   `json:"price"`        // Price of the data token
	Active       bool      `json:"active"`       // Status to indicate if the token is active and available for trade
	Metadata     map[string]interface{} `json:"metadata"` // Additional metadata to enhance token usability and traceability
}

// DataMarketplaceLedger manages the lifecycle and transactions of data tokens.
type DataMarketplaceLedger struct {
	Tokens map[string]DataToken // Maps Token IDs to DataTokens
}

// NewDataMarketplaceLedger initializes a new ledger for managing data tokens.
func NewDataMarketplaceLedger() *DataMarketplaceLedger {
	return &DataMarketplaceLedger{
		Tokens: make(map[string]DataToken),
	}
}

// CreateToken generates a new data token with initial metadata.
func (dml *DataMarketplaceLedger) CreateToken(owner, dataHash, description, accessRights string, price float64, metadata map[string]interface{}) (*DataToken, error) {
	tokenID := fmt.Sprintf("DT-%s", dataHash) // Generate a unique token ID based on data hash
	if _, exists := dml.Tokens[tokenID]; exists {
		return nil, fmt.Errorf("a token for this data hash already exists")
	}

	newToken := DataToken{
		TokenID:      tokenID,
		Owner:        owner,
		DataHash:     dataHash,
		Description:  description,
		AccessRights: accessRights,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Price:        price,
		Active:       true,
		Metadata:     metadata,
	}
	dml.Tokens[tokenID] = newToken
	return &newToken, nil
}

// UpdateToken updates details of an existing data token, including metadata.
func (dml *DataMarketplaceLedger) UpdateToken(tokenID string, updates map[string]interface{}) error {
	token, exists := dml.Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	// Apply updates to the token
	for key, value := range updates {
		switch key {
		case "description":
			token.Description = value.(string)
		case "price":
			token.Price = value.(float64)
		case "active":
			token.Active = value.(bool)
		default:
			token.Metadata[key] = value
		}
	}
	token.UpdatedAt = time.Now()
	dml.Tokens[tokenID] = token
	return nil
}

// TransferOwnership changes the ownership of a data token.
func (dml *DataMarketplaceLedger) TransferOwnership(tokenID, newOwner string) error {
	token, exists := dml.Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	token.Owner = newOwner
	token.UpdatedAt = time.Now()
	dml.Tokens[tokenID] = token
	return nil
}

// GetToken retrieves a data token by its ID.
func (dml *DataMarketplaceLedger) GetToken(tokenID string) (DataToken, error) {
	token, exists := dml.Tokens[tokenID]
	if !exists {
		return DataToken{}, errors.New("token not found")
	}
	return token, nil
}

// DeactivateToken disables a token, preventing it from being traded or used.
func (dml *DataMarketplaceLedger) DeactivateToken(tokenID string) error {
	token, exists := dml.Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	token.Active = false
	token.UpdatedAt = time.Now()
	dml.Tokens[tokenID] = token
	return nil
}
