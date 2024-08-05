package transactions

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/storage"
)

// PriceAdjustment represents the mechanism for adjusting the price of SYN1967 tokens.
type PriceAdjustment struct {
	TokenID     string
	NewPrice    float64
	AdjustmentTime time.Time
}

// NewPriceAdjustment creates a new price adjustment.
func NewPriceAdjustment(tokenID string, newPrice float64) (*PriceAdjustment, error) {
	if tokenID == "" {
		return nil, errors.New("token ID cannot be empty")
	}
	if newPrice <= 0 {
		return nil, errors.New("new price must be positive")
	}
	return &PriceAdjustment{
		TokenID:        tokenID,
		NewPrice:       newPrice,
		AdjustmentTime: time.Now(),
	}, nil
}

// ValidateAdjustment validates the price adjustment.
func (pa *PriceAdjustment) ValidateAdjustment() error {
	// Validate the token existence
	token, err := storage.GetTokenByID(pa.TokenID)
	if err != nil {
		return errors.New("token not found")
	}

	// Ensure the new price is different from the current price
	if token.Price == pa.NewPrice {
		return errors.New("new price must be different from the current price")
	}

	return nil
}

// ExecuteAdjustment executes the price adjustment.
func (pa *PriceAdjustment) ExecuteAdjustment() error {
	if err := pa.ValidateAdjustment(); err != nil {
		return err
	}

	// Update the token price
	token, err := storage.GetTokenByID(pa.TokenID)
	if err != nil {
		return err
	}
	token.Price = pa.NewPrice

	// Update storage
	err = storage.UpdateToken(token)
	if err != nil {
		return err
	}

	// Log the price adjustment
	priceLog := assets.PriceLog{
		TokenID:        pa.TokenID,
		OldPrice:       token.Price,
		NewPrice:       pa.NewPrice,
		AdjustmentTime: pa.AdjustmentTime,
	}
	err = assets.LogPriceAdjustment(priceLog)
	if err != nil {
		return err
	}

	return nil
}

// Example usage of price adjustment.
func ExamplePriceAdjustment() {
	tokenID := "token123"
	newPrice := 75.0

	adjustment, _ := NewPriceAdjustment(tokenID, newPrice)
	err := adjustment.ExecuteAdjustment()
	if err != nil {
		fmt.Printf("Price adjustment failed: %s\n", err)
	} else {
		fmt.Println("Price adjustment successful")
	}
}
