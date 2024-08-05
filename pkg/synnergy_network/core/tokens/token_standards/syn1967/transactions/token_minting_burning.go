package transactions

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/storage"
)

// MintingRequest represents the details required for minting new SYN1967 tokens.
type MintingRequest struct {
	TokenID      string
	Amount       float64
	CommodityID  string
	CreationTime time.Time
}

// BurningRequest represents the details required for burning existing SYN1967 tokens.
type BurningRequest struct {
	TokenID      string
	Amount       float64
	CommodityID  string
	DestructionTime time.Time
}

// NewMintingRequest creates a new minting request.
func NewMintingRequest(tokenID string, amount float64, commodityID string) (*MintingRequest, error) {
	if tokenID == "" || commodityID == "" {
		return nil, errors.New("token ID and commodity ID cannot be empty")
	}
	if amount <= 0 {
		return nil, errors.New("amount must be positive")
	}
	return &MintingRequest{
		TokenID:      tokenID,
		Amount:       amount,
		CommodityID:  commodityID,
		CreationTime: time.Now(),
	}, nil
}

// NewBurningRequest creates a new burning request.
func NewBurningRequest(tokenID string, amount float64, commodityID string) (*BurningRequest, error) {
	if tokenID == "" || commodityID == "" {
		return nil, errors.New("token ID and commodity ID cannot be empty")
	}
	if amount <= 0 {
		return nil, errors.New("amount must be positive")
	}
	return &BurningRequest{
		TokenID:         tokenID,
		Amount:          amount,
		CommodityID:     commodityID,
		DestructionTime: time.Now(),
	}, nil
}

// ValidateMinting validates the minting request.
func (mr *MintingRequest) ValidateMinting() error {
	// Validate the commodity existence
	commodity, err := storage.GetCommodityByID(mr.CommodityID)
	if err != nil {
		return errors.New("commodity not found")
	}

	// Ensure there is enough commodity to back the tokens
	if commodity.AvailableAmount < mr.Amount {
		return errors.New("insufficient commodity amount")
	}

	return nil
}

// ExecuteMinting executes the minting of new tokens.
func (mr *MintingRequest) ExecuteMinting() error {
	if err := mr.ValidateMinting(); err != nil {
		return err
	}

	// Create the new token
	newToken := assets.Token{
		ID:          mr.TokenID,
		CommodityID: mr.CommodityID,
		Amount:      mr.Amount,
		CreationTime:  mr.CreationTime,
	}

	// Update storage with the new token
	err := storage.AddToken(newToken)
	if err != nil {
		return err
	}

	// Update commodity amount
	commodity, _ := storage.GetCommodityByID(mr.CommodityID)
	commodity.AvailableAmount -= mr.Amount
	err = storage.UpdateCommodity(commodity)
	if err != nil {
		return err
	}

	// Log the minting event
	mintingLog := assets.EventLog{
		TokenID:     mr.TokenID,
		CommodityID: mr.CommodityID,
		Amount:      mr.Amount,
		EventType:   "minting",
		EventTime:   mr.CreationTime,
	}
	err = assets.LogEvent(mintingLog)
	if err != nil {
		return err
	}

	return nil
}

// ValidateBurning validates the burning request.
func (br *BurningRequest) ValidateBurning() error {
	// Validate the token existence
	token, err := storage.GetTokenByID(br.TokenID)
	if err != nil {
		return errors.New("token not found")
	}

	// Ensure there are enough tokens to burn
	if token.Amount < br.Amount {
		return errors.New("insufficient token amount")
	}

	return nil
}

// ExecuteBurning executes the burning of existing tokens.
func (br *BurningRequest) ExecuteBurning() error {
	if err := br.ValidateBurning(); err != nil {
		return err
	}

	// Update token amount
	token, _ := storage.GetTokenByID(br.TokenID)
	token.Amount -= br.Amount

	// If token amount is zero, remove the token
	if token.Amount == 0 {
		err := storage.DeleteToken(br.TokenID)
		if err != nil {
			return err
		}
	} else {
		err := storage.UpdateToken(token)
		if err != nil {
			return err
		}
	}

	// Update commodity amount
	commodity, _ := storage.GetCommodityByID(br.CommodityID)
	commodity.AvailableAmount += br.Amount
	err := storage.UpdateCommodity(commodity)
	if err != nil {
		return err
	}

	// Log the burning event
	burningLog := assets.EventLog{
		TokenID:     br.TokenID,
		CommodityID: br.CommodityID,
		Amount:      br.Amount,
		EventType:   "burning",
		EventTime:   br.DestructionTime,
	}
	err = assets.LogEvent(burningLog)
	if err != nil {
		return err
	}

	return nil
}

// Example usage of minting and burning.
func ExampleTokenMintingBurning() {
	tokenID := "token123"
	commodityID := "commodity456"
	amount := 100.0

	// Minting example
	mintingRequest, _ := NewMintingRequest(tokenID, amount, commodityID)
	err := mintingRequest.ExecuteMinting()
	if err != nil {
		fmt.Printf("Minting failed: %s\n", err)
	} else {
		fmt.Println("Minting successful")
	}

	// Burning example
	burningRequest, _ := NewBurningRequest(tokenID, amount, commodityID)
	err = burningRequest.ExecuteBurning()
	if err != nil {
		fmt.Printf("Burning failed: %s\n", err)
	} else {
		fmt.Println("Burning successful")
	}
}
