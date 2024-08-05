package management

import (
	"fmt"
	"sync"
	"time"
)

// Royalty represents the royalty details associated with a SYN721 token
type Royalty struct {
	Creator   string
	Percentage float64 // Royalty percentage on secondary sales
}

// RoyaltyChange represents a change in the royalty details of a SYN721 token
type RoyaltyChange struct {
	Timestamp  time.Time
	OldRoyalty Royalty
	NewRoyalty Royalty
}

// RoyaltyManager manages the royalties associated with SYN721 tokens
type RoyaltyManager struct {
	royalties           map[string]Royalty
	royaltyHistories    map[string][]RoyaltyChange
	mutex               sync.Mutex
}

// NewRoyaltyManager initializes a new RoyaltyManager
func NewRoyaltyManager() *RoyaltyManager {
	return &RoyaltyManager{
		royalties:        make(map[string]Royalty),
		royaltyHistories: make(map[string][]RoyaltyChange),
	}
}

// SetTokenRoyalty sets the royalty details for a new token
func (rm *RoyaltyManager) SetTokenRoyalty(tokenID, creator string, percentage float64) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if _, exists := rm.royalties[tokenID]; exists {
		return fmt.Errorf("royalty for token ID %s already exists", tokenID)
	}

	if percentage < 0 || percentage > 100 {
		return fmt.Errorf("invalid royalty percentage: %f", percentage)
	}

	royalty := Royalty{
		Creator:   creator,
		Percentage: percentage,
	}

	rm.royalties[tokenID] = royalty
	rm.royaltyHistories[tokenID] = []RoyaltyChange{
		{
			Timestamp:  time.Now(),
			OldRoyalty: Royalty{},
			NewRoyalty: royalty,
		},
	}

	return nil
}

// UpdateTokenRoyalty updates the royalty details of an existing token
func (rm *RoyaltyManager) UpdateTokenRoyalty(tokenID, creator string, percentage float64) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	oldRoyalty, exists := rm.royalties[tokenID]
	if !exists {
		return fmt.Errorf("royalty for token ID %s not found", tokenID)
	}

	if percentage < 0 || percentage > 100 {
		return fmt.Errorf("invalid royalty percentage: %f", percentage)
	}

	newRoyalty := Royalty{
		Creator:   creator,
		Percentage: percentage,
	}

	rm.royalties[tokenID] = newRoyalty
	rm.royaltyHistories[tokenID] = append(rm.royaltyHistories[tokenID], RoyaltyChange{
		Timestamp:  time.Now(),
		OldRoyalty: oldRoyalty,
		NewRoyalty: newRoyalty,
	})

	return nil
}

// GetTokenRoyalty retrieves the royalty details of a token by its ID
func (rm *RoyaltyManager) GetTokenRoyalty(tokenID string) (Royalty, error) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	royalty, exists := rm.royalties[tokenID]
	if !exists {
		return Royalty{}, fmt.Errorf("royalty for token ID %s not found", tokenID)
	}

	return royalty, nil
}

// GetRoyaltyHistory retrieves the royalty history of a token
func (rm *RoyaltyManager) GetRoyaltyHistory(tokenID string) ([]RoyaltyChange, error) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	history, exists := rm.royaltyHistories[tokenID]
	if !exists {
		return nil, fmt.Errorf("royalty history for token ID %s not found", tokenID)
	}

	return history, nil
}

// DeleteTokenRoyalty deletes the royalty details of a token
func (rm *RoyaltyManager) DeleteTokenRoyalty(tokenID string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if _, exists := rm.royalties[tokenID]; !exists {
		return fmt.Errorf("royalty for token ID %s not found", tokenID)
	}

	delete(rm.royalties, tokenID)
	delete(rm.royaltyHistories, tokenID)

	return nil
}

// CalculateRoyalty calculates the royalty amount for a given sale price
func (rm *RoyaltyManager) CalculateRoyalty(tokenID string, salePrice float64) (float64, error) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	royalty, exists := rm.royalties[tokenID]
	if !exists {
		return 0, fmt.Errorf("royalty for token ID %s not found", tokenID)
	}

	royaltyAmount := (royalty.Percentage / 100) * salePrice
	return royaltyAmount, nil
}

// TransferRoyalty transfers the royalty amount to the creator on a secondary sale
func (rm *RoyaltyManager) TransferRoyalty(tokenID string, salePrice float64) (float64, error) {
	royaltyAmount, err := rm.CalculateRoyalty(tokenID, salePrice)
	if err != nil {
		return 0, err
	}

	// Placeholder for actual transfer logic to the creator's account
	// transferToCreator(royalties[tokenID].Creator, royaltyAmount)

	return royaltyAmount, nil
}

func transferToCreator(creator string, amount float64) {
	// Implement the logic to transfer the amount to the creator's account
	// This is a placeholder function to illustrate the flow
}
