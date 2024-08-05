package token_support

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/shopspring/decimal"
)

// Token represents a token with its details
type Token struct {
	Symbol   string
	Name     string
	Decimals int
	Address  common.Address
}

// Listing represents a token listing
type Listing struct {
	Token     Token
	Price     decimal.Decimal
	ListedBy  common.Address
	ListedAt  int64
	ListingID string
}

// AutomatedListingManager manages automated token listings
type AutomatedListingManager struct {
	Tokens   map[string]Token
	Listings map[string]Listing
	Lock     sync.Mutex
}

// NewAutomatedListingManager creates a new AutomatedListingManager instance
func NewAutomatedListingManager() *AutomatedListingManager {
	return &AutomatedListingManager{
		Tokens:   make(map[string]Token),
		Listings: make(map[string]Listing),
	}
}

// AddToken adds a new token to the manager
func (alm *AutomatedListingManager) AddToken(symbol, name string, decimals int, address common.Address) error {
	alm.Lock.Lock()
	defer alm.Lock.Unlock()

	if _, exists := alm.Tokens[symbol]; exists {
		return errors.New("token already exists")
	}

	token := Token{
		Symbol:   symbol,
		Name:     name,
		Decimals: decimals,
		Address:  address,
	}

	alm.Tokens[symbol] = token
	return nil
}

// RemoveToken removes a token from the manager
func (alm *AutomatedListingManager) RemoveToken(symbol string) error {
	alm.Lock.Lock()
	defer alm.Lock.Unlock()

	if _, exists := alm.Tokens[symbol]; !exists {
		return errors.New("token not found")
	}

	delete(alm.Tokens, symbol)
	return nil
}

// ListToken lists a token with the given price
func (alm *AutomatedListingManager) ListToken(symbol string, price decimal.Decimal, listedBy common.Address, listedAt int64) (Listing, error) {
	alm.Lock.Lock()
	defer alm.Lock.Unlock()

	token, exists := alm.Tokens[symbol]
	if !exists {
		return Listing{}, errors.New("token not found")
	}

	listingID, err := generateListingID(symbol, listedBy, listedAt)
	if err != nil {
		return Listing{}, err
	}

	listing := Listing{
		Token:     token,
		Price:     price,
		ListedBy:  listedBy,
		ListedAt:  listedAt,
		ListingID: listingID,
	}

	alm.Listings[listingID] = listing
	return listing, nil
}

// RemoveListing removes a token listing by its ID
func (alm *AutomatedListingManager) RemoveListing(listingID string) error {
	alm.Lock.Lock()
	defer alm.Lock.Unlock()

	if _, exists := alm.Listings[listingID]; !exists {
		return errors.New("listing not found")
	}

	delete(alm.Listings, listingID)
	return nil
}

// GetListing retrieves a token listing by its ID
func (alm *AutomatedListingManager) GetListing(listingID string) (Listing, error) {
	alm.Lock.Lock()
	defer alm.Lock.Unlock()

	listing, exists := alm.Listings[listingID]
	if !exists {
		return Listing{}, errors.New("listing not found")
	}

	return listing, nil
}

// generateListingID generates a unique listing ID
func generateListingID(symbol string, listedBy common.Address, listedAt int64) (string, error) {
	randInt, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s-%s-%d-%d", symbol, listedBy.Hex(), listedAt, randInt)))
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// ListAllTokens lists all tokens managed by the AutomatedListingManager
func (alm *AutomatedListingManager) ListAllTokens() []Token {
	alm.Lock.Lock()
	defer alm.Lock.Unlock()

	tokens := []Token{}
	for _, token := range alm.Tokens {
		tokens = append(tokens, token)
	}
	return tokens
}

// ListAllListings lists all token listings managed by the AutomatedListingManager
func (alm *AutomatedListingManager) ListAllListings() []Listing {
	alm.Lock.Lock()
	defer alm.Lock.Unlock()

	listings := []Listing{}
	for _, listing := range alm.Listings {
		listings = append(listings, listing)
	}
	return listings
}

// UpdateListingPrice updates the price of a listed token
func (alm *AutomatedListingManager) UpdateListingPrice(listingID string, newPrice decimal.Decimal) error {
	alm.Lock.Lock()
	defer alm.Lock.Unlock()

	listing, exists := alm.Listings[listingID]
	if !exists {
		return errors.New("listing not found")
	}

	listing.Price = newPrice
	alm.Listings[listingID] = listing
	return nil
}
