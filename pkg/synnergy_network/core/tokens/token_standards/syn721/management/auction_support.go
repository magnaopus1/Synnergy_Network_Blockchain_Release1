package management

import (
	"fmt"
	"sync"
	"time"
)

// Auction types
const (
	EnglishAuction     = "English"
	PennyAuction       = "Penny"
	DutchAuction       = "Dutch"
	ReverseAuction     = "Reverse"
	SealedBidAuction   = "SealedBid"
	ComboAuction       = "Combo"
	SwedishAuction     = "Swedish"
	VickereyAuction    = "Vickerey"
	CandleAuction      = "Candle"
	ChineseAuction     = "Chinese"
	JapaneseAuction    = "Japanese"
)

// Bid represents a bid in an auction
type Bid struct {
	Bidder    string
	Amount    float64
	Timestamp time.Time
}

// Auction represents an auction for a SYN721 token
type Auction struct {
	TokenID      string
	Seller       string
	AuctionType  string
	StartTime    time.Time
	EndTime      time.Time
	ReservePrice float64
	Bids         []Bid
	WinningBid   *Bid
}

// AuctionManager manages auctions for SYN721 tokens
type AuctionManager struct {
	auctions map[string]*Auction
	mutex    sync.Mutex
}

// NewAuctionManager initializes a new AuctionManager
func NewAuctionManager() *AuctionManager {
	return &AuctionManager{
		auctions: make(map[string]*Auction),
	}
}

// StartAuction starts a new auction
func (am *AuctionManager) StartAuction(tokenID, seller, auctionType string, startTime, endTime time.Time, reservePrice float64) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if _, exists := am.auctions[tokenID]; exists {
		return fmt.Errorf("auction for token ID %s already exists", tokenID)
	}

	auction := &Auction{
		TokenID:      tokenID,
		Seller:       seller,
		AuctionType:  auctionType,
		StartTime:    startTime,
		EndTime:      endTime,
		ReservePrice: reservePrice,
		Bids:         []Bid{},
	}

	am.auctions[tokenID] = auction
	return nil
}

// PlaceBid places a bid in an ongoing auction
func (am *AuctionManager) PlaceBid(tokenID, bidder string, amount float64) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	auction, exists := am.auctions[tokenID]
	if !exists {
		return fmt.Errorf("auction for token ID %s not found", tokenID)
	}

	if time.Now().After(auction.EndTime) {
		return fmt.Errorf("auction for token ID %s has ended", tokenID)
	}

	bid := Bid{
		Bidder:    bidder,
		Amount:    amount,
		Timestamp: time.Now(),
	}

	// Specific rules for Penny Auctions
	if auction.AuctionType == PennyAuction {
		bid.Amount += 0.01 // Increase the bid amount by 1 cent
	}

	auction.Bids = append(auction.Bids, bid)
	return nil
}

// EndAuction ends an auction and determines the winning bid
func (am *AuctionManager) EndAuction(tokenID string) (*Bid, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	auction, exists := am.auctions[tokenID]
	if !exists {
		return nil, fmt.Errorf("auction for token ID %s not found", tokenID)
	}

	if time.Now().Before(auction.EndTime) {
		return nil, fmt.Errorf("auction for token ID %s has not ended yet", tokenID)
	}

	var winningBid *Bid
	switch auction.AuctionType {
	case EnglishAuction, PennyAuction, SealedBidAuction, ComboAuction, SwedishAuction, CandleAuction, ChineseAuction, JapaneseAuction:
		winningBid = am.findHighestBid(auction)
	case DutchAuction, ReverseAuction:
		winningBid = am.findLowestBid(auction)
	case VickereyAuction:
		winningBid = am.findSecondHighestBid(auction)
	default:
		return nil, fmt.Errorf("unknown auction type: %s", auction.AuctionType)
	}

	if winningBid != nil && winningBid.Amount >= auction.ReservePrice {
		auction.WinningBid = winningBid
	} else {
		auction.WinningBid = nil
	}

	return auction.WinningBid, nil
}

// findHighestBid finds the highest bid in an auction
func (am *AuctionManager) findHighestBid(auction *Auction) *Bid {
	var highestBid *Bid
	for _, bid := range auction.Bids {
		if highestBid == nil || bid.Amount > highestBid.Amount {
			highestBid = &bid
		}
	}
	return highestBid
}

// findLowestBid finds the lowest bid in an auction
func (am *AuctionManager) findLowestBid(auction *Auction) *Bid {
	var lowestBid *Bid
	for _, bid := range auction.Bids {
		if lowestBid == nil || bid.Amount < lowestBid.Amount {
			lowestBid = &bid
		}
	}
	return lowestBid
}

// findSecondHighestBid finds the second highest bid in an auction (for Vickerey auction)
func (am *AuctionManager) findSecondHighestBid(auction *Auction) *Bid {
	var highestBid, secondHighestBid *Bid
	for _, bid := range auction.Bids {
		if highestBid == nil || bid.Amount > highestBid.Amount {
			secondHighestBid = highestBid
			highestBid = &bid
		} else if secondHighestBid == nil || bid.Amount > secondHighestBid.Amount {
			secondHighestBid = &bid
		}
	}
	return secondHighestBid
}

// CancelAuction cancels an ongoing auction
func (am *AuctionManager) CancelAuction(tokenID string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	_, exists := am.auctions[tokenID]
	if !exists {
		return fmt.Errorf("auction for token ID %s not found", tokenID)
	}

	delete(am.auctions, tokenID)
	return nil
}

// GetAuction retrieves an auction by token ID
func (am *AuctionManager) GetAuction(tokenID string) (*Auction, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	auction, exists := am.auctions[tokenID]
	if !exists {
		return nil, fmt.Errorf("auction for token ID %s not found", tokenID)
	}

	return auction, nil
}

// GetActiveAuctions retrieves all active auctions
func (am *AuctionManager) GetActiveAuctions() []*Auction {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	var activeAuctions []*Auction
	for _, auction := range am.auctions {
		if time.Now().Before(auction.EndTime) {
			activeAuctions = append(activeAuctions, auction)
		}
	}

	return activeAuctions
}

// GetPastAuctions retrieves all past auctions
func (am *AuctionManager) GetPastAuctions() []*Auction {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	var pastAuctions []*Auction
	for _, auction := range am.auctions {
		if time.Now().After(auction.EndTime) {
			pastAuctions = append(pastAuctions, auction)
		}
	}

	return pastAuctions
}
