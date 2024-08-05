package management

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Auction types
const (
	EnglishAuction       = "english"
	DutchAuction         = "dutch"
	JapaneseAuction      = "japanese"
	CandleAuction        = "candle"
	VickreyAuction       = "vickrey"
	SwedishAuction       = "swedish"
	SealedBidAuction     = "sealed-bid"
	ReserveAuction       = "reserve"
	MinimumBidAuction    = "minimum-bid"
	AbsoluteAuction      = "absolute"
)

// Auction represents a generic auction structure.
type Auction struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	TokenID      string                 `json:"token_id"`
	Seller       string                 `json:"seller"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      time.Time              `json:"end_time"`
	CurrentBid   float64                `json:"current_bid"`
	Bids         map[string]float64     `json:"bids"`
	WinningBid   *Bid                   `json:"winning_bid"`
	ReservePrice float64                `json:"reserve_price,omitempty"`
	MinBidIncrement float64             `json:"min_bid_increment,omitempty"`
}

// Bid represents a bid in an auction.
type Bid struct {
	Bidder string  `json:"bidder"`
	Amount float64 `json:"amount"`
}

// AuctionManager manages all auctions.
type AuctionManager struct {
	mu       sync.Mutex
	Auctions map[string]*Auction
}

// NewAuctionManager creates a new instance of AuctionManager.
func NewAuctionManager() *AuctionManager {
	return &AuctionManager{
		Auctions: make(map[string]*Auction),
	}
}

// CreateAuction creates a new auction with the given parameters.
func (am *AuctionManager) CreateAuction(auctionType, tokenID, seller string, startTime, endTime time.Time, reservePrice, minBidIncrement float64) (*Auction, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	auctionID := fmt.Sprintf("auction-%d", time.Now().UnixNano())
	auction := &Auction{
		ID:              auctionID,
		Type:            auctionType,
		TokenID:         tokenID,
		Seller:          seller,
		StartTime:       startTime,
		EndTime:         endTime,
		Bids:            make(map[string]float64),
		ReservePrice:    reservePrice,
		MinBidIncrement: minBidIncrement,
	}
	am.Auctions[auctionID] = auction
	return auction, nil
}

// PlaceBid places a bid in the auction.
func (am *AuctionManager) PlaceBid(auctionID, bidder string, amount float64) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	auction, exists := am.Auctions[auctionID]
	if !exists {
		return errors.New("auction not found")
	}

	if time.Now().Before(auction.StartTime) || time.Now().After(auction.EndTime) {
		return errors.New("auction is not active")
	}

	if amount <= auction.CurrentBid {
		return errors.New("bid amount must be higher than the current bid")
	}

	if amount < auction.CurrentBid + auction.MinBidIncrement {
		return errors.New("bid amount must be at least the minimum bid increment higher than the current bid")
	}

	auction.Bids[bidder] = amount
	auction.CurrentBid = amount

	if auction.Type == VickreyAuction {
		if auction.WinningBid == nil || amount > auction.WinningBid.Amount {
			auction.WinningBid = &Bid{Bidder: bidder, Amount: amount}
		}
	}

	return nil
}

// FinalizeAuction finalizes the auction and determines the winner.
func (am *AuctionManager) FinalizeAuction(auctionID string) (*Bid, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	auction, exists := am.Auctions[auctionID]
	if !exists {
		return nil, errors.New("auction not found")
	}

	if time.Now().Before(auction.EndTime) {
		return nil, errors.New("auction is still active")
	}

	switch auction.Type {
	case EnglishAuction, MinimumBidAuction, AbsoluteAuction:
		return am.finalizeHighestBidAuction(auction)
	case DutchAuction:
		return am.finalizeDutchAuction(auction)
	case JapaneseAuction:
		return am.finalizeJapaneseAuction(auction)
	case CandleAuction:
		return am.finalizeCandleAuction(auction)
	case VickreyAuction:
		return auction.WinningBid, nil
	case SwedishAuction:
		return am.finalizeSwedishAuction(auction)
	case SealedBidAuction:
		return am.finalizeSealedBidAuction(auction)
	case ReserveAuction:
		if auction.CurrentBid >= auction.ReservePrice {
			return am.finalizeHighestBidAuction(auction)
		}
		return nil, errors.New("reserve price not met")
	default:
		return nil, errors.New("unsupported auction type")
	}
}

func (am *AuctionManager) finalizeHighestBidAuction(auction *Auction) (*Bid, error) {
	var highestBid *Bid
	for bidder, amount := range auction.Bids {
		if highestBid == nil || amount > highestBid.Amount {
			highestBid = &Bid{Bidder: bidder, Amount: amount}
		}
	}
	if highestBid == nil {
		return nil, errors.New("no bids placed")
	}
	auction.WinningBid = highestBid
	return highestBid, nil
}

func (am *AuctionManager) finalizeDutchAuction(auction *Auction) (*Bid, error) {
	return nil, errors.New("dutch auction finalization not implemented")
}

func (am *AuctionManager) finalizeJapaneseAuction(auction *Auction) (*Bid, error) {
	return nil, errors.New("japanese auction finalization not implemented")
}

func (am *AuctionManager) finalizeCandleAuction(auction *Auction) (*Bid, error) {
	return nil, errors.New("candle auction finalization not implemented")
}

func (am *AuctionManager) finalizeSwedishAuction(auction *Auction) (*Bid, error) {
	return nil, errors.New("swedish auction finalization not implemented")
}

func (am *AuctionManager) finalizeSealedBidAuction(auction *Auction) (*Bid, error) {
	var highestBid *Bid
	for bidder, amount := range auction.Bids {
		if highestBid == nil || amount > highestBid.Amount {
			highestBid = &Bid{Bidder: bidder, Amount: amount}
		}
	}
	if highestBid == nil {
		return nil, errors.New("no bids placed")
	}
	auction.WinningBid = highestBid
	return highestBid, nil
}

// GetAuction retrieves an auction by its ID.
func (am *AuctionManager) GetAuction(auctionID string) (*Auction, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	auction, exists := am.Auctions[auctionID]
	if !exists {
		return nil, errors.New("auction not found")
	}
	return auction, nil
}

// GetActiveAuctions retrieves all active auctions.
func (am *AuctionManager) GetActiveAuctions() ([]*Auction, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var activeAuctions []*Auction
	for _, auction := range am.Auctions {
		if time.Now().After(auction.StartTime) && time.Now().Before(auction.EndTime) {
			activeAuctions = append(activeAuctions, auction)
		}
	}
	return activeAuctions, nil
}
