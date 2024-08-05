package trading

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Bid represents a single bid in the real-time bidding system
type Bid struct {
	ID         string
	BidderID   string
	Amount     float64
	Timestamp  time.Time
}

// Auction represents an auction where bids are placed
type Auction struct {
	ID          string
	ResourceID  string
	StartTime   time.Time
	EndTime     time.Time
	StartingBid float64
	Bids        []Bid
	Active      bool
}

// RealTimeBiddingManager manages real-time bidding for computing resources
type RealTimeBiddingManager struct {
	mu       sync.Mutex
	auctions map[string]Auction
}

// NewRealTimeBiddingManager initializes a new RealTimeBiddingManager
func NewRealTimeBiddingManager() *RealTimeBiddingManager {
	return &RealTimeBiddingManager{
		auctions: make(map[string]Auction),
	}
}

// CreateAuction creates a new auction
func (rtbm *RealTimeBiddingManager) CreateAuction(resourceID string, startTime, endTime time.Time, startingBid float64) (string, error) {
	rtbm.mu.Lock()
	defer rtbm.mu.Unlock()

	if startTime.After(endTime) {
		return "", errors.New("start time must be before end time")
	}

	auctionID := generateID(resourceID, startTime, endTime)
	auction := Auction{
		ID:          auctionID,
		ResourceID:  resourceID,
		StartTime:   startTime,
		EndTime:     endTime,
		StartingBid: startingBid,
		Bids:        []Bid{},
		Active:      true,
	}

	rtbm.auctions[auctionID] = auction
	return auctionID, nil
}

// PlaceBid places a bid on an active auction
func (rtbm *RealTimeBiddingManager) PlaceBid(auctionID, bidderID string, amount float64) (string, error) {
	rtbm.mu.Lock()
	defer rtbm.mu.Unlock()

	auction, exists := rtbm.auctions[auctionID]
	if !exists {
		return "", errors.New("auction not found")
	}

	if !auction.Active {
		return "", errors.New("auction is not active")
	}

	if time.Now().After(auction.EndTime) {
		return "", errors.New("auction has ended")
	}

	if amount <= auction.StartingBid {
		return "", errors.New("bid amount must be higher than the starting bid")
	}

	for _, bid := range auction.Bids {
		if amount <= bid.Amount {
			return "", errors.New("bid amount must be higher than the previous bids")
		}
	}

	bidID := generateID(bidderID, auctionID, time.Now())
	bid := Bid{
		ID:        bidID,
		BidderID:  bidderID,
		Amount:    amount,
		Timestamp: time.Now(),
	}

	auction.Bids = append(auction.Bids, bid)
	rtbm.auctions[auctionID] = auction

	return bidID, nil
}

// GetAuction retrieves the details of an auction
func (rtbm *RealTimeBiddingManager) GetAuction(auctionID string) (Auction, error) {
	rtbm.mu.Lock()
	defer rtbm.mu.Unlock()

	auction, exists := rtbm.auctions[auctionID]
	if !exists {
		return Auction{}, errors.New("auction not found")
	}

	return auction, nil
}

// ListActiveAuctions lists all active auctions
func (rtbm *RealTimeBiddingManager) ListActiveAuctions() []Auction {
	rtbm.mu.Lock()
	defer rtbm.mu.Unlock()

	var activeAuctions []Auction
	for _, auction := range rtbm.auctions {
		if auction.Active && time.Now().Before(auction.EndTime) {
			activeAuctions = append(activeAuctions, auction)
		}
	}
	return activeAuctions
}

// CloseAuction closes an auction after its end time
func (rtbm *RealTimeBiddingManager) CloseAuction(auctionID string) error {
	rtbm.mu.Lock()
	defer rtbm.mu.Unlock()

	auction, exists := rtbm.auctions[auctionID]
	if !exists {
		return errors.New("auction not found")
	}

	if time.Now().Before(auction.EndTime) {
		return errors.New("auction cannot be closed before its end time")
	}

	auction.Active = false
	rtbm.auctions[auctionID] = auction

	return nil
}

// generateID generates a unique ID using Argon2
func generateID(parts ...interface{}) string {
	var input string
	for _, part := range parts {
		input += part.(string)
	}
	hash := argon2.IDKey([]byte(input), []byte("somesalt"), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}
