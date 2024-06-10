package auction_systems

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/core/smart_contract"
	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction"
)

// AuctionType defines the type of auction
type AuctionType int

const (
	// FirstPriceAuction means the highest bidder wins and pays their bid
	FirstPriceAuction AuctionType = iota
	// SecondPriceAuction means the highest bidder wins but pays the second highest bid
	SecondPriceAuction
)

// Bid represents a bid in the auction
type Bid struct {
	BidderID string
	Amount   *big.Int
	Timestamp time.Time
}

// Auction represents an auction mechanism
type Auction struct {
	sync.Mutex
	ID          string
	Type        AuctionType
	Bids        []*Bid
	StartTime   time.Time
	EndTime     time.Time
	Resources   int
	IsCompleted bool
	WinningBid  *Bid
}

// AuctionManager manages multiple auctions
type AuctionManager struct {
	sync.Mutex
	auctions map[string]*Auction
}

// NewAuctionManager initializes a new instance of AuctionManager
func NewAuctionManager() *AuctionManager {
	return &AuctionManager{
		auctions: make(map[string]*Auction),
	}
}

// CreateAuction creates a new auction
func (am *AuctionManager) CreateAuction(id string, auctionType AuctionType, startTime, endTime time.Time, resources int) (*Auction, error) {
	am.Lock()
	defer am.Unlock()
	if _, exists := am.auctions[id]; exists {
		return nil, errors.New("auction already exists")
	}

	auction := &Auction{
		ID:        id,
		Type:      auctionType,
		StartTime: startTime,
		EndTime:   endTime,
		Resources: resources,
	}
	am.auctions[id] = auction
	return auction, nil
}

// PlaceBid places a bid on an auction
func (am *AuctionManager) PlaceBid(auctionID, bidderID string, amount *big.Int) error {
	am.Lock()
	defer am.Unlock()

	auction, exists := am.auctions[auctionID]
	if !exists {
		return errors.New("auction not found")
	}
	if time.Now().Before(auction.StartTime) || time.Now().After(auction.EndTime) {
		return errors.New("auction is not active")
	}

	bid := &Bid{
		BidderID:  bidderID,
		Amount:    amount,
		Timestamp: time.Now(),
	}
	auction.Bids = append(auction.Bids, bid)
	return nil
}

// EndAuction ends the auction and determines the winner
func (am *AuctionManager) EndAuction(auctionID string) (*Bid, error) {
	am.Lock()
	defer am.Unlock()

	auction, exists := am.auctions[auctionID]
	if !exists {
		return nil, errors.New("auction not found")
	}
	if time.Now().Before(auction.EndTime) {
		return nil, errors.New("auction is still active")
	}
	if auction.IsCompleted {
		return auction.WinningBid, nil
	}

	auction.IsCompleted = true
	if len(auction.Bids) == 0 {
		return nil, errors.New("no bids placed")
	}

	auction.WinningBid = auction.determineWinner()
	return auction.WinningBid, nil
}

// determineWinner determines the winner of the auction based on the auction type
func (a *Auction) determineWinner() *Bid {
	var winningBid *Bid
	switch a.Type {
	case FirstPriceAuction:
		winningBid = a.getHighestBid()
	case SecondPriceAuction:
		winningBid = a.getSecondHighestBid()
	}
	return winningBid
}

// getHighestBid gets the highest bid
func (a *Auction) getHighestBid() *Bid {
	var highestBid *Bid
	for _, bid := range a.Bids {
		if highestBid == nil || bid.Amount.Cmp(highestBid.Amount) > 0 {
			highestBid = bid
		}
	}
	return highestBid
}

// getSecondHighestBid gets the highest bidder but pays the second highest amount
func (a *Auction) getSecondHighestBid() *Bid {
	var highestBid, secondHighestBid *Bid
	for _, bid := range a.Bids {
		if highestBid == nil || bid.Amount.Cmp(highestBid.Amount) > 0 {
			secondHighestBid = highestBid
			highestBid = bid
		} else if secondHighestBid == nil || bid.Amount.Cmp(secondHighestBid.Amount) > 0 {
			secondHighestBid = bid
		}
	}

	if secondHighestBid == nil {
		secondHighestBid = highestBid
	}
	winningBid := &Bid{
		BidderID:  highestBid.BidderID,
		Amount:    secondHighestBid.Amount,
		Timestamp: highestBid.Timestamp,
	}
	return winningBid
}

// Example usage
func main() {
	am := NewAuctionManager()

	auction, err := am.CreateAuction("auction1", FirstPriceAuction, time.Now().Add(time.Minute), time.Now().Add(time.Hour), 100)
	if err != nil {
		fmt.Println("Error creating auction:", err)
		return
	}

	err = am.PlaceBid("auction1", "user1", big.NewInt(1000))
	if err != nil {
		fmt.Println("Error placing bid:", err)
		return
	}

	err = am.PlaceBid("auction1", "user2", big.NewInt(1500))
	if err != nil {
		fmt.Println("Error placing bid:", err)
		return
	}

	winningBid, err := am.EndAuction("auction1")
	if err != nil {
		fmt.Println("Error ending auction:", err)
		return
	}

	fmt.Printf("Winning Bidder: %s, Amount: %s\n", winningBid.BidderID, winningBid.Amount.String())
}
