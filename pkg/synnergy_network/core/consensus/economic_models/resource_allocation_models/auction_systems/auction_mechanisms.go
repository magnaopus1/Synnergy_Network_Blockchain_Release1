package auction_systems

import (
	"errors"
	"sort"
	"sync"
)

// Bid represents a bid in the auction
type Bid struct {
	BidderID string
	Amount   float64
	Priority int
}

// Auction represents an auction in the network
type Auction struct {
	mu     sync.Mutex
	ID     string
	Bids   []*Bid
	Status string
}

// Network represents the entire network state
type Network struct {
	mu       sync.Mutex
	Auctions map[string]*Auction
	Nodes    map[string]*Node
}

// Node represents a network participant
type Node struct {
	ID    string
	Stake int
}

// NewNetwork initializes a new Network
func NewNetwork() *Network {
	return &Network{
		Auctions: make(map[string]*Auction),
		Nodes:    make(map[string]*Node),
	}
}

// CreateAuction creates a new auction
func (n *Network) CreateAuction(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Auctions[id] = &Auction{
		ID:     id,
		Bids:   []*Bid{},
		Status: "open",
	}
}

// AddBid adds a bid to an auction
func (n *Network) AddBid(auctionID string, bidderID string, amount float64, priority int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	auction, exists := n.Auctions[auctionID]
	if !exists {
		return errors.New("auction not found")
	}
	if auction.Status != "open" {
		return errors.New("auction is not open")
	}
	auction.Bids = append(auction.Bids, &Bid{
		BidderID: bidderID,
		Amount:   amount,
		Priority: priority,
	})
	return nil
}

// CloseAuction closes the auction and returns the winning bid
func (n *Network) CloseAuction(auctionID string) (*Bid, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	auction, exists := n.Auctions[auctionID]
	if !exists {
		return nil, errors.New("auction not found")
	}
	if auction.Status != "open" {
		return nil, errors.New("auction is not open")
	}
	auction.Status = "closed"
	sort.Slice(auction.Bids, func(i, j int) bool {
		if auction.Bids[i].Amount == auction.Bids[j].Amount {
			return auction.Bids[i].Priority > auction.Bids[j].Priority
		}
		return auction.Bids[i].Amount > auction.Bids[j].Amount
	})
	if len(auction.Bids) == 0 {
		return nil, errors.New("no bids received")
	}
	return auction.Bids[0], nil
}

// AllocateResourcesBasedOnAuction allocates resources based on auction results
func (n *Network) AllocateResourcesBasedOnAuction(auctionID string, totalResources int) (map[string]int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	auction, exists := n.Auctions[auctionID]
	if !exists {
		return nil, errors.New("auction not found")
	}
	if auction.Status != "closed" {
		return nil, errors.New("auction is not closed")
	}

	allocation := make(map[string]int)
	totalBids := 0.0
	for _, bid := range auction.Bids {
		totalBids += bid.Amount
	}

	for _, bid := range auction.Bids {
		allocation[bid.BidderID] = int((bid.Amount / totalBids) * float64(totalResources))
	}

	return allocation, nil
}

// AddNode adds a node to the network
func (n *Network) AddNode(id string, stake int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Nodes[id] = &Node{
		ID:    id,
		Stake: stake,
	}
}

// RemoveNode removes a node from the network
func (n *Network) RemoveNode(id string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, exists := n.Nodes[id]
	if !exists {
		return errors.New("node not found")
	}
	delete(n.Nodes, id)
	return nil
}

// GetNodeStake returns the current stake of a node
func (n *Network) GetNodeStake(id string) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	node, exists := n.Nodes[id]
	if !exists {
		return 0, errors.New("node not found")
	}
	return node.Stake, nil
}

// ListNodes lists all nodes in the network
func (n *Network) ListNodes() []*Node {
	n.mu.Lock()
	defer n.mu.Unlock()
	nodes := []*Node{}
	for _, node := range n.Nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// AllocateResourcesBasedOnStake allocates resources to nodes based on their stakes
func (n *Network) AllocateResourcesBasedOnStake(totalResources int) map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	allocation := make(map[string]int)
	totalStake := 0

	for _, node := range n.Nodes {
		totalStake += node.Stake
	}

	for id, node := range n.Nodes {
		allocation[id] = int(float64(node.Stake) / float64(totalStake) * float64(totalResources))
	}

	return allocation
}
