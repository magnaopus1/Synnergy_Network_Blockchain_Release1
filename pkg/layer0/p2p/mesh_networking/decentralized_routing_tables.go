package mesh_networking

import (
	"crypto/sha256"
	"encoding/hexhex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/syndtr/goleveldb/leveldb"
)

// LinkQuality represents the metrics for evaluating the quality of a link
type LinkQuality struct {
	Latency        time.Duration
	PacketLoss     float64
	SignalStrength float64
}

// RoutingTable manages routing entries with decentralized storage using LevelDB
type RoutingTable struct {
	mu      sync.RWMutex
	entries map[string]*RoutingEntry
	db      *leveldb.DB
}

// RoutingEntry represents a single routing entry
type RoutingEntry struct {
	PeerID   string
	Quality  LinkQuality
	LastSeen time.Time
}

// NewRoutingTable initializes a new routing table with LevelDB storage
func NewRoutingTable(dbPath string) (*RoutingTable, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open LevelDB: %v", err)
	}

	rt := &RoutingTable{
		entries: make(map[string]*RoutingEntry),
		db:      db,
	}

	err = rt.loadFromDB()
	if err != nil {
		return nil, fmt.Errorf("failed to load routing table from DB: %v", err)
	}

	return rt, nil
}

// AddOrUpdateEntry adds or updates a routing entry
func (rt *RoutingTable) AddOrUpdateEntry(peerID string, quality LinkQuality) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	entry := &RoutingEntry{
		PeerID:   peerID,
		Quality:  quality,
		LastSeen: time.Now(),
	}

	rt.entries[peerID] = entry
	err := rt.saveToDB(peerID, entry)
	if err != nil {
		log.Printf("failed to save routing entry to DB: %v", err)
	}
}

// RemoveEntry removes a routing entry
func (rt *RoutingTable) RemoveEntry(peerID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	delete(rt.entries, peerID)
	err := rt.db.Delete([]byte(peerID), nil)
	if err != nil {
		log.Printf("failed to remove routing entry from DB: %v", err)
	}
}

// GetEntry retrieves a routing entry
func (rt *RoutingTable) GetEntry(peerID string) (*RoutingEntry, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	entry, exists := rt.entries[peerID]
	return entry, exists
}

func (rt *RoutingTable) saveToDB(peerID string, entry *RoutingEntry) error {
	data, err := proto.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal routing entry: %v", err)
	}

	err = rt.db.Put([]byte(peerID), data, nil)
	if err != nil {
		return fmt.Errorf("failed to save routing entry to DB: %v", err)
	}

	return nil
}

func (rt *RoutingTable) loadFromDB() error {
	iter := rt.db.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		entry := &RoutingEntry{}
		err := proto.Unmarshal(value, entry)
		if err != nil {
			log.Printf("failed to unmarshal routing entry: %v", err)
			continue
		}

		rt.entries[string(key)] = entry
	}
	iter.Release()

	return iter.Error()
}

// BlockchainBackedRouting manages routing with blockchain integration
type BlockchainBackedRouting struct {
	table *RoutingTable
}

// NewBlockchainBackedRouting initializes a new BlockchainBackedRouting instance
func NewBlockchainBackedRouting(dbPath string) (*BlockchainBackedRouting, error) {
	rt, err := NewRoutingTable(dbPath)
	if err != nil {
		return nil, err
	}

	return &BlockchainBackedRouting{
		table: rt,
	}, nil
}

// AddOrUpdatePeer adds or updates a peer in the routing table and broadcasts to the blockchain
func (bbr *BlockchainBackedRouting) AddOrUpdatePeer(peerID string, quality LinkQuality) {
	bbr.table.AddOrUpdateEntry(peerID, quality)
	// Broadcast routing information to the blockchain
	bbr.broadcastRoutingInfo(peerID, quality)
}

// RemovePeer removes a peer from the routing table and broadcasts to the blockchain
func (bbr *BlockchainBackedRouting) RemovePeer(peerID string) {
	bbr.table.RemoveEntry(peerID)
	// Broadcast routing removal to the blockchain
	bbr.broadcastRoutingRemoval(peerID)
}

// GetPeerQuality retrieves the link quality of a peer
func (bbr *BlockchainBackedRouting) GetPeerQuality(peerID string) (LinkQuality, bool) {
	entry, exists := bbr.table.GetEntry(peerID)
	if !exists {
		return LinkQuality{}, false
	}
	return entry.Quality, true
}

// AdjustRouting adjusts routing decisions based on link quality metrics
func (bbr *BlockchainBackedRouting) AdjustRouting() {
	bbr.table.mu.RLock()
	defer bbr.table.mu.RUnlock()
	for peerID, entry := range bbr.table.entries {
		log.Printf("Adjusting routing for peer %s: Latency=%v, PacketLoss=%.2f, SignalStrength=%.2f", peerID, entry.Quality.Latency, entry.Quality.PacketLoss, entry.Quality.SignalStrength)
		// Add routing logic here based on the quality metrics
	}
}

func (bbr *BlockchainBackedRouting) broadcastRoutingInfo(peerID string, quality LinkQuality) {
	// Placeholder: Broadcast the routing information to the blockchain network
	log.Printf("Broadcasting routing info for peer %s to the blockchain", peerID)
}

func (bbr *BlockchainBackedRouting) broadcastRoutingRemoval(peerID string) {
	// Placeholder: Broadcast the routing removal to the blockchain network
	log.Printf("Broadcasting routing removal for peer %s to the blockchain", peerID)
}

// Blockchain Utility Functions

func Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func Sign(data []byte, privateKey []byte) ([]byte, error) {
	// Placeholder: Implement digital signature using the private key
	return nil, nil
}

func VerifySignature(data []byte, signature []byte, publicKey []byte) bool {
	// Placeholder: Implement signature verification using the public key
	return true
}

func main() {
	// Initialize blockchain-backed routing
	dbPath := "routing_table.db"
	bbr, err := NewBlockchainBackedRouting(dbPath)
	if err != nil {
		log.Fatalf("failed to initialize blockchain-backed routing: %v", err)
	}

	// Add/update peer
	peerID := "peer1"
	quality := LinkQuality{Latency: 20 * time.Millisecond, PacketLoss: 0.01, SignalStrength: 80}
	bbr.AddOrUpdatePeer(peerID, quality)

	// Adjust routing
	bbr.AdjustRouting()

	// Remove peer
	bbr.RemovePeer(peerID)
}
