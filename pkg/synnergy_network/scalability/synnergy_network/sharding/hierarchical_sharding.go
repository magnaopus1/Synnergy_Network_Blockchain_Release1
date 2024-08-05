package sharding

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network/encryption_util"
)

// HierarchicalSharding manages the hierarchical sharding mechanism for the blockchain network.
type HierarchicalSharding struct {
	shards       map[string]*Shard
	mu           sync.RWMutex
	secureRandom func([]byte) (int, error)
}

// Shard represents a shard in the blockchain network.
type Shard struct {
	ID      string
	Parent  *Shard
	Children map[string]*Shard
	Nodes   []Node
	CommKey []byte
}

// Node represents a node in the blockchain network.
type Node struct {
	ID    string
	Shard string
}

// Message represents a message sent between shards.
type Message struct {
	FromShard string
	ToShard   string
	Payload   []byte
	Timestamp time.Time
	Hash      []byte
}

// NewHierarchicalSharding initializes a new HierarchicalSharding.
func NewHierarchicalSharding() *HierarchicalSharding {
	return &HierarchicalSharding{
		shards:       make(map[string]*Shard),
		secureRandom: rand.Read,
	}
}

// AddShard adds a new shard to the hierarchical sharding system.
func (hs *HierarchicalSharding) AddShard(id string, parentID string, nodes []Node) error {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	if _, exists := hs.shards[id]; exists {
		return errors.New("shard already exists")
	}

	var parent *Shard
	if parentID != "" {
		var parentExists bool
		parent, parentExists = hs.shards[parentID]
		if !parentExists {
			return errors.New("parent shard not found")
		}
	}

	commKey := make([]byte, 32)
	if _, err := hs.secureRandom(commKey); err != nil {
		return fmt.Errorf("failed to generate communication key: %v", err)
	}

	shard := &Shard{
		ID:      id,
		Parent:  parent,
		Children: make(map[string]*Shard),
		Nodes:   nodes,
		CommKey: commKey,
	}

	if parent != nil {
		parent.Children[id] = shard
	}

	hs.shards[id] = shard
	return nil
}

// RemoveShard removes a shard from the hierarchical sharding system.
func (hs *HierarchicalSharding) RemoveShard(id string) error {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	shard, exists := hs.shards[id]
	if !exists {
		return errors.New("shard not found")
	}

	if shard.Parent != nil {
		delete(shard.Parent.Children, id)
	}

	for childID := range shard.Children {
		hs.RemoveShard(childID)
	}

	delete(hs.shards, id)
	return nil
}

// SendMessage sends a message from one shard to another.
func (hs *HierarchicalSharding) SendMessage(fromShard, toShard string, payload []byte) error {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	from, exists := hs.shards[fromShard]
	if !exists {
		return errors.New("from shard not found")
	}

	to, exists := hs.shards[toShard]
	if !exists {
		return errors.New("to shard not found")
	}

	encryptedPayload, err := encryption_util.EncryptAES(payload, to.CommKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %v", err)
	}

	message := Message{
		FromShard: from.ID,
		ToShard:   to.ID,
		Payload:   encryptedPayload,
		Timestamp: time.Now(),
		Hash:      hs.hashMessage(encryptedPayload),
	}

	return hs.send(message)
}

// ReceiveMessage processes a received message.
func (hs *HierarchicalSharding) ReceiveMessage(message Message) ([]byte, error) {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	shard, exists := hs.shards[message.ToShard]
	if !exists {
		return nil, errors.New("to shard not found")
	}

	if !bytes.Equal(hs.hashMessage(message.Payload), message.Hash) {
		return nil, errors.New("message hash mismatch")
	}

	decryptedPayload, err := encryption_util.DecryptAES(message.Payload, shard.CommKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %v", err)
	}

	return decryptedPayload, nil
}

// hashMessage generates a SHA-256 hash of the given payload.
func (hs *HierarchicalSharding) hashMessage(payload []byte) []byte {
	hash := sha256.Sum256(payload)
	return hash[:]
}

// send handles the actual sending of the message (e.g., network transport).
func (hs *HierarchicalSharding) send(message Message) error {
	// Simulate sending the message over the network.
	// In a real implementation, this would involve network communication.
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	fmt.Printf("Sending message: %s\n", data)
	return nil
}
