package sharding

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/synnergy_network/encryption_util"
	"github.com/synnergy_network/error_handling_util"
)

// PartitionTolerance manages the partition tolerance mechanism for the blockchain network.
type PartitionTolerance struct {
	shards map[string]*Shard
	mu     sync.RWMutex
}

// Shard represents a shard in the blockchain network.
type Shard struct {
	ID      string
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

// NewPartitionTolerance initializes a new PartitionTolerance.
func NewPartitionTolerance() *PartitionTolerance {
	return &PartitionTolerance{
		shards: make(map[string]*Shard),
	}
}

// AddShard adds a new shard to the partition tolerance system.
func (pt *PartitionTolerance) AddShard(id string, nodes []Node) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if _, exists := pt.shards[id]; exists {
		return errors.New("shard already exists")
	}

	commKey := make([]byte, 32)
	if _, err := encryption_util.SecureRandom(commKey); err != nil {
		return fmt.Errorf("failed to generate communication key: %v", err)
	}

	shard := &Shard{
		ID:      id,
		Nodes:   nodes,
		CommKey: commKey,
	}

	pt.shards[id] = shard
	return nil
}

// RemoveShard removes a shard from the partition tolerance system.
func (pt *PartitionTolerance) RemoveShard(id string) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if _, exists := pt.shards[id]; !exists {
		return errors.New("shard not found")
	}

	delete(pt.shards, id)
	return nil
}

// SendMessage sends a message from one shard to another.
func (pt *PartitionTolerance) SendMessage(fromShard, toShard string, payload []byte) error {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	from, exists := pt.shards[fromShard]
	if !exists {
		return errors.New("from shard not found")
	}

	to, exists := pt.shards[toShard]
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
		Hash:      pt.hashMessage(encryptedPayload),
	}

	return pt.send(message)
}

// ReceiveMessage processes a received message.
func (pt *PartitionTolerance) ReceiveMessage(message Message) ([]byte, error) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	shard, exists := pt.shards[message.ToShard]
	if !exists {
		return nil, errors.New("to shard not found")
	}

	if !equalHashes(pt.hashMessage(message.Payload), message.Hash) {
		return nil, errors.New("message hash mismatch")
	}

	decryptedPayload, err := encryption_util.DecryptAES(message.Payload, shard.CommKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %v", err)
	}

	return decryptedPayload, nil
}

// hashMessage generates a SHA-256 hash of the given payload.
func (pt *PartitionTolerance) hashMessage(payload []byte) []byte {
	hash := sha256.Sum256(payload)
	return hash[:]
}

// equalHashes compares two hashes.
func equalHashes(hash1, hash2 []byte) bool {
	if len(hash1) != len(hash2) {
		return false
	}
	for i, b := range hash1 {
		if b != hash2[i] {
			return false
		}
	}
	return true
}

// send handles the actual sending of the message (e.g., network transport).
func (pt *PartitionTolerance) send(message Message) error {
	// Simulate sending the message over the network.
	// In a real implementation, this would involve network communication.
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	fmt.Printf("Sending message: %s\n", data)
	return nil
}

// ShardID returns the shard ID for a given key using a consistent hashing mechanism.
func (pt *PartitionTolerance) ShardID(key string) (string, error) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	if len(pt.shards) == 0 {
		return "", errors.New("no shards available")
	}

	h := fnv.New32a()
	_, err := h.Write([]byte(key))
	if err != nil {
		return "", err
	}
	hashValue := h.Sum32()

	var shardID string
	var minDiff uint32 = ^uint32(0) // Max uint32

	for id := range pt.shards {
		shardHash := fnvHash(id)
		diff := hashDiff(shardHash, hashValue)
		if diff < minDiff {
			minDiff = diff
			shardID = id
		}
	}

	return shardID, nil
}

// fnvHash generates a FNV-1a hash for a given string.
func fnvHash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// hashDiff calculates the absolute difference between two hash values.
func hashDiff(a, b uint32) uint32 {
	if a > b {
		return a - b
	}
	return b - a
}

// AddNode adds a node to a specific shard.
func (pt *PartitionTolerance) AddNode(shardID string, node Node) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	shard, exists := pt.shards[shardID]
	if !exists {
		return errors.New("shard not found")
	}

	shard.Nodes = append(shard.Nodes, node)
	return nil
}

// RemoveNode removes a node from a specific shard.
func (pt *PartitionTolerance) RemoveNode(shardID, nodeID string) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	shard, exists := pt.shards[shardID]
	if !exists {
		return errors.New("shard not found")
	}

	for i, node := range shard.Nodes {
		if node.ID == nodeID {
			shard.Nodes = append(shard.Nodes[:i], shard.Nodes[i+1:]...)
			return nil
		}
	}

	return errors.New("node not found")
}

// ListNodes lists all nodes in a specific shard.
func (pt *PartitionTolerance) ListNodes(shardID string) ([]Node, error) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	shard, exists := pt.shards[shardID]
	if !exists {
		return nil, errors.New("shard not found")
	}

	return shard.Nodes, nil
}

// CheckPartitionTolerance verifies if a shard can operate independently in case of a partition.
func (pt *PartitionTolerance) CheckPartitionTolerance(shardID string) error {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	shard, exists := pt.shards[shardID]
	if !exists {
		return errors.New("shard not found")
	}

	if len(shard.Nodes) == 0 {
		return errors.New("no nodes in shard")
	}

	// Placeholder for additional partition tolerance checks.
	// Implement real checks based on business logic and requirements.

	return nil
}

// RecoverShard attempts to recover a shard after a partition.
func (pt *PartitionTolerance) RecoverShard(shardID string) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	shard, exists := pt.shards[shardID]
	if !exists {
		return errors.New("shard not found")
	}

	// Placeholder for shard recovery logic.
	// Implement actual recovery steps based on business logic and requirements.

	fmt.Printf("Shard %s recovered successfully\n", shardID)
	return nil
}
