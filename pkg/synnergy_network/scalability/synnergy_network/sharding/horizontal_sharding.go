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

// HorizontalSharding manages the horizontal sharding mechanism for the blockchain network.
type HorizontalSharding struct {
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

// NewHorizontalSharding initializes a new HorizontalSharding.
func NewHorizontalSharding() *HorizontalSharding {
	return &HorizontalSharding{
		shards: make(map[string]*Shard),
	}
}

// AddShard adds a new shard to the horizontal sharding system.
func (hs *HorizontalSharding) AddShard(id string, nodes []Node) error {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	if _, exists := hs.shards[id]; exists {
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

	hs.shards[id] = shard
	return nil
}

// RemoveShard removes a shard from the horizontal sharding system.
func (hs *HorizontalSharding) RemoveShard(id string) error {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	if _, exists := hs.shards[id]; !exists {
		return errors.New("shard not found")
	}

	delete(hs.shards, id)
	return nil
}

// SendMessage sends a message from one shard to another.
func (hs *HorizontalSharding) SendMessage(fromShard, toShard string, payload []byte) error {
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
func (hs *HorizontalSharding) ReceiveMessage(message Message) ([]byte, error) {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	shard, exists := hs.shards[message.ToShard]
	if !exists {
		return nil, errors.New("to shard not found")
	}

	if !equalHashes(hs.hashMessage(message.Payload), message.Hash) {
		return nil, errors.New("message hash mismatch")
	}

	decryptedPayload, err := encryption_util.DecryptAES(message.Payload, shard.CommKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %v", err)
	}

	return decryptedPayload, nil
}

// hashMessage generates a SHA-256 hash of the given payload.
func (hs *HorizontalSharding) hashMessage(payload []byte) []byte {
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
func (hs *HorizontalSharding) send(message Message) error {
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
func (hs *HorizontalSharding) ShardID(key string) (string, error) {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	if len(hs.shards) == 0 {
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

	for id := range hs.shards {
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
	return b -
