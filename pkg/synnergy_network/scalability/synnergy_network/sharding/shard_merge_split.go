package sharding

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/synnergy_network/encryption_util"
	"github.com/synnergy_network/error_handling_util"
)

// ShardMergeSplit handles shard merging and splitting operations.
type ShardMergeSplit struct {
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

// NewShardMergeSplit initializes a new ShardMergeSplit.
func NewShardMergeSplit() *ShardMergeSplit {
	return &ShardMergeSplit{
		shards: make(map[string]*Shard),
	}
}

// SplitShard splits a shard into two new shards.
func (sms *ShardMergeSplit) SplitShard(id string) error {
	sms.mu.Lock()
	defer sms.mu.Unlock()

	shard, exists := sms.shards[id]
	if !exists {
		return errors.New("shard not found")
	}

	if len(shard.Nodes) < 2 {
		return errors.New("not enough nodes to split the shard")
	}

	mid := len(shard.Nodes) / 2
	newShard1Nodes := shard.Nodes[:mid]
	newShard2Nodes := shard.Nodes[mid:]

	newShard1ID := id + "_1"
	newShard2ID := id + "_2"

	newShard1CommKey := make([]byte, 32)
	newShard2CommKey := make([]byte, 32)
	if _, err := encryption_util.SecureRandom(newShard1CommKey); err != nil {
		return fmt.Errorf("failed to generate communication key: %v", err)
	}
	if _, err := encryption_util.SecureRandom(newShard2CommKey); err != nil {
		return fmt.Errorf("failed to generate communication key: %v", err)
	}

	newShard1 := &Shard{
		ID:      newShard1ID,
		Nodes:   newShard1Nodes,
		CommKey: newShard1CommKey,
	}
	newShard2 := &Shard{
		ID:      newShard2ID,
		Nodes:   newShard2Nodes,
		CommKey: newShard2CommKey,
	}

	sms.shards[newShard1ID] = newShard1
	sms.shards[newShard2ID] = newShard2
	delete(sms.shards, id)

	return nil
}

// MergeShards merges two shards into one.
func (sms *ShardMergeSplit) MergeShards(id1, id2 string) error {
	sms.mu.Lock()
	defer sms.mu.Unlock()

	shard1, exists1 := sms.shards[id1]
	shard2, exists2 := sms.shards[id2]
	if !exists1 || !exists2 {
		return errors.New("one or both shards not found")
	}

	newShardID := id1 + "_" + id2
	newShardNodes := append(shard1.Nodes, shard2.Nodes...)

	newShardCommKey := make([]byte, 32)
	if _, err := encryption_util.SecureRandom(newShardCommKey); err != nil {
		return fmt.Errorf("failed to generate communication key: %v", err)
	}

	newShard := &Shard{
		ID:      newShardID,
		Nodes:   newShardNodes,
		CommKey: newShardCommKey,
	}

	sms.shards[newShardID] = newShard
	delete(sms.shards, id1)
	delete(sms.shards, id2)

	return nil
}

// ListShards lists all shards in the network.
func (sms *ShardMergeSplit) ListShards() ([]string, error) {
	sms.mu.RLock()
	defer sms.mu.RUnlock()

	if len(sms.shards) == 0 {
		return nil, errors.New("no shards available")
	}

	shardIDs := make([]string, 0, len(sms.shards))
	for id := range sms.shards {
		shardIDs = append(shardIDs, id)
	}

	return shardIDs, nil
}

// GetShard returns a shard by its ID.
func (sms *ShardMergeSplit) GetShard(id string) (*Shard, error) {
	sms.mu.RLock()
	defer sms.mu.RUnlock()

	shard, exists := sms.shards[id]
	if !exists {
		return nil, errors.New("shard not found")
	}

	return shard, nil
}

// SecureRandom generates a secure random byte slice.
func (encryption_util *encryptionUtil) SecureRandom(b []byte) (n int, err error) {
	_, err = rand.Read(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// ShardCommunication handles communication between shards.
func (sms *ShardMergeSplit) ShardCommunication(fromShard, toShard string, payload []byte) error {
	sms.mu.RLock()
	defer sms.mu.RUnlock()

	from, exists := sms.shards[fromShard]
	if !exists {
		return errors.New("from shard not found")
	}

	to, exists := sms.shards[toShard]
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
		Hash:      sms.hashMessage(encryptedPayload),
	}

	return sms.send(message)
}

// ReceiveMessage processes a received message.
func (sms *ShardMergeSplit) ReceiveMessage(message Message) ([]byte, error) {
	sms.mu.RLock()
	defer sms.mu.RUnlock()

	shard, exists := sms.shards[message.ToShard]
	if !exists {
		return nil, errors.New("to shard not found")
	}

	if !equalHashes(sms.hashMessage(message.Payload), message.Hash) {
		return nil, errors.New("message hash mismatch")
	}

	decryptedPayload, err := encryption_util.DecryptAES(message.Payload, shard.CommKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %v", err)
	}

	return decryptedPayload, nil
}

// hashMessage generates a SHA-256 hash of the given payload.
func (sms *ShardMergeSplit) hashMessage(payload []byte) []byte {
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
func (sms *ShardMergeSplit) send(message Message) error {
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
func (sms *ShardMergeSplit) ShardID(key string) (string, error) {
	sms.mu.RLock()
	defer sms.mu.RUnlock()

	if len(sms.shards) == 0 {
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

	for id := range sms.shards {
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
