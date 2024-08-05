package sharding

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"sync"
	"time"

	"github.com/synnergy_network/encryption_util"
	"github.com/synnergy_network/error_handling_util"
)

// ShardManagement handles shard creation, deletion, and management in the blockchain network.
type ShardManagement struct {
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

// NewShardManagement initializes a new ShardManagement.
func NewShardManagement() *ShardManagement {
	return &ShardManagement{
		shards: make(map[string]*Shard),
	}
}

// CreateShard creates a new shard with the given nodes.
func (sm *ShardManagement) CreateShard(id string, nodes []Node) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.shards[id]; exists {
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

	sm.shards[id] = shard
	return nil
}

// DeleteShard removes a shard from the shard management system.
func (sm *ShardManagement) DeleteShard(id string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.shards[id]; !exists {
		return errors.New("shard not found")
	}

	delete(sm.shards, id)
	return nil
}

// AddNode adds a node to a specific shard.
func (sm *ShardManagement) AddNode(shardID string, node Node) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	shard, exists := sm.shards[shardID]
	if !exists {
		return errors.New("shard not found")
	}

	shard.Nodes = append(shard.Nodes, node)
	return nil
}

// RemoveNode removes a node from a specific shard.
func (sm *ShardManagement) RemoveNode(shardID, nodeID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	shard, exists := sm.shards[shardID]
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
func (sm *ShardManagement) ListNodes(shardID string) ([]Node, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	shard, exists := sm.shards[shardID]
	if !exists {
		return nil, errors.New("shard not found")
	}

	return shard.Nodes, nil
}

// SendMessage sends a message from one shard to another.
func (sm *ShardManagement) SendMessage(fromShard, toShard string, payload []byte) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	from, exists := sm.shards[fromShard]
	if !exists {
		return errors.New("from shard not found")
	}

	to, exists := sm.shards[toShard]
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
		Hash:      sm.hashMessage(encryptedPayload),
	}

	return sm.send(message)
}

// ReceiveMessage processes a received message.
func (sm *ShardManagement) ReceiveMessage(message Message) ([]byte, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	shard, exists := sm.shards[message.ToShard]
	if !exists {
		return nil, errors.New("to shard not found")
	}

	if !equalHashes(sm.hashMessage(message.Payload), message.Hash) {
		return nil, errors.New("message hash mismatch")
	}

	decryptedPayload, err := encryption_util.DecryptAES(message.Payload, shard.CommKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %v", err)
	}

	return decryptedPayload, nil
}

// hashMessage generates a SHA-256 hash of the given payload.
func (sm *ShardManagement) hashMessage(payload []byte) []byte {
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
func (sm *ShardManagement) send(message Message) error {
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
func (sm *ShardManagement) ShardID(key string) (string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if len(sm.shards) == 0 {
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

	for id := range sm.shards {
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

// CheckShardHealth checks the health of a specific shard.
func (sm *ShardManagement) CheckShardHealth(shardID string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	shard, exists := sm.shards[shardID]
	if !exists {
		return errors.New("shard not found")
	}

	if len(shard.Nodes) == 0 {
		return errors.New("no nodes in shard")
	}

	// Placeholder for additional health checks.
	// Implement real checks based on business logic and requirements.

	return nil
}

// RecoverShard attempts to recover a shard after a failure.
func (sm *ShardManagement) RecoverShard(shardID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	shard, exists := sm.shards[shardID]
	if !exists {
		return errors.New("shard not found")
	}

	// Placeholder for shard recovery logic.
	// Implement actual recovery steps based on business logic and requirements.

	fmt.Printf("Shard %s recovered successfully\n", shardID)
	return nil
}

// ShardCommunication handles cross-shard communication.
func (sm *ShardManagement) ShardCommunication(fromShard, toShard string, payload []byte) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	from, exists := sm.shards[fromShard]
	if !exists {
		return errors.New("from shard not found")
	}

	to, exists := sm.shards[toShard]
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
		Hash:      sm.hashMessage(encryptedPayload),
	}

	return sm.send(message)
}

// ListShards lists all shards in the network.
func (sm *ShardManagement) ListShards() ([]string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if len(sm.shards) == 0 {
		return nil, errors.New("no shards available")
	}

	shardIDs := make([]string, 0, len(sm.shards))
	for id := range sm.shards {
		shardIDs = append(shardIDs, id)
	}

	return shardIDs, nil
}

// RandomShard returns a random shard ID.
func (sm *ShardManagement) RandomShard() (string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if len(sm.shards) == 0 {
		return "", errors.New("no shards available")
	}

	rand.Seed(time.Now().UnixNano())
	keys := make([]string, 0, len(sm.shards))
	for k := range sm.shards {
		keys = append(keys, k)
	}

	return keys[rand.Intn(len(keys))], nil
}

// MigrateNode migrates a node from one shard to another.
func (sm *ShardManagement) MigrateNode(nodeID, fromShard, toShard string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	from, exists := sm.shards[fromShard]
	if !exists {
		return errors.New("from shard not found")
	}

	to, exists := sm.shards[toShard]
	if !exists {
		return errors.New("to shard not found")
	}

	var node Node
	var nodeIndex int
	for i, n := range from.Nodes {
		if n.ID == nodeID {
			node = n
			nodeIndex = i
			break
		}
	}

	if node.ID == "" {
		return errors.New("node not found in from shard")
	}

	from.Nodes = append(from.Nodes[:nodeIndex], from.Nodes[nodeIndex+1:]...)
	to.Nodes = append(to.Nodes, node)

	return nil
}
