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

// CrossShardCommunication handles communication between shards in the blockchain network.
type CrossShardCommunication struct {
	shards       map[string]*Shard
	mu           sync.RWMutex
	secureRandom func([]byte) (int, error)
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

// NewCrossShardCommunication initializes a new CrossShardCommunication.
func NewCrossShardCommunication() *CrossShardCommunication {
	return &CrossShardCommunication{
		shards:       make(map[string]*Shard),
		secureRandom: rand.Read,
	}
}

// AddShard adds a new shard to the cross-shard communication system.
func (csc *CrossShardCommunication) AddShard(id string, nodes []Node) error {
	csc.mu.Lock()
	defer csc.mu.Unlock()

	if _, exists := csc.shards[id]; exists {
		return errors.New("shard already exists")
	}

	commKey := make([]byte, 32)
	if _, err := csc.secureRandom(commKey); err != nil {
		return fmt.Errorf("failed to generate communication key: %v", err)
	}

	csc.shards[id] = &Shard{
		ID:      id,
		Nodes:   nodes,
		CommKey: commKey,
	}
	return nil
}

// RemoveShard removes a shard from the cross-shard communication system.
func (csc *CrossShardCommunication) RemoveShard(id string) error {
	csc.mu.Lock()
	defer csc.mu.Unlock()

	if _, exists := csc.shards[id]; !exists {
		return errors.New("shard not found")
	}

	delete(csc.shards, id)
	return nil
}

// SendMessage sends a message from one shard to another.
func (csc *CrossShardCommunication) SendMessage(fromShard, toShard string, payload []byte) error {
	csc.mu.RLock()
	defer csc.mu.RUnlock()

	from, exists := csc.shards[fromShard]
	if !exists {
		return errors.New("from shard not found")
	}

	to, exists := csc.shards[toShard]
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
		Hash:      csc.hashMessage(encryptedPayload),
	}

	return csc.send(message)
}

// ReceiveMessage processes a received message.
func (csc *CrossShardCommunication) ReceiveMessage(message Message) ([]byte, error) {
	csc.mu.RLock()
	defer csc.mu.RUnlock()

	shard, exists := csc.shards[message.ToShard]
	if !exists {
		return nil, errors.New("to shard not found")
	}

	if !bytes.Equal(csc.hashMessage(message.Payload), message.Hash) {
		return nil, errors.New("message hash mismatch")
	}

	decryptedPayload, err := encryption_util.DecryptAES(message.Payload, shard.CommKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %v", err)
	}

	return decryptedPayload, nil
}

// hashMessage generates a SHA-256 hash of the given payload.
func (csc *CrossShardCommunication) hashMessage(payload []byte) []byte {
	hash := sha256.Sum256(payload)
	return hash[:]
}

// send handles the actual sending of the message (e.g., network transport).
func (csc *CrossShardCommunication) send(message Message) error {
	// Simulate sending the message over the network.
	// In a real implementation, this would involve network communication.
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	fmt.Printf("Sending message: %s\n", data)
	return nil
}
