package sharding

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/synnergy_network/encryption_util"
	"github.com/synnergy_network/error_handling_util"
	"github.com/synnergy_network/logging_util"
)

// Shard represents a shard in the blockchain network.
type Shard struct {
	ID       string
	Nodes    []Node
	State    map[string]string // key-value store for state
	CommKey  []byte
	StateMux sync.RWMutex
}

// Node represents a node in the blockchain network.
type Node struct {
	ID    string
	Shard string
}

// StateSharding handles state sharding operations in the blockchain network.
type StateSharding struct {
	shards map[string]*Shard
	mu     sync.RWMutex
}

// NewStateSharding initializes a new StateSharding instance.
func NewStateSharding() *StateSharding {
	return &StateSharding{
		shards: make(map[string]*Shard),
	}
}

// AddShard adds a new shard to the network.
func (ss *StateSharding) AddShard(id string, nodes []Node) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if _, exists := ss.shards[id]; exists {
		return errors.New("shard already exists")
	}

	commKey := make([]byte, 32)
	if _, err := encryption_util.SecureRandom(commKey); err != nil {
		return fmt.Errorf("failed to generate communication key: %v", err)
	}

	ss.shards[id] = &Shard{
		ID:      id,
		Nodes:   nodes,
		State:   make(map[string]string),
		CommKey: commKey,
	}

	return nil
}

// RemoveShard removes a shard from the network.
func (ss *StateSharding) RemoveShard(id string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if _, exists := ss.shards[id]; !exists {
		return errors.New("shard not found")
	}

	delete(ss.shards, id)
	return nil
}

// GetShard returns a shard by its ID.
func (ss *StateSharding) GetShard(id string) (*Shard, error) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	shard, exists := ss.shards[id]
	if !exists {
		return nil, errors.New("shard not found")
	}

	return shard, nil
}

// ListShards lists all shard IDs in the network.
func (ss *StateSharding) ListShards() []string {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	ids := make([]string, 0, len(ss.shards))
	for id := range ss.shards {
		ids = append(ids, id)
	}

	return ids
}

// SetState sets a key-value pair in the specified shard's state.
func (ss *StateSharding) SetState(shardID, key, value string) error {
	ss.mu.RLock()
	shard, exists := ss.shards[shardID]
	ss.mu.RUnlock()

	if !exists {
		return errors.New("shard not found")
	}

	shard.StateMux.Lock()
	defer shard.StateMux.Unlock()

	encryptedValue, err := ss.encryptState(value, shard.CommKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt state: %v", err)
	}

	shard.State[key] = encryptedValue
	return nil
}

// GetState gets a value by key from the specified shard's state.
func (ss *StateSharding) GetState(shardID, key string) (string, error) {
	ss.mu.RLock()
	shard, exists := ss.shards[shardID]
	ss.mu.RUnlock()

	if !exists {
		return "", errors.New("shard not found")
	}

	shard.StateMux.RLock()
	defer shard.StateMux.RUnlock()

	encryptedValue, exists := shard.State[key]
	if !exists {
		return "", errors.New("state key not found")
	}

	decryptedValue, err := ss.decryptState(encryptedValue, shard.CommKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt state: %v", err)
	}

	return decryptedValue, nil
}

// TransferState transfers state from one shard to another.
func (ss *StateSharding) TransferState(fromShardID, toShardID, key string) error {
	fromShard, err := ss.GetShard(fromShardID)
	if err != nil {
		return err
	}

	toShard, err := ss.GetShard(toShardID)
	if err != nil {
		return err
	}

	fromShard.StateMux.Lock()
	defer fromShard.StateMux.Unlock()

	encryptedValue, exists := fromShard.State[key]
	if !exists {
		return errors.New("state key not found in from shard")
	}

	// Decrypt the state in the context of fromShard
	decryptedValue, err := ss.decryptState(encryptedValue, fromShard.CommKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt state from fromShard: %v", err)
	}

	toShard.StateMux.Lock()
	defer toShard.StateMux.Unlock()

	// Encrypt the state in the context of toShard
	encryptedValue, err = ss.encryptState(decryptedValue, toShard.CommKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt state for toShard: %v", err)
	}

	toShard.State[key] = encryptedValue
	delete(fromShard.State, key)

	return nil
}

// encryptState encrypts state using AES encryption with a given key.
func (ss *StateSharding) encryptState(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decryptState decrypts state using AES encryption with a given key.
func (ss *StateSharding) decryptState(ciphertextHex string, key []byte) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// hash generates a SHA-256 hash of the given input.
func hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// loggingUtil provides basic logging functions.
func loggingUtil(message string) {
	fmt.Println(message)
}

func main() {
	loggingUtil("Starting state sharding example")

	ss := NewStateSharding()

	nodes1 := []Node{{ID: "node1", Shard: "shard1"}, {ID: "node2", Shard: "shard1"}}
	nodes2 := []Node{{ID: "node3", Shard: "shard2"}, {ID: "node4", Shard: "shard2"}}

	if err := ss.AddShard("shard1", nodes1); err != nil {
		loggingUtil(fmt.Sprintf("Error adding shard1: %v", err))
	}

	if err := ss.AddShard("shard2", nodes2); err != nil {
		loggingUtil(fmt.Sprintf("Error adding shard2: %v", err))
	}

	if err := ss.SetState("shard1", "key1", "value1"); err != nil {
		loggingUtil(fmt.Sprintf("Error setting state in shard1: %v", err))
	}

	value, err := ss.GetState("shard1", "key1")
	if err != nil {
		loggingUtil(fmt.Sprintf("Error getting state from shard1: %v", err))
	} else {
		loggingUtil(fmt.Sprintf("Got state from shard1: %s", value))
	}

	if err := ss.TransferState("shard1", "shard2", "key1"); err != nil {
		loggingUtil(fmt.Sprintf("Error transferring state from shard1 to shard2: %v", err))
	}

	value, err = ss.GetState("shard2", "key1")
	if err != nil {
		loggingUtil(fmt.Sprintf("Error getting state from shard2: %v", err))
	} else {
		loggingUtil(fmt.Sprintf("Got state from shard2: %s", value))
	}

	loggingUtil("State sharding example completed")
}
