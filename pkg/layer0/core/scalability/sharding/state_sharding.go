package sharding

import (
	"sync"
	"errors"
	"hash/fnv"
)

// State represents the state information of a blockchain stored in a shard.
type State struct {
	Data map[string]interface{}
	lock sync.RWMutex
}

// Shard encapsulates a segment of the blockchain, both transactions and state.
type Shard struct {
	ID    int
	State *State
}

// StateShardManager manages the shards and their states.
type StateShardManager struct {
	Shards      map[int]*Shard
	shardLock   sync.RWMutex
	numShards   int
}

// NewStateShardManager creates a manager for handling state across multiple shards.
func NewStateShardManager(numShards int) *StateShardManager {
	ssm := &StateShardManager{
		Shards:    make(map[int]*Shard),
		numShards: numShards,
	}
	for i := 0; i < numShards; i++ {
		ssm.Shards[i] = &Shard{ID: i, State: &State{Data: make(map[string]interface{})}}
	}
	return ssm
}

// GetShardForKey calculates which shard a given key should be placed in.
func (ssm *StateShardManager) GetShardForKey(key string) *Shard {
	hash := fnv.New32()
	hash.Write([]byte(key))
	shardID := int(hash.Sum32()) % ssm.numShards
	return ssm.Shards[shardID]
}

// SetState sets a value in the state of the appropriate shard for the given key.
func (ssm *StateShardManager) SetState(key string, value interface{}) error {
	shard := ssm.GetShardForKey(key)
	shard.State.lock.Lock()
	defer shard.State.lock.Unlock()
	shard.State.Data[key] = value
	return nil
}

// GetState retrieves a value from the state of the appropriate shard for the given key.
func (ssm *StateShardManager) GetState(key string) (interface{}, error) {
	shard := ssm.GetShardForKey(key)
	shard.State.lock.RLock()
	defer shard.State.lock.RUnlock()
	value, exists := shard.State.Data[key]
	if !exists {
		return nil, errors.New("key not found")
	}
	return value, nil
}

// MergeShards combines the state of two shards into one.
func (ssm *StateShardManager) MergeShards(shardID1, shardID2 int) error {
	ssm.shardLock.Lock()
	defer ssm.shardLock.Unlock()

	shard1, ok1 := ssm.Shards[shardID1]
	shard2, ok2 := ssm.Shards[shardID2]
	if !ok1 || !ok2 {
		return errors.New("one or both shards not found")
	}

	shard1.State.lock.Lock()
	shard2.State.lock.Lock()
	defer shard1.State.lock.Unlock()
	defer shard2.State.lock.Unlock()

	// Merge shard2 state into shard1
	for k, v := range shard2.State.Data {
		shard1.State.Data[k] = v
	}
	delete(ssm.Shards, shardID2) // Remove shard2 after merging
	return nil
}

// SplitShard divides the state of a shard based on some criterion (not implemented here).
func (ssm *StateShardManager) SplitShard(shardID int) error {
	// Placeholder for splitting logic
	return nil
}

func main() {
	ssm := NewStateShardManager(4) // Create a state shard manager with 4 shards
	ssm.SetState("user123", "John Doe")
	value, err := ssm.GetState("user123")
	if err != nil {
		panic(err)
	}
	println("Retrieved value:", value)
}
