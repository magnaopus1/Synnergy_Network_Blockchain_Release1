package sharding

import (
	"sync"
	"errors"
	"log"
)

// Shard represents a distinct segment of the blockchain's data.
type Shard struct {
	ID              int
	Transactions    []*Transaction
	State           map[string]interface{}
	lock            sync.RWMutex
}

// Transaction models a blockchain transaction that will be stored in a shard.
type Transaction struct {
	ID       string
	Data     map[string]interface{}
}

// ShardManager handles the operations and lifecycle of all shards within the blockchain.
type ShardManager struct {
	Shards          map[int]*Shard
	shardLock       sync.RWMutex
	nextShardID     int
}

// NewShardManager initializes a ShardManager with an optional initial set of shards.
func NewShardManager() *ShardManager {
	return &ShardManager{
		Shards:      make(map[int]*Shard),
		nextShardID: 0,
	}
}

// CreateShard creates a new shard with an automatic ID and no initial transactions.
func (sm *ShardManager) CreateShard() *Shard {
	sm.shardLock.Lock()
	defer sm.shardLock.Unlock()
	shard := &Shard{
		ID:           sm.nextShardID,
		Transactions: []*Transaction{},
		State:        make(map[string]interface{}),
	}
	sm.Shards[shard.ID] = shard
	sm.nextShardID++
	return shard
}

// RemoveShard safely removes a shard if it is empty.
func (sm *ShardManager) RemoveShard(shardID int) error {
	sm.shardLock.Lock()
	defer sm.shardLock.Unlock()
	shard, exists := sm.Shards[shardID]
	if !exists {
		return errors.New("shard does not exist")
	}
	if len(shard.Transactions) > 0 {
		return errors.New("shard is not empty")
	}
	delete(sm.Shards, shardID)
	return nil
}

// MergeShards combines two shards into one, transferring all transactions to the first shard.
func (sm *ShardManager) MergeShards(firstID, secondID int) error {
	sm.shardLock.Lock()
	defer sm.shardLock.Unlock()

	first, ok1 := sm.Shards[firstID]
	second, ok2 := sm.Shards[secondID]
	if !ok1 || !ok2 {
		return errors.New("one or both shards do not exist")
	}

	first.lock.Lock()
	second.lock.Lock()
	defer first.lock.Unlock()
	defer second.lock.Unlock()

	first.Transactions = append(first.Transactions, second.Transactions...)
	first.State = mergeStates(first.State, second.State)
	delete(sm.Shards, secondID)
	return nil
}

// mergeStates combines state data from two shards.
func mergeStates(first, second map[string]interface{}) map[string]interface{} {
	for k, v := range second {
		first[k] = v
	}
	return first
}

// SplitShard divides a shard into two based on a criterion (not implemented here).
func (sm *ShardManager) SplitShard(shardID int) error {
	// Placeholder for splitting logic
	return nil
}

// HandleShardOperations demonstrates how to create, merge, and manage shards.
func HandleShardOperations(sm *ShardManager) {
	shard1 := sm.CreateShard()
	shard2 := sm.CreateShard()

	// Add transactions to shards (not shown here)
	// ...

	if err := sm.MergeShards(shard1.ID, shard2.ID); err != nil {
		log.Printf("Failed to merge shards: %v", err)
	}

	// More operations such as splitting shards can be called here.
}

func main() {
	sm := NewShardManager()
	HandleShardOperations(sm)
}
