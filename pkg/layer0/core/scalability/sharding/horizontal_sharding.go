package sharding

import (
	"sync"
	"errors"
	"math/rand"
	"time"
)

// Transaction represents the basic unit of blockchain data in a specific shard.
type Transaction struct {
	ID       string
	Data     map[string]interface{}
	ShardID  int
}

// Shard holds the data and manages transactions within its boundaries.
type Shard struct {
	ID            int
	Transactions  []*Transaction
	Lock          sync.RWMutex
}

// HorizontalShardManager manages the distribution and processing of data across shards.
type HorizontalShardManager struct {
	Shards        map[int]*Shard
	shardCount    int
	lock          sync.Mutex
}

// NewHorizontalShardManager initializes a new shard manager with a specified number of shards.
func NewHorizontalShardManager(count int) *HorizontalShardManager {
	manager := &HorizontalShardManager{
		Shards:     make(map[int]*Shard),
		shardCount: count,
	}
	for i := 0; i < count; i++ {
		manager.Shards[i] = &Shard{ID: i, Transactions: make([]*Transaction, 0)}
	}
	return manager
}

// AddTransaction assigns a transaction to a shard based on hashing or other criteria.
func (hsm *HorizontalShardManager) AddTransaction(tx *Transaction) error {
	if tx == nil {
		return errors.New("transaction cannot be nil")
	}

	shardID := tx.ShardID % hsm.shardCount // Simple modulo for shard assignment, replace with a robust hash function
	shard := hsm.Shards[shardID]
	shard.Lock.Lock()
	defer shard.Lock.Unlock()
	shard.Transactions = append(shard.Transactions, tx)
	return nil
}

// ProcessShardTransactions processes transactions within each shard concurrently.
func (hsm *HorizontalShardManager) ProcessShardTransactions(process func(tx *Transaction) error) {
	var wg sync.WaitGroup
	for _, shard := range hsm.Shards {
		wg.Add(1)
		go func(s *Shard) {
			defer wg.Done()
			s.Lock.RLock()
			defer s.Lock.RUnlock()
			for _, tx := range s.Transactions {
				if err := process(tx); err != nil {
					// Handle error, e.g., log or retry
				}
			}
		}(shard)
	}
	wg.Wait()
}

// RebalanceShards dynamically adjusts shards to maintain load balance.
func (hsm *HorizontalShardManager) RebalanceShards() {
	// Example of a naive rebalancing, more sophisticated algorithms needed for production
	hsm.lock.Lock()
	defer hsm.lock.Unlock()
	allTxs := make([]*Transaction, 0)
	for _, shard := range hsm.Shards {
		shard.Lock.Lock()
		allTxs = append(allTxs, shard.Transactions...)
		shard.Transactions = shard.Transactions[:0] // Clear shard transactions
		shard.Lock.Unlock()
	}
	for _, tx := range allTxs {
		newShardID := rand.Intn(hsm.shardCount) // Randomly reassign transactions
		hsm.Shards[newShardID].Lock.Lock()
		hsm.Shards[newShardID].Transactions = append(hsm.Shards[newShardID].Transactions, tx)
		hsm.Shards[newShardID].Lock.Unlock()
	}
}

func main() {
	hsm := NewHorizontalShardManager(10) // Create a shard manager with 10 shards

	// Simulate adding transactions
	hsm.AddTransaction(&Transaction{ID: "tx1", Data: map[string]interface{}{"value": 100}, ShardID: 1})
	hsm.AddTransaction(&Transaction{ID: "tx2", Data: map[string]interface{}{"value": 200}, ShardID: 2})

	// Process transactions
	hsm.ProcessShardTransactions(func(tx *Transaction) error {
		// Here, implement the actual processing logic, e.g., validate transaction
		return nil
	})

	// Periodically rebalance shards
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		hsm.RebalanceShards()
	}
}
