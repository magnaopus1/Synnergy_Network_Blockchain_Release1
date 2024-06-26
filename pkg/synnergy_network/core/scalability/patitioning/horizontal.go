package partitioning

import (
	"log"
	"sync"
	"time"
	"errors"
)

// Transaction represents the basic unit of blockchain data.
type Transaction struct {
	ID       string
	Data     map[string]interface{}
	PartKey  string // Partition key determines the partition for this transaction
}

// Partition holds a slice of Transactions that are segmented based on a specific criterion.
type Partition struct {
	Transactions []*Transaction
	Lock         sync.Mutex
}

// HorizontalPartitioner manages the distribution of data across multiple partitions.
type HorizontalPartitioner struct {
	Partitions map[string]*Partition
	Lock       sync.RWMutex
}

// NewHorizontalPartitioner creates a new instance of HorizontalPartitioner.
func NewHorizontalPartitioner() *HorizontalPartitioner {
	return &HorizontalPartitioner{
		Partitions: make(map[string]*Partition),
	}
}

// AddTransaction adds a new transaction to the appropriate partition.
func (hp *HorizontalPartitioner) AddTransaction(tx *Transaction) error {
	if tx == nil {
		return errors.New("transaction cannot be nil")
	}

	hp.Lock.Lock()
	defer hp.Lock.Unlock()

	partition, exists := hp.Partitions[tx.PartKey]
	if !exists {
		partition = &Partition{}
		hp.Partitions[tx.PartKey] = partition
	}

	partition.Lock.Lock()
	defer partition.Lock.Unlock()
	partition.Transactions = append(partition.Transactions, tx)
	log.Printf("Transaction added to partition: %s", tx.PartKey)
	return nil
}

// ProcessTransactions processes all transactions within each partition concurrently.
func (hp *HorizontalPartitioner) ProcessTransactions(process func([]*Transaction) error) {
	hp.Lock.RLock()
	defer hp.Lock.RUnlock()

	var wg sync.WaitGroup
	for _, partition := range hp.Partitions {
		wg.Add(1)
		go func(p *Partition) {
			defer wg.Done()
			p.Lock.Lock()
			defer p.Lock.Unlock()
			if err := process(p.Transactions); err != nil {
				log.Printf("Error processing transactions: %v", err)
			}
		}(partition)
	}
	wg.Wait()
}

// RebalancePartitions redistributes transactions across partitions to optimize load, potentially using ML for predictions.
func (hp *HorizontalPartitioner) RebalancePartitions() {
	hp.Lock.Lock()
	defer hp.Lock.Unlock()
	// Example: Simple load rebalancing, more sophisticated methods could involve machine learning predictions
	log.Println("Rebalancing partitions...")
	for key, partition := range hp.Partitions {
		if len(partition.Transactions) > 100 { // Arbitrary threshold for example
			log.Printf("High load detected in partition: %s", key)
			// Redistribution logic here
		}
	}
}

// MonitorAndOptimize continuously adjusts the distribution strategy based on real-time data.
func (hp *HorizontalPartitioner) MonitorAndOptimize() {
	for {
		time.Sleep(1 * time.Minute) // Adjust as needed for less/more frequent adjustments
		hp.RebalancePartitions()
	}
}

func main() {
	hp := NewHorizontalPartitioner()

	// Example of adding transactions
	hp.AddTransaction(&Transaction{ID: "tx1", Data: map[string]interface{}{"amount": 100}, PartKey: "key1"})
	hp.AddTransaction(&Transaction{ID: "tx2", Data: map[string]interface{}{"amount": 200}, PartKey: "key2"})

	// Start the monitoring and optimizing routine
	go hp.MonitorAndOptimize()

	// Process transactions
	hp.ProcessTransactions(func(txs []*Transaction) error {
		// Example processing logic
		for _, tx := range txs {
			log.Printf("Processing transaction ID: %s", tx.ID)
		}
		return nil
	})
}
