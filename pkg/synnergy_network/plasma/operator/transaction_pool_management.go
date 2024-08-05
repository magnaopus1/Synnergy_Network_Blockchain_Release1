package operator

import (
    "container/heap"
    "errors"
    "sync"
    "time"
)

// Transaction represents a blockchain transaction
type Transaction struct {
    ID        string
    Timestamp time.Time
    Data      []byte
    Fee       int64
}

// PriorityQueue implements a priority queue for transactions
type PriorityQueue []*Transaction

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
    // We want the highest fee transactions to be processed first
    return pq[i].Fee > pq[j].Fee
}

func (pq PriorityQueue) Swap(i, j int) {
    pq[i], pq[j] = pq[j], pq[i]
}

func (pq *PriorityQueue) Push(x interface{}) {
    transaction := x.(*Transaction)
    *pq = append(*pq, transaction)
}

func (pq *PriorityQueue) Pop() interface{} {
    old := *pq
    n := len(old)
    item := old[n-1]
    *pq = old[0 : n-1]
    return item
}

// TransactionPool manages transactions waiting to be included in blocks
type TransactionPool struct {
    pool       PriorityQueue
    poolMutex  sync.Mutex
    maxSize    int
    timeWindow time.Duration
}

// NewTransactionPool initializes a new transaction pool
func NewTransactionPool(maxSize int, timeWindow time.Duration) *TransactionPool {
    pq := make(PriorityQueue, 0)
    heap.Init(&pq)
    return &TransactionPool{
        pool:       pq,
        maxSize:    maxSize,
        timeWindow: timeWindow,
    }
}

// AddTransaction adds a new transaction to the pool
func (tp *TransactionPool) AddTransaction(tx *Transaction) error {
    tp.poolMutex.Lock()
    defer tp.poolMutex.Unlock()

    if tp.pool.Len() >= tp.maxSize {
        return errors.New("transaction pool is full")
    }

    heap.Push(&tp.pool, tx)
    return nil
}

// GetTransactionsForBlock retrieves transactions to be included in the next block
func (tp *TransactionPool) GetTransactionsForBlock() []*Transaction {
    tp.poolMutex.Lock()
    defer tp.poolMutex.Unlock()

    var selectedTransactions []*Transaction
    now := time.Now()

    for tp.pool.Len() > 0 {
        tx := heap.Pop(&tp.pool).(*Transaction)
        if now.Sub(tx.Timestamp) <= tp.timeWindow {
            selectedTransactions = append(selectedTransactions, tx)
        }
    }

    return selectedTransactions
}

// RemoveTransaction removes a transaction from the pool by ID
func (tp *TransactionPool) RemoveTransaction(txID string) error {
    tp.poolMutex.Lock()
    defer tp.poolMutex.Unlock()

    for i, tx := range tp.pool {
        if tx.ID == txID {
            heap.Remove(&tp.pool, i)
            return nil
        }
    }

    return errors.New("transaction not found in pool")
}

// PurgeOldTransactions removes transactions that are too old
func (tp *TransactionPool) PurgeOldTransactions() {
    tp.poolMutex.Lock()
    defer tp.poolMutex.Unlock()

    now := time.Now()
    var newPool PriorityQueue

    for tp.pool.Len() > 0 {
        tx := heap.Pop(&tp.pool).(*Transaction)
        if now.Sub(tx.Timestamp) <= tp.timeWindow {
            heap.Push(&newPool, tx)
        }
    }

    tp.pool = newPool
}
