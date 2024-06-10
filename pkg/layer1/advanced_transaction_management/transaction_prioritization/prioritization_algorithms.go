package transaction_prioritization

import (
	"crypto/sha256"
	"sort"
	"sync"
	"time"
)

// Transaction defines the structure of a blockchain transaction.
type Transaction struct {
	ID        string    `json:"id"`
	Fee       float64   `json:"fee"`
	Timestamp time.Time `json:"timestamp"`
	Urgency   int       `json:"urgency"` // Custom urgency indicator, higher means more urgent
	Size      int       `json:"size"`    // Size of the transaction in bytes
}

// Prioritizer manages the prioritization of transactions.
type Prioritizer struct {
	transactions []*Transaction
	lock         sync.RWMutex
}

// NewPrioritizer creates a new Prioritizer.
func NewPrioritizer() *Prioritizer {
	return &Prioritizer{
		transactions: []*Transaction{},
	}
}

// AddTransaction adds a new transaction to the pool.
func (p *Prioritizer) AddTransaction(tx *Transaction) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.transactions = append(p.transactions, tx)
}

// Prioritize uses a complex algorithm to reorder the transactions based on multiple factors.
func (p *Prioritizer) Prioritize() {
	p.lock.Lock()
	defer p.lock.Unlock()

	sort.Slice(p.transactions, func(i, j int) bool {
		// Primary sort by urgency
		if p.transactions[i].Urgency != p.transactions[j].Urgency {
			return p.transactions[i].Urgency > p.transactions[j].Urgency
		}
		// Secondary sort by fee, normalized by size (fee per byte)
		feePerByteI := p.transactions[i].Fee / float64(p.transactions[i].Size)
		feePerByteJ := p.transactions[j].Fee / float64(p.transactions[j].Size)
		return feePerByteI > feePerByteJ
	})
}

// HashTransactions creates a hash of all transactions, used for integrity verification.
func (p *Prioritizer) HashTransactions() ([]byte, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	var txData []byte
	for _, tx := range p.transactions {
		txData = append(txData, tx.ID...)
	}

	hash := sha256.Sum256(txData)
	return hash[:], nil
}

// Additional functionality can be developed to handle custom prioritization rules.
