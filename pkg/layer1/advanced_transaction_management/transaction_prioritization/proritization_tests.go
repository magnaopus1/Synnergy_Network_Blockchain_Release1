package transaction_prioritization

import (
	"testing"
	"time"
)

// TestPrioritizerAddTransaction tests the addition of transactions to the prioritizer.
func TestPrioritizerAddTransaction(t *testing.T) {
	p := NewPrioritizer()
	tx := &Transaction{
		ID:        "tx1",
		Fee:       1.0,
		Timestamp: time.Now(),
		Urgency:   5,
		Size:      250,
	}
	p.AddTransaction(tx)

	if len(p.transactions) != 1 {
		t.Errorf("Expected 1 transaction, got %d", len(p.transactions))
	}
}

// TestPrioritizerPrioritizationLogic tests the prioritization logic.
func TestPrioritizerPrioritizationLogic(t *testing.T) {
	p := NewPrioritizer()
	tx1 := &Transaction{
		ID:        "tx1",
		Fee:       1.0,
		Timestamp: time.Now(),
		Urgency:   3,
		Size:      300,
	}
	tx2 := &Transaction{
		ID:        "tx2",
		Fee:       2.0,
		Timestamp: time.Now().Add(-10 * time.Minute),
		Urgency:   2,
		Size:      200,
	}
	p.AddTransaction(tx1)
	p.AddTransaction(tx2)

	p.Prioritize()

	if p.transactions[0].ID != "tx1" {
		t.Errorf("Expected tx1 to be prioritized first, but got %s", p.transactions[0].ID)
	}
}

// TestTransactionHashing tests the integrity of transaction hashing.
func TestTransactionHashing(t *testing.T) {
	p := NewPrioritizer()
	tx := &Transaction{
		ID:        "tx1",
		Fee:       1.0,
		Timestamp: time.Now(),
		Urgency:   5,
		Size:      250,
	}
	p.AddTransaction(tx)

	hash, err := p.HashTransactions()
	if err != nil {
		t.Errorf("Error hashing transactions: %v", err)
	}
	if len(hash) == 0 {
		t.Errorf("Expected a hash value, got empty")
	}
}

// Additional tests could include concurrency tests, testing with larger datasets, and edge cases.
