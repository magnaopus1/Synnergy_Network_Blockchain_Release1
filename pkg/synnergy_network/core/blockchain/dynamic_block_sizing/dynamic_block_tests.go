package dynamic_block_sizing

import (
	"sync"
	"testing"
	"time"
)

// MockConsensus is a mock implementation of the ConsensusInterface for testing purposes.
type MockConsensus struct {
	ProposedSizes []int
}

func (mc *MockConsensus) ProposeBlockSizeChange(newSize int) bool {
	mc.ProposedSizes = append(mc.ProposedSizes, newSize)
	return true
}

func TestDynamicBlockSizer(t *testing.T) {
	initialBlockSize := 1000
	maxBlockSize := 5000
	minBlockSize := 500
	adjustInterval := 1 * time.Second
	mockConsensus := &MockConsensus{}

	dbs := NewDynamicBlockSizer(initialBlockSize, maxBlockSize, minBlockSize, adjustInterval, mockConsensus)
	dbs.Start()

	// Simulate transaction loads
	go func() {
		for i := 0; i < 10; i++ {
			dbs.UpdateTransactionLoad(1200)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	time.Sleep(2 * time.Second)

	currentBlockSize := dbs.GetCurrentBlockSize()
	if currentBlockSize <= initialBlockSize {
		t.Errorf("Expected block size to increase, got %d", currentBlockSize)
	}

	if len(mockConsensus.ProposedSizes) == 0 {
		t.Errorf("Expected proposed block sizes, but got none")
	}
}

func TestAdaptiveBlockSize(t *testing.T) {
	initialBlockSize := 1000
	maxBlockSize := 5000
	minBlockSize := 500
	adjustInterval := 1 * time.Second
	mockConsensus := &MockConsensus{}

	dbs := NewDynamicBlockSizer(initialBlockSize, maxBlockSize, minBlockSize, adjustInterval, mockConsensus)
	dbs.Start()

	tests := []struct {
		avgLoad       int
		expectedSize  int
	}{
		{1200, 2000}, // Load is high, increase block size
		{300, 500},   // Load is low, decrease block size
		{700, 1000},  // Load is moderate, keep block size
	}

	for _, test := range tests {
		newSize := dbs.adaptiveBlockSize(test.avgLoad)
		if newSize != test.expectedSize {
			t.Errorf("For avgLoad %d, expected block size %d, but got %d", test.avgLoad, test.expectedSize, newSize)
		}
	}
}

func TestUpdateTransactionLoad(t *testing.T) {
	initialBlockSize := 1000
	maxBlockSize := 5000
	minBlockSize := 500
	adjustInterval := 1 * time.Second
	mockConsensus := &MockConsensus{}

	dbs := NewDynamicBlockSizer(initialBlockSize, maxBlockSize, minBlockSize, adjustInterval, mockConsensus)
	dbs.Start()

	dbs.UpdateTransactionLoad(1200)
	time.Sleep(100 * time.Millisecond)

	if len(dbs.transactionLoad) != 1 {
		t.Errorf("Expected transaction load length to be 1, but got %d", len(dbs.transactionLoad))
	}
}

func TestGetCurrentBlockSize(t *testing.T) {
	initialBlockSize := 1000
	maxBlockSize := 5000
	minBlockSize := 500
	adjustInterval := 1 * time.Second
	mockConsensus := &MockConsensus{}

	dbs := NewDynamicBlockSizer(initialBlockSize, maxBlockSize, minBlockSize, adjustInterval, mockConsensus)
	dbs.Start()

	if dbs.GetCurrentBlockSize() != initialBlockSize {
		t.Errorf("Expected current block size to be %d, but got %d", initialBlockSize, dbs.GetCurrentBlockSize())
	}

	dbs.mu.Lock()
	dbs.currentBlockSize = 2000
	dbs.mu.Unlock()

	if dbs.GetCurrentBlockSize() != 2000 {
		t.Errorf("Expected current block size to be 2000, but got %d", dbs.GetCurrentBlockSize())
	}
}
