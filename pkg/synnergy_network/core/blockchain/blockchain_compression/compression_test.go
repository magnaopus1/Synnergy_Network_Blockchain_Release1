package blockchain_compression

import (
	"testing"
	"time"
)

// TestNewBlock ensures the creation of a new block is accurate.
func TestNewBlock(t *testing.T) {
	block := NewBlock(1, "previousHash", "data", true)
	if block.Index != 1 {
		t.Errorf("Expected block index 1, got %d", block.Index)
	}
	if block.PreviousHash != "previousHash" {
		t.Errorf("Expected previous hash 'previousHash', got %s", block.PreviousHash)
	}
	if block.Data != "data" {
		t.Errorf("Expected block data 'data', got %s", block.Data)
	}
	if block.Prunable != true {
		t.Errorf("Expected block prunable true, got %v", block.Prunable)
	}
}

// TestAddBlock ensures adding a block to the blockchain is successful.
func TestAddBlock(t *testing.T) {
	blockchain := &Blockchain{}
	block := NewBlock(1, "previousHash", "data", true)
	blockchain.AddBlock(block)
	if len(blockchain.Blocks) != 1 {
		t.Errorf("Expected blockchain length 1, got %d", len(blockchain.Blocks))
	}
}

// TestPruneBlock ensures pruning a block works correctly.
func TestPruneBlock(t *testing.T) {
	blockchain := &Blockchain{}
	block := NewBlock(1, "previousHash", "data", true)
	blockchain.AddBlock(block)
	err := blockchain.PruneBlock(0)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(blockchain.Blocks) != 0 {
		t.Errorf("Expected blockchain length 0, got %d", len(blockchain.Blocks))
	}
}

// TestSelectivePruning ensures selective pruning based on condition works.
func TestSelectivePruning(t *testing.T) {
	blockchain := &Blockchain{}
	block1 := NewBlock(1, "previousHash1", "data1", true)
	block2 := NewBlock(2, "previousHash2", "data2", true)
	block3 := NewBlock(3, "previousHash3", "data3", false)
	blockchain.AddBlock(block1)
	blockchain.AddBlock(block2)
	blockchain.AddBlock(block3)

	blockchain.SelectivePruning(func(block *Block) bool {
		return block.Prunable && block.Index == 1
	})

	if len(blockchain.Blocks) != 2 {
		t.Errorf("Expected blockchain length 2, got %d", len(blockchain.Blocks))
	}
	if blockchain.Blocks[0].Index != 2 || blockchain.Blocks[1].Index != 3 {
		t.Errorf("Expected remaining blocks with indices 2 and 3, got %d and %d", blockchain.Blocks[0].Index, blockchain.Blocks[1].Index)
	}
}

// TestPruneOlderThan30Days ensures pruning blocks older than 30 days works.
func TestPruneOlderThan30Days(t *testing.T) {
	blockchain := &Blockchain{}
	oldBlock := &Block{
		Index:        1,
		PreviousHash: "previousHash1",
		Timestamp:    time.Now().Unix() - 31*24*60*60,
		Data:         "data1",
		Hash:         "hash1",
		Prunable:     true,
	}
	newBlock := NewBlock(2, "previousHash2", "data2", true)
	blockchain.AddBlock(oldBlock)
	blockchain.AddBlock(newBlock)

	blockchain.SelectivePruning(PruneOlderThan30Days)

	if len(blockchain.Blocks) != 1 {
		t.Errorf("Expected blockchain length 1, got %d", len(blockchain.Blocks))
	}
	if blockchain.Blocks[0].Index != 2 {
		t.Errorf("Expected remaining block index 2, got %d", blockchain.Blocks[0].Index)
	}
}

// Mock compression and decompression for testing
func CompressBlock(block *Block) (*Block, error) {
	// Simulate compression
	block.Data = "compressed-" + block.Data
	return block, nil
}

func DecompressBlock(block *Block) (*Block, error) {
	// Simulate decompression
	block.Data = block.Data[len("compressed-"):]
	return block, nil
}

// TestAdaptiveCompressionThreshold ensures adaptive compression works correctly.
func TestAdaptiveCompressionThreshold(t *testing.T) {
	blockchain := &Blockchain{}
	block1 := NewBlock(1, "previousHash1", "data1", true)
	block2 := NewBlock(2, "previousHash2", "data2", true)
	blockchain.AddBlock(block1)
	blockchain.AddBlock(block2)

	compressedBlocks, err := AdaptiveCompressionThreshold(blockchain.Blocks, 40)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	for _, block := range compressedBlocks {
		if block.Data[:11] != "compressed-" {
			t.Errorf("Expected compressed data, got %s", block.Data)
		}
	}

	compressedBlocks, err = AdaptiveCompressionThreshold(blockchain.Blocks, 60)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	for _, block := range compressedBlocks {
		if block.Data[:11] == "compressed-" {
			t.Errorf("Did not expect compressed data, got %s", block.Data)
		}
	}
}
