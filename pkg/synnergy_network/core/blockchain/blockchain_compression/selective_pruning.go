package blockchain_compression

import (
	"errors"
	"time"
)

// Block represents a blockchain block.
type Block struct {
	Index        int
	PreviousHash string
	Timestamp    int64
	Data         string
	Hash         string
	Prunable     bool
}

// Blockchain represents the blockchain.
type Blockchain struct {
	Blocks []*Block
}

// NewBlock creates a new block.
func NewBlock(index int, previousHash, data string, prunable bool) *Block {
	return &Block{
		Index:        index,
		PreviousHash: previousHash,
		Timestamp:    time.Now().Unix(),
		Data:         data,
		Hash:         CalculateHash(index, previousHash, data),
		Prunable:     prunable,
	}
}

// CalculateHash calculates the hash of a block.
func CalculateHash(index int, previousHash, data string) string {
	// Implement a suitable hash function
	// Example: return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d%s%s", index, previousHash, data))))
	return ""
}

// AddBlock adds a block to the blockchain.
func (bc *Blockchain) AddBlock(block *Block) {
	bc.Blocks = append(bc.Blocks, block)
}

// PruneBlock prunes a block from the blockchain.
func (bc *Blockchain) PruneBlock(index int) error {
	if index < 0 || index >= len(bc.Blocks) {
		return errors.New("block index out of range")
	}
	if !bc.Blocks[index].Prunable {
		return errors.New("block is not prunable")
	}
	bc.Blocks = append(bc.Blocks[:index], bc.Blocks[index+1:]...)
	return nil
}

// SelectivePruning selectively prunes prunable blocks based on a condition.
func (bc *Blockchain) SelectivePruning(condition func(*Block) bool) {
	for i := len(bc.Blocks) - 1; i >= 0; i-- {
		block := bc.Blocks[i]
		if block.Prunable && condition(block) {
			bc.PruneBlock(i)
		}
	}
}

// Condition example: prune blocks older than 30 days
func PruneOlderThan30Days(block *Block) bool {
	return time.Now().Unix()-block.Timestamp > 30*24*60*60
}

// AdaptiveCompressionThreshold dynamically adjusts the compression threshold based on network conditions.
func AdaptiveCompressionThreshold(blocks []*Block, networkLoad int) ([]*Block, error) {
	if networkLoad < 0 || networkLoad > 100 {
		return nil, errors.New("invalid network load value")
	}

	compressedBlocks := make([]*Block, 0, len(blocks))
	for _, block := range blocks {
		if networkLoad < 50 {
			compressedBlock, err := CompressBlock(block)
			if err != nil {
				return nil, err
			}
			decompressedBlock, err := DecompressBlock(compressedBlock)
			if err != nil {
				return nil, err
			}
			compressedBlocks = append(compressedBlocks, decompressedBlock)
		} else {
			compressedBlocks = append(compressedBlocks, block)
		}
	}

	return compressedBlocks, nil
}
