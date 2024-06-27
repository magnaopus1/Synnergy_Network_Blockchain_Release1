package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
	"synthron-blockchain/pkg/synnergy_network/core/common"
)

// BlockPropagator manages the propagation of blocks in the network using PoH.
type BlockPropagator struct {
	Chain *common.Blockchain
	lock  sync.Mutex
}

// NewBlockPropagator initializes a new BlockPropagator.
func NewBlockPropagator(chain *common.Blockchain) *BlockPropagator {
	return &BlockPropagator{Chain: chain}
}

// PropagateBlock handles the propagation of a new block to the blockchain.
func (bp *BlockPropagator) PropagateBlock(block *common.Block) error {
	bp.lock.Lock()
	defer bp.lock.Unlock()

	// Validate block before propagation
	if err := bp.validateBlockForPropagation(block); err != nil {
		return err
	}

	// Append to blockchain
	bp.Chain.Blocks = append(bp.Chain.Blocks, block)
	fmt.Println("Block propagated successfully:", block.Hash)
	return nil
}

// validateBlockForPropagation ensures the block is valid for propagation.
func (bp *BlockPropagator) validateBlockForPropagation(block *common.Block) error {
	if len(bp.Chain.Blocks) > 0 {
		lastBlock := bp.Chain.Blocks[len(bp.Chain.Blocks)-1]
		if lastBlock.Hash != block.PrevBlockHash {
			return fmt.Errorf("block propagation failed: previous hash does not match")
		}
	}

	// Ensure the block's timestamp is valid and follows PoH rules
	if !bp.isValidTimestamp(block.Timestamp) {
		return fmt.Errorf("block propagation failed: invalid timestamp")
	}

	return nil
}

// isValidTimestamp checks if the block's timestamp adheres to the PoH rules.
func (bp *BlockPropagator) isValidTimestamp(timestamp int64) bool {
	// Ensure the timestamp is greater than the last block and within a reasonable drift
	lastBlockTime := bp.Chain.Blocks[len(bp.Chain.Blocks)-1].Timestamp
	return timestamp > lastBlockTime && time.Since(time.Unix(timestamp, 0)) < 2*time.Minute
}

// CalculateBlockHash calculates the hash of a block using PoH specified hash function.
func CalculateBlockHash(block *common.Block) string {
	record := fmt.Sprintf("%d:%s:%d", block.Timestamp, block.PrevBlockHash, block.Nonce)
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// GenerateMerkleRoot generates a Merkle root for the transactions in a block.
func GenerateMerkleRoot(transactions []*common.Transaction) string {
	// Placeholder for Merkle root generation
	return "merkle_root"
}

// CryptographicAnchor generates a cryptographic anchor for a block.
func CryptographicAnchor(block *common.Block) string {
	// Placeholder for anchor generation based on PoH mechanism
	return "cryptographic_anchor"
}
