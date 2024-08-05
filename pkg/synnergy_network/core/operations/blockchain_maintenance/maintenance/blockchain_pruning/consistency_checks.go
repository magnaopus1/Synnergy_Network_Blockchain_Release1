package blockchain_pruning

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/synnergy_network/utils"
	"github.com/synnergy_network/core/operations/blockchain"
)

// ConsistencyChecker defines the structure for consistency checks in blockchain pruning.
type ConsistencyChecker struct {
	mutex sync.Mutex
}

// NewConsistencyChecker creates a new instance of ConsistencyChecker.
func NewConsistencyChecker() *ConsistencyChecker {
	return &ConsistencyChecker{}
}

// ValidateBlock validates the integrity of a single block.
func (cc *ConsistencyChecker) ValidateBlock(block blockchain.Block) error {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	// Validate block hash
	if !cc.validateBlockHash(block) {
		return errors.New("invalid block hash")
	}

	// Validate block transactions
	if err := cc.validateBlockTransactions(block); err != nil {
		return err
	}

	// Additional validation logic as required

	log.Printf("Block %d validation passed", block.Header.Height)
	return nil
}

// validateBlockHash validates the hash of a block.
func (cc *ConsistencyChecker) validateBlockHash(block blockchain.Block) bool {
	calculatedHash := cc.calculateBlockHash(block)
	return calculatedHash == block.Header.Hash
}

// calculateBlockHash calculates the hash of a block.
func (cc *ConsistencyChecker) calculateBlockHash(block blockchain.Block) string {
	hashData := fmt.Sprintf("%d%s%s%s",
		block.Header.Height,
		block.Header.PreviousHash,
		block.Header.Timestamp,
		block.Transactions)

	hash := sha256.Sum256([]byte(hashData))
	return fmt.Sprintf("%x", hash)
}

// validateBlockTransactions validates the transactions within a block.
func (cc *ConsistencyChecker) validateBlockTransactions(block blockchain.Block) error {
	for _, tx := range block.Transactions {
		if err := cc.validateTransaction(tx); err != nil {
			return err
		}
	}
	return nil
}

// validateTransaction validates a single transaction.
func (cc *ConsistencyChecker) validateTransaction(tx blockchain.Transaction) error {
	// Add transaction validation logic here
	// Example: check signature, verify inputs/outputs, etc.

	if !cc.verifyTransactionSignature(tx) {
		return errors.New("invalid transaction signature")
	}

	// Additional validation logic as required

	return nil
}

// verifyTransactionSignature verifies the signature of a transaction.
func (cc *ConsistencyChecker) verifyTransactionSignature(tx blockchain.Transaction) bool {
	// Add logic to verify transaction signature
	// This is a placeholder implementation
	return utils.VerifySignature(tx.Inputs[0].PublicKey, tx.Signature, tx.Hash())
}

// ConsistencyCheck performs a comprehensive consistency check on the entire blockchain.
func (cc *ConsistencyChecker) ConsistencyCheck(blockchain blockchain.Blockchain) error {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	for _, block := range blockchain.Blocks {
		if err := cc.ValidateBlock(block); err != nil {
			return fmt.Errorf("block %d failed consistency check: %v", block.Header.Height, err)
		}
	}

	log.Println("Blockchain consistency check passed")
	return nil
}

// PruneAndCheckConsistency performs pruning and consistency checks.
func (cc *ConsistencyChecker) PruneAndCheckConsistency(blockchain blockchain.Blockchain, pruneHeight int) error {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	prunedBlocks := cc.pruneBlockchain(blockchain, pruneHeight)
	if err := cc.consistencyCheckAfterPruning(prunedBlocks); err != nil {
		return err
	}

	log.Println("Pruning and consistency check passed")
	return nil
}

// pruneBlockchain prunes the blockchain up to the specified height.
func (cc *ConsistencyChecker) pruneBlockchain(blockchain blockchain.Blockchain, pruneHeight int) []blockchain.Block {
	prunedBlocks := []blockchain.Block{}
	for _, block := range blockchain.Blocks {
		if block.Header.Height <= pruneHeight {
			prunedBlocks = append(prunedBlocks, block)
		}
	}
	return prunedBlocks
}

// consistencyCheckAfterPruning performs consistency checks on pruned blocks.
func (cc *ConsistencyChecker) consistencyCheckAfterPruning(blocks []blockchain.Block) error {
	for _, block := range blocks {
		if err := cc.ValidateBlock(block); err != nil {
			return fmt.Errorf("block %d failed consistency check after pruning: %v", block.Header.Height, err)
		}
	}
	return nil
}
