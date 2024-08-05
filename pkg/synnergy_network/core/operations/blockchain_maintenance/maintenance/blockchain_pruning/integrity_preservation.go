package blockchain_pruning

import (
	"crypto/sha256"
	"errors"
	"log"
	"sync"

	"github.com/synnergy_network/encryption_utils"
	"github.com/synnergy_network/blockchain"
	"github.com/synnergy_network/consensus"
)

// ConsistencyChecker defines the structure for performing consistency checks on the blockchain
type ConsistencyChecker struct {
	blockchain *blockchain.Blockchain
	mu         sync.Mutex
}

// NewConsistencyChecker initializes a new ConsistencyChecker
func NewConsistencyChecker(bc *blockchain.Blockchain) *ConsistencyChecker {
	return &ConsistencyChecker{blockchain: bc}
}

// VerifyHashChain verifies that the hash chain of blocks is consistent
func (cc *ConsistencyChecker) VerifyHashChain() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	blocks := cc.blockchain.GetAllBlocks()
	for i := 1; i < len(blocks); i++ {
		if blocks[i].PreviousHash != blocks[i-1].Hash {
			log.Printf("Hash chain broken between block %d and block %d", i-1, i)
			return errors.New("hash chain verification failed")
		}
	}
	log.Println("Hash chain verification passed")
	return nil
}

// VerifyMerkleTrees verifies the Merkle trees of transactions in each block
func (cc *ConsistencyChecker) VerifyMerkleTrees() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	blocks := cc.blockchain.GetAllBlocks()
	for _, block := range blocks {
		if !block.VerifyMerkleRoot() {
			log.Printf("Merkle tree verification failed for block %d", block.Index)
			return errors.New("merkle tree verification failed")
		}
	}
	log.Println("Merkle tree verification passed")
	return nil
}

// VerifyStateConsistency verifies the global state consistency with transactions
func (cc *ConsistencyChecker) VerifyStateConsistency() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	state := cc.blockchain.GetGlobalState()
	blocks := cc.blockchain.GetAllBlocks()

	for _, block := range blocks {
		for _, tx := range block.Transactions {
			if !state.ApplyTransaction(tx) {
				log.Printf("State inconsistency found in block %d, transaction %s", block.Index, tx.ID)
				return errors.New("state consistency verification failed")
			}
		}
	}
	log.Println("State consistency verification passed")
	return nil
}

// VerifyBlockSignatures verifies that all block signatures are valid
func (cc *ConsistencyChecker) VerifyBlockSignatures() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	blocks := cc.blockchain.GetAllBlocks()
	for _, block := range blocks {
		if !consensus.VerifyBlockSignature(block) {
			log.Printf("Invalid block signature found in block %d", block.Index)
			return errors.New("block signature verification failed")
		}
	}
	log.Println("Block signature verification passed")
	return nil
}

// VerifyRedundantData checks for any redundant or duplicate data within the blockchain
func (cc *ConsistencyChecker) VerifyRedundantData() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	dataSet := make(map[string]bool)
	blocks := cc.blockchain.GetAllBlocks()

	for _, block := range blocks {
		blockDataHash := sha256.Sum256([]byte(block.String()))
		if dataSet[string(blockDataHash[:])] {
			log.Printf("Redundant data found in block %d", block.Index)
			return errors.New("redundant data verification failed")
		}
		dataSet[string(blockDataHash[:])] = true
	}
	log.Println("No redundant data found")
	return nil
}

// PerformAllChecks runs all consistency checks
func (cc *ConsistencyChecker) PerformAllChecks() error {
	if err := cc.VerifyHashChain(); err != nil {
		return err
	}
	if err := cc.VerifyMerkleTrees(); err != nil {
		return err
	}
	if err := cc.VerifyStateConsistency(); err != nil {
		return err
	}
	if err := cc.VerifyBlockSignatures(); err != nil {
		return err
	}
	if err := cc.VerifyRedundantData(); err != nil {
		return err
	}
	log.Println("All consistency checks passed")
	return nil
}
