package finality

import (
    "sync"
    "errors"
)

// Block represents a simplified block structure for the Synnergy Network.
type Block struct {
    Hash      string
    PrevHash  string
    Timestamp int64
    Data      []byte
    Signature []byte // Signature by the block producer
}

// Blockchain represents a sequence of blocks along with the finality specifics.
type Blockchain struct {
    Chain            []*Block
    Checkpoints      map[int]*Block
    FinalizedBlocks  map[int]*Block
    lock             sync.RWMutex
    finalityDepth    int // Depth for deterministic finality in PoS
    checkpointFactor int // Interval at which checkpoints are established
}

// NewBlockchain initializes a new blockchain with given finality parameters.
func NewBlockchain(finalityDepth, checkpointFactor int) *Blockchain {
    return &Blockchain{
        Chain:            make([]*Block, 0),
        Checkpoints:      make(map[int]*Block),
        FinalizedBlocks:  make(map[int]*Block),
        finalityDepth:    finalityDepth,
        checkpointFactor: checkpointFactor,
    }
}

// AddBlock adds a new block to the blockchain and checks for finality conditions.
func (bc *Blockchain) AddBlock(newBlock *Block) error {
    bc.lock.Lock()
    defer bc.lock.Unlock()

    lastBlock := bc.Chain[len(bc.Chain)-1]
    if newBlock.PrevHash != lastBlock.Hash {
        return errors.New("invalid block: previous hash does not match")
    }

    bc.Chain = append(bc.Chain, newBlock)
    bc.evaluateFinality(newBlock)
    return nil
}

// evaluateFinality evaluates blocks for finality conditions.
func (bc *Blockchain) evaluateFinality(block *Block) {
    currentIndex := len(bc.Chain) - 1

    // Checkpointing
    if currentIndex%bc.checkpointFactor == 0 {
        bc.Checkpoints[currentIndex] = block
    }

    // Finalization of blocks using PoS mechanism
    if currentIndex >= bc.finalityDepth {
        finalizedBlock := bc.Chain[currentIndex-bc.finalityDepth]
        bc.FinalizedBlocks[finalizedBlock.Hash] = finalizedBlock
    }
}

// IsFinalized checks if a block is finalized.
func (bc *Blockchain) IsFinalized(blockHash string) bool {
    bc.lock.RLock()
    defer bc.lock.RUnlock()

    _, exists := bc.FinalizedBlocks[blockHash]
    return exists
}

// IsCheckpointed checks if a block is a checkpoint.
func (bc *Blockchain) IsCheckpointed(blockIndex int) bool {
    bc.lock.RLock()
    defer bc.lock.RUnlock()

    _, exists := bc.Checkpoints[blockIndex]
    return exists
}

