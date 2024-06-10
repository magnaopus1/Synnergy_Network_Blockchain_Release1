package chain

import (
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "errors"
    "time"

    "synthron_blockchain/crypto" // Assume a package that handles cryptographic functions
)

type Block struct {
    Index     int
    Timestamp int64
    Data      []byte
    PrevHash  string
    Hash      string
    Nonce     int
}

type Blockchain struct {
    blocks []*Block
    mutex  sync.RWMutex
}

func NewBlockchain() *Blockchain {
    genesisBlock := &Block{
        Index:     0,
        Timestamp: time.Now().Unix(),
        Data:      []byte("genesis block"),
        PrevHash:  "",
    }
    genesisBlock.Hash = calculateHash(genesisBlock)

    return &Blockchain{
        blocks: []*Block{genesisBlock},
    }
}

func calculateHash(block *Block) string {
    record := string(block.Index) + string(block.Timestamp) + string(block.Data) + block.PrevHash
    hash := sha256.Sum256([]byte(record))
    return hex.EncodeToString(hash[:])
}

func (bc *Blockchain) AddBlock(data []byte) error {
    bc.mutex.Lock()
    defer bc.mutex.Unlock()

    lastBlock := bc.blocks[len(bc.blocks)-1]
    newBlock := &Block{
        Index:     lastBlock.Index + 1,
        Timestamp: time.Now().Unix(),
        Data:      data,
        PrevHash:  lastBlock.Hash,
    }
    newBlock.Hash = calculateHash(newBlock)
    if !bc.isValidNewBlock(newBlock, lastBlock) {
        return errors.New("invalid block")
    }

    bc.blocks = append(bc.blocks, newBlock)
    return nil
}

func (bc *Blockchain) isValidNewBlock(newBlock, lastBlock *Block) bool {
    if lastBlock.Index+1 != newBlock.Index {
        return false
    }
    if lastBlock.Hash != newBlock.PrevHash {
        return false
    }
    if calculateHash(newBlock) != newBlock.Hash {
        return false
    }
    return true
}

func (bc *Blockchain) ValidateChain() bool {
    for i := 1; i < len(bc.blocks); i++ {
        if !bc.isValidNewBlock(bc.blocks[i], bc.blocks[i-1]) {
            return false
        }
    }
    return true
}

// Implementation for decentralized governance and consensus (Proof of Work, Proof of Stake)
// Additional security features and optimizations

