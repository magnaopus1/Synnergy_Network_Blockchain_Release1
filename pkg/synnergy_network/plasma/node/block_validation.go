package node

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

// Block represents a block in the blockchain
type Block struct {
    Index        int
    Timestamp    time.Time
    Transactions []child_chain.Transaction
    PrevHash     string
    Hash         string
    Nonce        int
}

// Node represents a node in the blockchain network
type Node struct {
    Blockchain []Block
    mu         sync.Mutex
}

// NewNode creates a new Node
func NewNode() *Node {
    return &Node{
        Blockchain: []Block{},
    }
}

// ValidateBlock validates the given block
func (n *Node) ValidateBlock(block Block) error {
    n.mu.Lock()
    defer n.mu.Unlock()

    if len(n.Blockchain) == 0 {
        if block.Index != 0 {
            return errors.New("invalid genesis block index")
        }
    } else {
        lastBlock := n.Blockchain[len(n.Blockchain)-1]
        if block.Index != lastBlock.Index+1 {
            return errors.New("invalid block index")
        }
        if block.PrevHash != lastBlock.Hash {
            return errors.New("invalid previous block hash")
        }
    }

    if calculateHash(block) != block.Hash {
        return errors.New("invalid block hash")
    }

    return nil
}

// AddBlock adds a block to the blockchain
func (n *Node) AddBlock(block Block) error {
    if err := n.ValidateBlock(block); err != nil {
        return err
    }

    n.mu.Lock()
    defer n.mu.Unlock()

    n.Blockchain = append(n.Blockchain, block)
    return nil
}

// calculateHash calculates the hash of a block
func calculateHash(block Block) string {
    record := fmt.Sprintf("%d%s%d%s", block.Index, block.Timestamp, block.Nonce, block.PrevHash)
    for _, tx := range block.Transactions {
        record += tx.Hash
    }
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil))
}

// CreateGenesisBlock creates the genesis block
func CreateGenesisBlock() Block {
    genesisBlock := Block{
        Index:        0,
        Timestamp:    time.Now(),
        Transactions: []child_chain.Transaction{},
        PrevHash:     "",
        Hash:         "",
        Nonce:        0,
    }
    genesisBlock.Hash = calculateHash(genesisBlock)
    return genesisBlock
}

// ProofOfWork performs the proof of work algorithm
func (n *Node) ProofOfWork(block Block, difficulty int) Block {
    prefix := ""
    for i := 0; i < difficulty; i++ {
        prefix += "0"
    }

    for {
        block.Nonce++
        hash := calculateHash(block)
        if hash[:difficulty] == prefix {
            block.Hash = hash
            break
        }
    }
    return block
}

// ValidateBlockchain validates the entire blockchain
func (n *Node) ValidateBlockchain() error {
    n.mu.Lock()
    defer n.mu.Unlock()

    for i, block := range n.Blockchain {
        if i > 0 {
            if err := n.ValidateBlock(block); err != nil {
                return err
            }
        }
    }
    return nil
}
