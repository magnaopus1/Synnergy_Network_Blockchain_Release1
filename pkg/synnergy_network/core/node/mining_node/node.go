package mining_node

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "math/big"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"
)

// MiningNode represents a node participating in the Proof of Work mining process.
type MiningNode struct {
    ID              string
    Blockchain      *Blockchain
    MiningAddress   string
    CurrentBlock    *Block
    TargetDifficulty *big.Int
    Mutex           sync.Mutex
}

// Block represents a single block in the blockchain.
type Block struct {
    Index         int
    Timestamp     int64
    Transactions  []*Transaction
    PrevHash      string
    Hash          string
    Nonce         int
}

// Transaction represents a single transaction in the blockchain.
type Transaction struct {
    Sender    string
    Recipient string
    Amount    float64
}

// Blockchain represents the blockchain structure.
type Blockchain struct {
    Blocks []*Block
}

// NewMiningNode initializes a new mining node.
func NewMiningNode(id string, miningAddress string, targetDifficulty *big.Int) *MiningNode {
    blockchain := &Blockchain{Blocks: []*Block{genesisBlock()}}
    return &MiningNode{
        ID:              id,
        Blockchain:      blockchain,
        MiningAddress:   miningAddress,
        TargetDifficulty: targetDifficulty,
    }
}

// genesisBlock creates the genesis block for the blockchain.
func genesisBlock() *Block {
    return &Block{
        Index:        0,
        Timestamp:    time.Now().Unix(),
        Transactions: []*Transaction{},
        PrevHash:     "",
        Hash:         "",
        Nonce:        0,
    }
}

// AddTransaction adds a new transaction to the current block.
func (mn *MiningNode) AddTransaction(transaction *Transaction) {
    mn.Mutex.Lock()
    defer mn.Mutex.Unlock()
    mn.CurrentBlock.Transactions = append(mn.CurrentBlock.Transactions, transaction)
}

// StartMining starts the mining process.
func (mn *MiningNode) StartMining() {
    mn.CurrentBlock = &Block{
        Index:        len(mn.Blockchain.Blocks),
        Timestamp:    time.Now().Unix(),
        Transactions: []*Transaction{},
        PrevHash:     mn.Blockchain.Blocks[len(mn.Blockchain.Blocks)-1].Hash,
        Nonce:        0,
    }
    go mn.mine()
}

// mine performs the mining operation.
func (mn *MiningNode) mine() {
    for {
        select {
        case <-time.After(time.Second):
            mn.Mutex.Lock()
            if valid, hash := mn.isValidHash(); valid {
                mn.CurrentBlock.Hash = hash
                mn.Blockchain.Blocks = append(mn.Blockchain.Blocks, mn.CurrentBlock)
                mn.CurrentBlock = &Block{
                    Index:        len(mn.Blockchain.Blocks),
                    Timestamp:    time.Now().Unix(),
                    Transactions: []*Transaction{},
                    PrevHash:     mn.Blockchain.Blocks[len(mn.Blockchain.Blocks)-1].Hash,
                    Nonce:        0,
                }
            } else {
                mn.CurrentBlock.Nonce++
            }
            mn.Mutex.Unlock()
        }
    }
}

// isValidHash checks if the current block's hash is valid.
func (mn *MiningNode) isValidHash() (bool, string) {
    hash := mn.calculateHash(mn.CurrentBlock)
    hashInt := new(big.Int)
    hashInt.SetString(hash, 16)
    if hashInt.Cmp(mn.TargetDifficulty) == -1 {
        return true, hash
    }
    return false, hash
}

// calculateHash calculates the hash for a block.
func (mn *MiningNode) calculateHash(block *Block) string {
    data := string(block.Index) + string(block.Timestamp) + mn.transactionsToString(block.Transactions) + block.PrevHash + string(block.Nonce)
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// transactionsToString converts transactions to a string representation.
func (mn *MiningNode) transactionsToString(transactions []*Transaction) string {
    var str string
    for _, tx := range transactions {
        str += tx.Sender + tx.Recipient + string(tx.Amount)
    }
    return str
}

// HandleInterrupts handles system interrupts for graceful shutdown.
func (mn *MiningNode) HandleInterrupts() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        mn.StopMining()
        os.Exit(0)
    }()
}

// StopMining stops the mining process.
func (mn *MiningNode) StopMining() {
    // Add any cleanup logic if needed.
}

// ValidateTransaction validates a transaction before adding it to the block.
func (mn *MiningNode) ValidateTransaction(tx *Transaction) error {
    if tx.Amount <= 0 {
        return errors.New("invalid transaction amount")
    }
    // Add more validation logic as needed.
    return nil
}

// main function to initialize and start the mining node.
func main() {
    node := NewMiningNode("node1", "mining_address", big.NewInt(1<<16)) // Example difficulty
    node.HandleInterrupts()
    node.StartMining()

    // Add logic to interact with the node, e.g., adding transactions.
}
