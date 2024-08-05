package node

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "math/rand"
    "sync"
    "time"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

// Node represents a node in the blockchain network
type Node struct {
    Blockchain       []Block
    Nodes            map[string]*Node
    PendingTxns      []child_chain.Transaction
    Consensus        string
    Difficulty       int
    mu               sync.Mutex
    NodeID           string
    Stake            int
    ValidatorSet     map[string]int
    ValidatorAddress string
}

// NewNode creates a new Node
func NewNode(nodeID string, consensus string, difficulty int) *Node {
    return &Node{
        Blockchain:       []Block{},
        Nodes:            make(map[string]*Node),
        PendingTxns:      []child_chain.Transaction{},
        Consensus:        consensus,
        Difficulty:       difficulty,
        NodeID:           nodeID,
        Stake:            0,
        ValidatorSet:     make(map[string]int),
        ValidatorAddress: "",
    }
}

// ParticipateInConsensus allows a node to participate in the consensus process
func (n *Node) ParticipateInConsensus() error {
    switch n.Consensus {
    case "PoW":
        return n.participateInPoW()
    case "PoS":
        return n.participateInPoS()
    case "PoH":
        return n.participateInPoH()
    default:
        return errors.New("unknown consensus algorithm")
    }
}

// participateInPoW participates in Proof of Work consensus
func (n *Node) participateInPoW() error {
    newBlock := Block{
        Index:        len(n.Blockchain),
        Timestamp:    time.Now(),
        Transactions: n.PendingTxns,
        PrevHash:     n.Blockchain[len(n.Blockchain)-1].Hash,
    }

    minedBlock := n.ProofOfWork(newBlock, n.Difficulty)
    if err := n.AddBlock(minedBlock); err != nil {
        return err
    }

    n.PendingTxns = []child_chain.Transaction{}
    return nil
}

// participateInPoS participates in Proof of Stake consensus
func (n *Node) participateInPoS() error {
    selectedValidator, err := n.selectValidator()
    if err != nil {
        return err
    }

    if selectedValidator == n.NodeID {
        newBlock := Block{
            Index:        len(n.Blockchain),
            Timestamp:    time.Now(),
            Transactions: n.PendingTxns,
            PrevHash:     n.Blockchain[len(n.Blockchain)-1].Hash,
        }

        newBlock.Hash = calculateHash(newBlock)
        if err := n.AddBlock(newBlock); err != nil {
            return err
        }

        n.PendingTxns = []child_chain.Transaction{}
    }

    return nil
}

// participateInPoH participates in Proof of History consensus
func (n *Node) participateInPoH() error {
    newBlock := Block{
        Index:        len(n.Blockchain),
        Timestamp:    time.Now(),
        Transactions: n.PendingTxns,
        PrevHash:     n.Blockchain[len(n.Blockchain)-1].Hash,
    }

    historyProof := n.generateProofOfHistory(newBlock)
    newBlock.Hash = calculateHash(newBlock) + historyProof

    if err := n.AddBlock(newBlock); err != nil {
        return err
    }

    n.PendingTxns = []child_chain.Transaction{}
    return nil
}

// selectValidator selects a validator for Proof of Stake consensus
func (n *Node) selectValidator() (string, error) {
    n.mu.Lock()
    defer n.mu.Unlock()

    totalStake := 0
    for _, stake := range n.ValidatorSet {
        totalStake += stake
    }

    if totalStake == 0 {
        return "", errors.New("no validators available")
    }

    rand.Seed(time.Now().UnixNano())
    randValue := rand.Intn(totalStake)

    cumulativeStake := 0
    for validator, stake := range n.ValidatorSet {
        cumulativeStake += stake
        if cumulativeStake > randValue {
            return validator, nil
        }
    }

    return "", errors.New("validator selection failed")
}

// generateProofOfHistory generates a proof of history for a block
func (n *Node) generateProofOfHistory(block Block) string {
    history := ""
    for i := 0; i < n.Difficulty; i++ {
        record := fmt.Sprintf("%d%s%d%s", block.Index, block.Timestamp, block.Nonce, block.PrevHash)
        hash := sha256.New()
        hash.Write([]byte(record + history))
        history = hex.EncodeToString(hash.Sum(nil))
    }
    return history
}

// AddNode adds a new node to the network
func (n *Node) AddNode(nodeID string, node *Node) {
    n.mu.Lock()
    defer n.mu.Unlock()

    n.Nodes[nodeID] = node
}

// RemoveNode removes a node from the network
func (n *Node) RemoveNode(nodeID string) {
    n.mu.Lock()
    defer n.mu.Unlock()

    delete(n.Nodes, nodeID)
}

// AddTransaction adds a new transaction to the pending transactions pool
func (n *Node) AddTransaction(tx child_chain.Transaction) {
    n.mu.Lock()
    defer n.mu.Unlock()

    n.PendingTxns = append(n.PendingTxns, tx)
}

// GetPendingTransactions retrieves all pending transactions
func (n *Node) GetPendingTransactions() []child_chain.Transaction {
    n.mu.Lock()
    defer n.mu.Unlock()

    return n.PendingTxns
}

// AddValidator adds a new validator to the validator set
func (n *Node) AddValidator(validatorID string, stake int) {
    n.mu.Lock()
    defer n.mu.Unlock()

    n.ValidatorSet[validatorID] = stake
}

// RemoveValidator removes a validator from the validator set
func (n *Node) RemoveValidator(validatorID string) {
    n.mu.Lock()
    defer n.mu.Unlock()

    delete(n.ValidatorSet, validatorID)
}
