package node

import (
    "log"
    "os"
    "sync"

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
    Address          string
    Port             string
}

// NewNode creates a new Node
func NewNode(nodeID, address, port, consensus string, difficulty int) *Node {
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
        Address:          address,
        Port:             port,
    }
}

// InitNode initializes a node with the given configuration file
func InitNode(configFile string) (*Node, error) {
    config, err := LoadConfig(configFile)
    if err != nil {
        return nil, err
    }

    node := NewNodeFromConfig(config)
    if err := node.ValidateConfig(); err != nil {
        return nil, err
    }

    // Create genesis block if blockchain is empty
    if len(node.Blockchain) == 0 {
        genesisBlock := CreateGenesisBlock()
        node.Blockchain = append(node.Blockchain, genesisBlock)
    }

    return node, nil
}

// CreateGenesisBlock creates the genesis block for the blockchain
func CreateGenesisBlock() Block {
    return Block{
        Index:        0,
        Timestamp:    time.Now(),
        Transactions: []child_chain.Transaction{},
        PrevHash:     "",
        Hash:         calculateHash(Block{Index: 0, Timestamp: time.Now(), Transactions: []child_chain.Transaction{}, PrevHash: ""}),
        Nonce:        0,
    }
}

// StartNode starts the node and begins listening for connections
func (n *Node) StartNode() {
    go func() {
        if err := n.ListenForMessages(); err != nil {
            log.Fatalf("Failed to start listening for messages: %v", err)
        }
    }()
    log.Printf("Node %s started at %s:%s", n.NodeID, n.Address, n.Port)
}

// SaveNodeState saves the current state of the node to a file
func (n *Node) SaveNodeState(filename string) error {
    data, err := json.MarshalIndent(n, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(filename, data, 0644)
}

// LoadNodeState loads the state of the node from a file
func LoadNodeState(filename string) (*Node, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }

    var node Node
    if err := json.Unmarshal(data, &node); err != nil {
        return nil, err
    }

    return &node, nil
}

// GracefulShutdown performs a graceful shutdown of the node
func (n *Node) GracefulShutdown() {
    log.Printf("Shutting down node %s...", n.NodeID)
    if err := n.SaveNodeState(n.NodeID + "_state.json"); err != nil {
        log.Printf("Failed to save node state: %v", err)
    }
    os.Exit(0)
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
