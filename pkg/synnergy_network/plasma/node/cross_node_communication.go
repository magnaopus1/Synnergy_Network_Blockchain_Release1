package node

import (
    "encoding/json"
    "errors"
    "net"
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

// SendMessage sends a message to another node
func (n *Node) SendMessage(nodeAddress, nodePort, message string) error {
    conn, err := net.Dial("tcp", net.JoinHostPort(nodeAddress, nodePort))
    if err != nil {
        return err
    }
    defer conn.Close()

    _, err = conn.Write([]byte(message))
    return err
}

// ListenForMessages listens for incoming messages from other nodes
func (n *Node) ListenForMessages() error {
    listener, err := net.Listen("tcp", net.JoinHostPort(n.Address, n.Port))
    if err != nil {
        return err
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept()
        if err != nil {
            return err
        }
        go n.handleConnection(conn)
    }
}

// handleConnection handles an incoming connection
func (n *Node) handleConnection(conn net.Conn) {
    defer conn.Close()
    var messageBuffer [1024]byte

    nBytes, err := conn.Read(messageBuffer[:])
    if err != nil {
        return
    }

    message := string(messageBuffer[:nBytes])
    n.processMessage(message)
}

// processMessage processes a received message
func (n *Node) processMessage(message string) {
    var msg map[string]interface{}
    err := json.Unmarshal([]byte(message), &msg)
    if err != nil {
        return
    }

    msgType, ok := msg["type"].(string)
    if !ok {
        return
    }

    switch msgType {
    case "block":
        var block Block
        if err := json.Unmarshal([]byte(msg["data"].(string)), &block); err != nil {
            return
        }
        n.handleReceivedBlock(block)
    case "transaction":
        var txn child_chain.Transaction
        if err := json.Unmarshal([]byte(msg["data"].(string)), &txn); err != nil {
            return
        }
        n.handleReceivedTransaction(txn)
    }
}

// handleReceivedBlock handles a block received from another node
func (n *Node) handleReceivedBlock(block Block) {
    if err := n.ValidateBlock(block); err == nil {
        n.AddBlock(block)
        n.BroadcastBlock(block)
    }
}

// handleReceivedTransaction handles a transaction received from another node
func (n *Node) handleReceivedTransaction(txn child_chain.Transaction) {
    n.AddTransaction(txn)
    n.BroadcastTransaction(txn)
}

// BroadcastBlock broadcasts a block to all connected nodes
func (n *Node) BroadcastBlock(block Block) {
    msg := map[string]interface{}{
        "type": "block",
        "data": block,
    }
    message, _ := json.Marshal(msg)
    for _, node := range n.Nodes {
        go n.SendMessage(node.Address, node.Port, string(message))
    }
}

// BroadcastTransaction broadcasts a transaction to all connected nodes
func (n *Node) BroadcastTransaction(txn child_chain.Transaction) {
    msg := map[string]interface{}{
        "type": "transaction",
        "data": txn,
    }
    message, _ := json.Marshal(msg)
    for _, node := range n.Nodes {
        go n.SendMessage(node.Address, node.Port, string(message))
    }
}

// SyncBlockchain syncs the blockchain with a given node
func (n *Node) SyncBlockchain(node *Node) error {
    n.mu.Lock()
    defer n.mu.Unlock()

    if len(node.Blockchain) > len(n.Blockchain) {
        n.Blockchain = node.Blockchain
    }

    return nil
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
