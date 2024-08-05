package node

import (
    "log"
    "time"
    "sync"
    "net/http"
    "encoding/json"
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

// NodeStatus represents the status of the node
type NodeStatus struct {
    NodeID           string `json:"node_id"`
    Address          string `json:"address"`
    Port             string `json:"port"`
    BlockchainLength int    `json:"blockchain_length"`
    PendingTxnsCount int    `json:"pending_txns_count"`
    ValidatorCount   int    `json:"validator_count"`
    Stake            int    `json:"stake"`
    LastBlockHash    string `json:"last_block_hash"`
}

// MonitorNode continuously monitors the node's status
func (n *Node) MonitorNode() {
    ticker := time.NewTicker(10 * time.Second)
    go func() {
        for {
            select {
            case <-ticker.C:
                n.PrintStatus()
            }
        }
    }()
}

// PrintStatus prints the current status of the node
func (n *Node) PrintStatus() {
    status := n.GetStatus()
    data, err := json.MarshalIndent(status, "", "  ")
    if err != nil {
        log.Printf("Failed to marshal status: %v", err)
        return
    }
    log.Println(string(data))
}

// GetStatus retrieves the current status of the node
func (n *Node) GetStatus() NodeStatus {
    n.mu.Lock()
    defer n.mu.Unlock()

    lastBlockHash := ""
    if len(n.Blockchain) > 0 {
        lastBlockHash = n.Blockchain[len(n.Blockchain)-1].Hash
    }

    return NodeStatus{
        NodeID:           n.NodeID,
        Address:          n.Address,
        Port:             n.Port,
        BlockchainLength: len(n.Blockchain),
        PendingTxnsCount: len(n.PendingTxns),
        ValidatorCount:   len(n.ValidatorSet),
        Stake:            n.Stake,
        LastBlockHash:    lastBlockHash,
    }
}

// StartHTTPServer starts an HTTP server to serve the node status
func (n *Node) StartHTTPServer() {
    http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
        status := n.GetStatus()
        data, err := json.Marshal(status)
        if err != nil {
            http.Error(w, "Failed to get status", http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.Write(data)
    })

    log.Printf("Starting HTTP server at %s:%s", n.Address, n.Port)
    if err := http.ListenAndServe(n.Address+":"+n.Port, nil); err != nil {
        log.Fatalf("Failed to start HTTP server: %v", err)
    }
}
