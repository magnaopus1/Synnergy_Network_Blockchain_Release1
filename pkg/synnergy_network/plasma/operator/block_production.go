package operator

import (
    "encoding/json"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
    "github.com/synnergy_network_blockchain/plasma/client"
    "github.com/synnergy_network_blockchain/plasma/contract"
    "github.com/synnergy_network_blockchain/plasma/node"
)

// Operator represents the blockchain operator
type Operator struct {
    ChainManager  *child_chain.ChainManager
    ClientManager *client.ClientManager
    ContractManager *contract.ContractManager
    NodeManager   *node.NodeManager
    mu            sync.Mutex
}

// NewOperator initializes a new Operator
func NewOperator(cm *child_chain.ChainManager, clm *client.ClientManager, ctm *contract.ContractManager, nm *node.NodeManager) *Operator {
    return &Operator{
        ChainManager:  cm,
        ClientManager: clm,
        ContractManager: ctm,
        NodeManager:   nm,
    }
}

// ProduceBlock produces a new block and adds it to the blockchain
func (o *Operator) ProduceBlock() error {
    o.mu.Lock()
    defer o.mu.Unlock()

    pendingTxns := o.ChainManager.GetPendingTransactions()
    if len(pendingTxns) == 0 {
        return nil
    }

    newBlock, err := o.ChainManager.CreateBlock(pendingTxns)
    if err != nil {
        return err
    }

    if err := o.ChainManager.AddBlock(newBlock); err != nil {
        return err
    }

    // Broadcast the new block to other nodes
    if err := o.NodeManager.BroadcastBlock(newBlock); err != nil {
        return err
    }

    // Clear the pending transactions
    o.ChainManager.ClearPendingTransactions()

    log.Printf("Produced new block: %v", newBlock)
    return nil
}

// StartBlockProduction starts the block production process
func (o *Operator) StartBlockProduction(interval time.Duration) {
    ticker := time.NewTicker(interval)
    go func() {
        for {
            select {
            case <-ticker.C:
                if err := o.ProduceBlock(); err != nil {
                    log.Printf("Error producing block: %v", err)
                }
            }
        }
    }()
}

// GetStatusHandler returns the status of the operator
func (o *Operator) GetStatusHandler(w http.ResponseWriter, r *http.Request) {
    status := map[string]interface{}{
        "chainManager":  o.ChainManager.GetStatus(),
        "clientManager": o.ClientManager.GetStatus(),
        "contractManager": o.ContractManager.GetStatus(),
        "nodeManager":   o.NodeManager.GetStatus(),
    }

    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(status); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
}

// RegisterRoutes registers the HTTP routes for the operator
func (o *Operator) RegisterRoutes() {
    http.HandleFunc("/status", o.GetStatusHandler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

// ChainManager represents the manager for the blockchain
type ChainManager struct {
    mu             sync.Mutex
    Blockchain     []child_chain.Block
    PendingTxns    []child_chain.Transaction
    Difficulty     int
}

// GetPendingTransactions returns the list of pending transactions
func (cm *ChainManager) GetPendingTransactions() []child_chain.Transaction {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    return cm.PendingTxns
}

// CreateBlock creates a new block with the given transactions
func (cm *ChainManager) CreateBlock(txns []child_chain.Transaction) (*child_chain.Block, error) {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    prevBlock := cm.Blockchain[len(cm.Blockchain)-1]
    newBlock := &child_chain.Block{
        Index:        prevBlock.Index + 1,
        Timestamp:    time.Now().Unix(),
        Transactions: txns,
        PrevHash:     prevBlock.Hash,
        Hash:         "", // This will be set after the block is mined
    }

    // Implement mining logic (Proof of Work, etc.)
    newBlock.Mine(cm.Difficulty)

    return newBlock, nil
}

// AddBlock adds a block to the blockchain
func (cm *ChainManager) AddBlock(block *child_chain.Block) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    if err := cm.ValidateBlock(block); err != nil {
        return err
    }

    cm.Blockchain = append(cm.Blockchain, *block)
    return nil
}

// ClearPendingTransactions clears the list of pending transactions
func (cm *ChainManager) ClearPendingTransactions() {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    cm.PendingTxns = []child_chain.Transaction{}
}

// ValidateBlock validates a block
func (cm *ChainManager) ValidateBlock(block *child_chain.Block) error {
    // Implement block validation logic
    return nil
}

// NodeManager represents the manager for nodes
type NodeManager struct {
    mu    sync.Mutex
    Nodes map[string]*node.Node
}

// BroadcastBlock broadcasts a block to all nodes
func (nm *NodeManager) BroadcastBlock(block *child_chain.Block) error {
    nm.mu.Lock()
    defer nm.mu.Unlock()

    for _, node := range nm.Nodes {
        if err := node.ReceiveBlock(block); err != nil {
            return err
        }
    }
    return nil
}

// GetStatus returns the status of the node manager
func (nm *NodeManager) GetStatus() map[string]interface{} {
    nm.mu.Lock()
    defer nm.mu.Unlock()

    status := make(map[string]interface{})
    for id, node := range nm.Nodes {
        status[id] = node.GetStatus()
    }
    return status
}
