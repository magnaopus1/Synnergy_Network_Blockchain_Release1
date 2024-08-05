package operator

import (
    "encoding/json"
    "log"
    "net/http"
    "sync"

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

// CrossOperatorMessage represents a message exchanged between operators
type CrossOperatorMessage struct {
    From   string `json:"from"`
    To     string `json:"to"`
    Type   string `json:"type"`
    Data   string `json:"data"`
}

// SendCrossOperatorMessage sends a message to another operator
func (o *Operator) SendCrossOperatorMessage(to string, message CrossOperatorMessage) error {
    o.mu.Lock()
    defer o.mu.Unlock()

    url := "http://" + to + "/receive_message"
    messageJSON, err := json.Marshal(message)
    if err != nil {
        return err
    }

    resp, err := http.Post(url, "application/json", bytes.NewBuffer(messageJSON))
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("failed to send message: %v", resp.Status)
    }

    return nil
}

// ReceiveCrossOperatorMessage handles receiving messages from other operators
func (o *Operator) ReceiveCrossOperatorMessage(w http.ResponseWriter, r *http.Request) {
    var message CrossOperatorMessage
    if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Process the message based on its type
    switch message.Type {
    case "block":
        var block child_chain.Block
        if err := json.Unmarshal([]byte(message.Data), &block); err != nil {
            log.Printf("Failed to unmarshal block: %v", err)
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        if err := o.ChainManager.AddBlock(&block); err != nil {
            log.Printf("Failed to add block: %v", err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    case "transaction":
        var txn child_chain.Transaction
        if err := json.Unmarshal([]byte(message.Data), &txn); err != nil {
            log.Printf("Failed to unmarshal transaction: %v", err)
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        if err := o.ChainManager.AddTransaction(&txn); err != nil {
            log.Printf("Failed to add transaction: %v", err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    default:
        log.Printf("Unknown message type: %v", message.Type)
        http.Error(w, "unknown message type", http.StatusBadRequest)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// RegisterCrossOperatorRoutes registers the HTTP routes for cross-operator communication
func (o *Operator) RegisterCrossOperatorRoutes() {
    http.HandleFunc("/receive_message", o.ReceiveCrossOperatorMessage)
    log.Fatal(http.ListenAndServe(":8081", nil))
}
