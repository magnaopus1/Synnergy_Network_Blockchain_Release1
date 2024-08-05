package bridge

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "sync"
    "time"

    "github.com/synnergy_network/bridge/transfer_logs"
    "github.com/synnergy_network/bridge/security_protocols"
    "github.com/synnergy_network/bridge/state_verification"
)

// Node represents a node in the decentralized network
type Node struct {
    ID       string    `json:"id"`
    Address  string    `json:"address"`
    Status   string    `json:"status"`
    LastSeen time.Time `json:"last_seen"`
}

// DecentralizedManager manages the decentralized network
type DecentralizedManager struct {
    nodes   map[string]Node
    mu      sync.RWMutex
    config  *ManagerConfig
}

// ManagerConfig represents the configuration for the decentralized manager
type ManagerConfig struct {
    NodeTimeout      time.Duration
    CheckInterval    time.Duration
    EncryptionKey    string
}

// NewDecentralizedManager creates a new DecentralizedManager
func NewDecentralizedManager(config *ManagerConfig) *DecentralizedManager {
    return &DecentralizedManager{
        nodes:  make(map[string]Node),
        config: config,
    }
}

// RegisterNode registers a new node in the decentralized network
func (dm *DecentralizedManager) RegisterNode(id, address string) (Node, error) {
    if id == "" || address == "" {
        return Node{}, errors.New("invalid node parameters")
    }

    node := Node{
        ID:       id,
        Address:  address,
        Status:   "Active",
        LastSeen: time.Now(),
    }

    dm.mu.Lock()
    dm.nodes[id] = node
    dm.mu.Unlock()

    transfer_logs.LogNodeRegistration(node)

    return node, nil
}

// UpdateNodeStatus updates the status of a node in the decentralized network
func (dm *DecentralizedManager) UpdateNodeStatus(id, status string) error {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    node, exists := dm.nodes[id]
    if !exists {
        return errors.New("node not found")
    }

    node.Status = status
    node.LastSeen = time.Now()
    dm.nodes[id] = node

    transfer_logs.LogNodeStatusUpdate(node)

    return nil
}

// RemoveNode removes a node from the decentralized network
func (dm *DecentralizedManager) RemoveNode(id string) error {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    _, exists := dm.nodes[id]
    if !exists {
        return errors.New("node not found")
    }

    delete(dm.nodes, id)

    transfer_logs.LogNodeRemoval(id)

    return nil
}

// MonitorNodes monitors the nodes and updates their status based on the last seen timestamp
func (dm *DecentralizedManager) MonitorNodes() {
    ticker := time.NewTicker(dm.config.CheckInterval)
    defer ticker.Stop()

    for range ticker.C {
        dm.mu.Lock()
        for id, node := range dm.nodes {
            if time.Since(node.LastSeen) > dm.config.NodeTimeout {
                node.Status = "Inactive"
                dm.nodes[id] = node
                transfer_logs.LogNodeStatusUpdate(node)
            }
        }
        dm.mu.Unlock()
    }
}

// EncryptData encrypts decentralized management data for secure storage
func (dm *DecentralizedManager) EncryptData(data interface{}) (string, error) {
    key := sha256.Sum256([]byte(dm.config.EncryptionKey))
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return "", err
    }

    jsonData, err := json.Marshal(data)
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(jsonData))
    iv := ciphertext[:aes.BlockSize]

    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], jsonData)

    return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts decentralized management data for use
func (dm *DecentralizedManager) DecryptData(encryptedData string) (interface{}, error) {
    key := sha256.Sum256([]byte(dm.config.EncryptionKey))
    ciphertext, _ := hex.DecodeString(encryptedData)
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return nil, err
    }

    if len(ciphertext) < aes.BlockSize {
        return nil, errors.New("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    var data interface{}
    if err := json.Unmarshal(ciphertext, &data); err != nil {
        return nil, err
    }

    return data, nil
}

// Example usage demonstrating comprehensive functionality
func ExampleComprehensiveFunctionality() {
    config := &ManagerConfig{
        NodeTimeout:   5 * time.Minute,
        CheckInterval: 1 * time.Minute,
        EncryptionKey: "superSecureKey",
    }
    dm := NewDecentralizedManager(config)

    // Register a new node
    node, err := dm.RegisterNode("node1", "192.168.1.1")
    if err != nil {
        fmt.Println("Error registering node:", err)
        return
    }

    fmt.Println("Registered Node:", node)

    // Update the node status
    err = dm.UpdateNodeStatus("node1", "Active")
    if err != nil {
        fmt.Println("Error updating node status:", err)
        return
    }

    fmt.Println("Updated Node Status:", node)

    // Encrypt node data
    encryptedData, err := dm.EncryptData(dm.nodes)
    if err != nil {
        fmt.Println("Error encrypting data:", err)
        return
    }

    fmt.Println("Encrypted Data:", encryptedData)

    // Decrypt node data
    decryptedData, err := dm.DecryptData(encryptedData)
    if err != nil {
        fmt.Println("Error decrypting data:", err)
        return
    }

    fmt.Println("Decrypted Data:", decryptedData)

    // Start monitoring nodes
    go dm.MonitorNodes()

    // Simulate some delay
    time.Sleep(2 * time.Minute)

    // Update node status to simulate activity
    err = dm.UpdateNodeStatus("node1", "Active")
    if err != nil {
        fmt.Println("Error updating node status:", err)
    }

    // Simulate additional delay
    time.Sleep(5 * time.Minute)
}
