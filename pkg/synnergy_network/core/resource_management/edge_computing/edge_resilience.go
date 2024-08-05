package edge_computing

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
    "sync"
)

// Node represents an edge computing node in the network.
type Node struct {
    ID       string
    IP       string
    Capacity int
    Load     int
    Status   string
    Data     map[string]string // Key-value storage for node-specific data
}

// EdgeResilienceManager manages resilience strategies for the edge network.
type EdgeResilienceManager struct {
    nodes        map[string]*Node
    mutex        sync.Mutex
    encryptionKey []byte
    redundancyFactor int
}

// NewEdgeResilienceManager initializes a new EdgeResilienceManager.
func NewEdgeResilienceManager(encryptionKey []byte, redundancyFactor int) *EdgeResilienceManager {
    return &EdgeResilienceManager{
        nodes:           make(map[string]*Node),
        encryptionKey:   encryptionKey,
        redundancyFactor: redundancyFactor,
    }
}

// AddNode adds a new node to the network.
func (erm *EdgeResilienceManager) AddNode(node *Node) error {
    erm.mutex.Lock()
    defer erm.mutex.Unlock()
    if _, exists := erm.nodes[node.ID]; exists {
        return errors.New("node already exists")
    }
    erm.nodes[node.ID] = node
    return nil
}

// RemoveNode removes a node from the network.
func (erm *EdgeResilienceManager) RemoveNode(nodeID string) error {
    erm.mutex.Lock()
    defer erm.mutex.Unlock()
    if _, exists := erm.nodes[nodeID]; !exists {
        return errors.New("node not found")
    }
    delete(erm.nodes, nodeID)
    return nil
}

// GetNode returns the details of a specific node.
func (erm *EdgeResilienceManager) GetNode(nodeID string) (*Node, error) {
    erm.mutex.Lock()
    defer erm.mutex.Unlock()
    node, exists := erm.nodes[nodeID]
    if !exists {
        return nil, errors.New("node not found")
    }
    return node, nil
}

// ReplicateData replicates data across multiple nodes to ensure redundancy.
func (erm *EdgeResilienceManager) ReplicateData(nodeID, dataKey, dataValue string) error {
    erm.mutex.Lock()
    defer erm.mutex.Unlock()
    
    count := 0
    for _, node := range erm.nodes {
        if node.ID != nodeID && count < erm.redundancyFactor {
            node.Data[dataKey] = dataValue
            count++
        }
    }

    if count == 0 {
        return errors.New("no suitable nodes found for replication")
    }

    return nil
}

// EncryptData encrypts data using AES.
func (erm *EdgeResilienceManager) EncryptData(data string) (string, error) {
    block, err := aes.NewCipher(erm.encryptionKey)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES.
func (erm *EdgeResilienceManager) DecryptData(data string) (string, error) {
    block, err := aes.NewCipher(erm.encryptionKey)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    encoded, err := base64.StdEncoding.DecodeString(data)
    if err != nil {
        return "", err
    }
    nonceSize := gcm.NonceSize()
    if len(encoded) < nonceSize {
        return "", errors.New("ciphertext too short")
    }
    nonce, ciphertext := encoded[:nonceSize], encoded[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}

// MonitorNodeStatus continuously monitors the status of nodes.
func (erm *EdgeResilienceManager) MonitorNodeStatus() {
    erm.mutex.Lock()
    defer erm.mutex.Unlock()

    for _, node := range erm.nodes {
        // Example: Check if node is responsive, update status accordingly
        // In practice, this would involve network checks, health pings, etc.
        node.Status = "active" // Placeholder, actual implementation required
    }
}

// HandleNodeFailure manages failover and data recovery in case of node failure.
func (erm *EdgeResilienceManager) HandleNodeFailure(failedNodeID string) error {
    erm.mutex.Lock()
    defer erm.mutex.Unlock()

    failedNode, exists := erm.nodes[failedNodeID]
    if !exists {
        return errors.New("node not found")
    }

    // Redistribute data from the failed node
    for dataKey, dataValue := range failedNode.Data {
        for _, node := range erm.nodes {
            if node.ID != failedNodeID {
                node.Data[dataKey] = dataValue
            }
        }
    }

    // Remove the failed node from the network
    delete(erm.nodes, failedNodeID)
    return nil
}
