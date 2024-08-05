package edge_computing

import (
    "sync"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
)

// Node represents an edge computing node in the network.
type Node struct {
    ID         string
    CPUUsage   float64
    MemoryUsage float64
    Bandwidth  float64
    Status     string
    Data       map[string]string
}

// EdgeResourceUtilizationManager manages the utilization of resources across edge nodes.
type EdgeResourceUtilizationManager struct {
    nodes         map[string]*Node
    mutex         sync.Mutex
    encryptionKey []byte
}

// NewEdgeResourceUtilizationManager initializes a new EdgeResourceUtilizationManager.
func NewEdgeResourceUtilizationManager(encryptionKey []byte) *EdgeResourceUtilizationManager {
    return &EdgeResourceUtilizationManager{
        nodes: make(map[string]*Node),
        encryptionKey: encryptionKey,
    }
}

// AddNode adds a new node to the network.
func (erum *EdgeResourceUtilizationManager) AddNode(node *Node) error {
    erum.mutex.Lock()
    defer erum.mutex.Unlock()
    if _, exists := erum.nodes[node.ID]; exists {
        return errors.New("node already exists")
    }
    erum.nodes[node.ID] = node
    return nil
}

// RemoveNode removes a node from the network.
func (erum *EdgeResourceUtilizationManager) RemoveNode(nodeID string) error {
    erum.mutex.Lock()
    defer erum.mutex.Unlock()
    if _, exists := erum.nodes[nodeID]; !exists {
        return errors.New("node not found")
    }
    delete(erum.nodes, nodeID)
    return nil
}

// UpdateNodeResourceUsage updates the resource usage statistics for a node.
func (erum *EdgeResourceUtilizationManager) UpdateNodeResourceUsage(nodeID string, cpuUsage, memoryUsage, bandwidth float64) error {
    erum.mutex.Lock()
    defer erum.mutex.Unlock()
    node, exists := erum.nodes[nodeID]
    if !exists {
        return errors.New("node not found")
    }
    node.CPUUsage = cpuUsage
    node.MemoryUsage = memoryUsage
    node.Bandwidth = bandwidth
    return nil
}

// EncryptData encrypts data using AES.
func (erum *EdgeResourceUtilizationManager) EncryptData(data string) (string, error) {
    block, err := aes.NewCipher(erum.encryptionKey)
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
func (erum *EdgeResourceUtilizationManager) DecryptData(data string) (string, error) {
    block, err := aes.NewCipher(erum.encryptionKey)
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

// MonitorResources monitors and logs the resource usage of nodes.
func (erum *EdgeResourceUtilizationManager) MonitorResources() {
    erum.mutex.Lock()
    defer erum.mutex.Unlock()
    
    for _, node := range erum.nodes {
        // Placeholder for monitoring logic, such as logging or alerting
        fmt.Printf("Node ID: %s, CPU Usage: %f, Memory Usage: %f, Bandwidth: %f\n", 
            node.ID, node.CPUUsage, node.MemoryUsage, node.Bandwidth)
    }
}

// AdjustResourceAllocation dynamically adjusts resource allocation based on usage.
func (erum *EdgeResourceUtilizationManager) AdjustResourceAllocation() {
    erum.mutex.Lock()
    defer erum.mutex.Unlock()

    totalCPU := 0.0
    totalMemory := 0.0
    for _, node := range erum.nodes {
        totalCPU += node.CPUUsage
        totalMemory += node.MemoryUsage
    }

    // Placeholder logic for dynamic resource adjustment
    for _, node := range erum.nodes {
        if node.CPUUsage > 0.8 {
            fmt.Printf("High CPU usage detected on node %s, adjusting resources.\n", node.ID)
            // Logic for reallocating or optimizing resources
        }
    }
}
