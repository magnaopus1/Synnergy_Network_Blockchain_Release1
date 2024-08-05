package resource_pools

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "log"
    "math"
    "sync"
    "time"
)

// LoadBalancer handles the distribution of workloads across nodes in the network
type LoadBalancer struct {
    Nodes               map[string]*Node
    mu                  sync.Mutex
    loadMetrics         map[string]*LoadMetrics
    lastUpdated         time.Time
    encryptionKey       []byte
    encryptedMetricsLog map[string]string // Node ID -> Encrypted load metrics
}

// Node represents a network node
type Node struct {
    ID         string
    IP         string
    Capacity   float64 // Total capacity of the node
    Load       float64 // Current load on the node
    IsActive   bool
}

// LoadMetrics stores real-time load metrics for a node
type LoadMetrics struct {
    CPUUsage     float64
    MemoryUsage  float64
    NetworkUsage float64
    LastUpdated  time.Time
}

// NewLoadBalancer initializes a new LoadBalancer
func NewLoadBalancer(key []byte) *LoadBalancer {
    return &LoadBalancer{
        Nodes:               make(map[string]*Node),
        loadMetrics:         make(map[string]*LoadMetrics),
        lastUpdated:         time.Now(),
        encryptionKey:       key,
        encryptedMetricsLog: make(map[string]string),
    }
}

// RegisterNode adds a new node to the load balancer
func (lb *LoadBalancer) RegisterNode(id, ip string, capacity float64) {
    lb.mu.Lock()
    defer lb.mu.Unlock()

    lb.Nodes[id] = &Node{
        ID:       id,
        IP:       ip,
        Capacity: capacity,
        IsActive: true,
    }
}

// UpdateLoadMetrics updates the load metrics for a node
func (lb *LoadBalancer) UpdateLoadMetrics(nodeID string, cpu, memory, network float64) {
    lb.mu.Lock()
    defer lb.mu.Unlock()

    if node, exists := lb.Nodes[nodeID]; exists && node.IsActive {
        lb.loadMetrics[nodeID] = &LoadMetrics{
            CPUUsage:     cpu,
            MemoryUsage:  memory,
            NetworkUsage: network,
            LastUpdated:  time.Now(),
        }
        lb.encryptAndLogMetrics(nodeID)
    } else {
        log.Printf("Node %s not found or inactive", nodeID)
    }
}

// DistributeLoad dynamically balances the load across all active nodes
func (lb *LoadBalancer) DistributeLoad() {
    lb.mu.Lock()
    defer lb.mu.Unlock()

    totalLoad := 0.0
    for _, node := range lb.Nodes {
        if node.IsActive {
            totalLoad += node.Load
        }
    }

    if totalLoad == 0 {
        return
    }

    for _, node := range lb.Nodes {
        if node.IsActive {
            optimalLoad := (node.Capacity / lb.totalCapacity()) * totalLoad
            lb.adjustNodeLoad(node, optimalLoad)
        }
    }
}

// totalCapacity calculates the total capacity of all active nodes
func (lb *LoadBalancer) totalCapacity() float64 {
    total := 0.0
    for _, node := range lb.Nodes {
        if node.IsActive {
            total += node.Capacity
        }
    }
    return total
}

// adjustNodeLoad adjusts the load on a specific node
func (lb *LoadBalancer) adjustNodeLoad(node *Node, optimalLoad float64) {
    if node.Load > optimalLoad {
        fmt.Printf("Reducing load on node %s\n", node.ID)
        // Implement logic to reduce the load on the node
    } else if node.Load < optimalLoad {
        fmt.Printf("Increasing load on node %s\n", node.ID)
        // Implement logic to increase the load on the node
    }
}

// encryptAndLogMetrics encrypts the load metrics and logs them
func (lb *LoadBalancer) encryptAndLogMetrics(nodeID string) {
    metrics := lb.loadMetrics[nodeID]
    data := fmt.Sprintf("CPU: %.2f, Memory: %.2f, Network: %.2f, Time: %s",
        metrics.CPUUsage, metrics.MemoryUsage, metrics.NetworkUsage, metrics.LastUpdated.String())
    
    encryptedData, err := encryptData([]byte(data), lb.encryptionKey)
    if err != nil {
        log.Printf("Failed to encrypt metrics for node %s: %v", nodeID, err)
        return
    }

    lb.encryptedMetricsLog[nodeID] = hex.EncodeToString(encryptedData)
}

// encryptData encrypts data using AES
func encryptData(data, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(data))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
    return ciphertext, nil
}

// DecryptData decrypts the encrypted data
func DecryptData(encryptedData, key []byte) ([]byte, error) {
    ciphertext, err := hex.DecodeString(string(encryptedData))
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(key)
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

    return ciphertext, nil
}

// MonitorHealth continuously monitors node health and updates their status
func (lb *LoadBalancer) MonitorHealth() {
    lb.mu.Lock()
    defer lb.mu.Unlock()

    for id, metrics := range lb.loadMetrics {
        if time.Since(metrics.LastUpdated) > 2*time.Minute {
            if node, exists := lb.Nodes[id]; exists {
                node.IsActive = false
                log.Printf("Node %s marked as inactive due to lack of updates", id)
            }
        }
    }
}
