package resource_pools

import (
    "sync"
    "time"
    "fmt"
    "log"
    "math"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "errors"
)

// ResourceAllocator manages the dynamic allocation of resources across the network
type ResourceAllocator struct {
    Nodes           map[string]*Node
    mu              sync.Mutex
    monitoringData  map[string]*NodeMetrics
    threshold       float64
    scalingFactor   float64
}

// Node represents a node in the network
type Node struct {
    ID         string
    CPUUsage   float64
    MemUsage   float64
    NetUsage   float64
    Resources  map[string]int // Resource ID -> Quantity
}

// NodeMetrics stores metrics for monitoring purposes
type NodeMetrics struct {
    CPUUsage   float64
    MemUsage   float64
    NetUsage   float64
    LastUpdate time.Time
}

// NewResourceAllocator initializes a new ResourceAllocator
func NewResourceAllocator(threshold, scalingFactor float64) *ResourceAllocator {
    return &ResourceAllocator{
        Nodes:          make(map[string]*Node),
        monitoringData: make(map[string]*NodeMetrics),
        threshold:      threshold,
        scalingFactor:  scalingFactor,
    }
}

// MonitorResources continuously monitors resource usage
func (ra *ResourceAllocator) MonitorResources(nodeID string) {
    ra.mu.Lock()
    defer ra.mu.Unlock()

    node, exists := ra.Nodes[nodeID]
    if !exists {
        log.Printf("Node %s not found", nodeID)
        return
    }

    metrics, exists := ra.monitoringData[nodeID]
    if !exists {
        metrics = &NodeMetrics{}
        ra.monitoringData[nodeID] = metrics
    }

    metrics.CPUUsage = node.CPUUsage
    metrics.MemUsage = node.MemUsage
    metrics.NetUsage = node.NetUsage
    metrics.LastUpdate = time.Now()
}

// AdjustResources dynamically adjusts resources based on real-time data
func (ra *ResourceAllocator) AdjustResources(nodeID string) {
    ra.mu.Lock()
    defer ra.mu.Unlock()

    metrics, exists := ra.monitoringData[nodeID]
    if !exists {
        log.Printf("Metrics for node %s not found", nodeID)
        return
    }

    if metrics.CPUUsage > ra.threshold {
        ra.scaleUp(nodeID, "CPU")
    } else if metrics.CPUUsage < ra.threshold {
        ra.scaleDown(nodeID, "CPU")
    }

    if metrics.MemUsage > ra.threshold {
        ra.scaleUp(nodeID, "Memory")
    } else if metrics.MemUsage < ra.threshold {
        ra.scaleDown(nodeID, "Memory")
    }

    if metrics.NetUsage > ra.threshold {
        ra.scaleUp(nodeID, "Network")
    } else if metrics.NetUsage < ra.threshold {
        ra.scaleDown(nodeID, "Network")
    }
}

// scaleUp increases the resources allocated to a node
func (ra *ResourceAllocator) scaleUp(nodeID, resourceType string) {
    // Logic to increase resource allocation
    fmt.Printf("Scaling up %s resources for node %s\n", resourceType, nodeID)
}

// scaleDown decreases the resources allocated to a node
func (ra *ResourceAllocator) scaleDown(nodeID, resourceType string) {
    // Logic to decrease resource allocation
    fmt.Printf("Scaling down %s resources for node %s\n", resourceType, nodeID)
}

// EncryptData encrypts data using AES
func EncryptData(plaintext []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

    return ciphertext, nil
}

// DecryptData decrypts data using AES
func DecryptData(ciphertext []byte, key []byte) ([]byte, error) {
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

// LoadBalancing distributes workloads evenly across nodes
func (ra *ResourceAllocator) LoadBalancing() {
    // Logic to balance the load across nodes
    fmt.Println("Load balancing in progress...")
}

// AutoScaling automatically adjusts resource allocation based on predictions
func (ra *ResourceAllocator) AutoScaling() {
    // Predictive analysis and auto-scaling logic
    fmt.Println("Auto-scaling resources based on forecasted demand...")
}
