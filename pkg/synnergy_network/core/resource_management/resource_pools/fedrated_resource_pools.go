package resource_pools

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "errors"
    "io"
    "log"
    "sync"
    "time"
)

// FederatedResourcePool represents a pool of resources managed collectively by federated nodes
type FederatedResourcePool struct {
    ID          string
    Resources   map[string]int // Resource ID -> Quantity
    Allocations map[string]int // Node ID -> Allocated Resource Quantity
    mu          sync.Mutex
    members     map[string]*FederatedNode // Node ID -> FederatedNode
}

// FederatedNode represents a node in the federated resource pool
type FederatedNode struct {
    ID         string
    Stake      int
    Resources  map[string]int
    LastActive time.Time
}

// NewFederatedResourcePool initializes a new FederatedResourcePool
func NewFederatedResourcePool(id string) *FederatedResourcePool {
    return &FederatedResourcePool{
        ID:          id,
        Resources:   make(map[string]int),
        Allocations: make(map[string]int),
        members:     make(map[string]*FederatedNode),
    }
}

// AddNode adds a new node to the federated resource pool
func (frp *FederatedResourcePool) AddNode(nodeID string, stake int) error {
    frp.mu.Lock()
    defer frp.mu.Unlock()

    if _, exists := frp.members[nodeID]; exists {
        return errors.New("node already exists in the pool")
    }

    frp.members[nodeID] = &FederatedNode{
        ID:         nodeID,
        Stake:      stake,
        Resources:  make(map[string]int),
        LastActive: time.Now(),
    }
    return nil
}

// AllocateResources allocates resources to a node based on its stake and current availability
func (frp *FederatedResourcePool) AllocateResources(nodeID string, resourceID string, quantity int) error {
    frp.mu.Lock()
    defer frp.mu.Unlock()

    node, exists := frp.members[nodeID]
    if !exists {
        return errors.New("node not found in the pool")
    }

    if frp.Resources[resourceID] < quantity {
        return errors.New("insufficient resources in the pool")
    }

    frp.Resources[resourceID] -= quantity
    node.Resources[resourceID] += quantity
    frp.Allocations[nodeID] += quantity
    node.LastActive = time.Now()
    return nil
}

// ReleaseResources releases resources from a node back to the pool
func (frp *FederatedResourcePool) ReleaseResources(nodeID string, resourceID string, quantity int) error {
    frp.mu.Lock()
    defer frp.mu.Unlock()

    node, exists := frp.members[nodeID]
    if !exists {
        return errors.New("node not found in the pool")
    }

    if node.Resources[resourceID] < quantity {
        return errors.New("node does not have enough allocated resources")
    }

    node.Resources[resourceID] -= quantity
    frp.Resources[resourceID] += quantity
    frp.Allocations[nodeID] -= quantity
    node.LastActive = time.Now()
    return nil
}

// EncryptData encrypts data using AES encryption
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

// DecryptData decrypts data using AES encryption
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

// GetPoolStatus provides the current status of the resource pool
func (frp *FederatedResourcePool) GetPoolStatus() (map[string]int, error) {
    frp.mu.Lock()
    defer frp.mu.Unlock()

    return frp.Resources, nil
}

// RemoveInactiveNodes removes nodes that have been inactive for a specified duration
func (frp *FederatedResourcePool) RemoveInactiveNodes(duration time.Duration) {
    frp.mu.Lock()
    defer frp.mu.Unlock()

    for id, node := range frp.members {
        if time.Since(node.LastActive) > duration {
            log.Printf("Removing inactive node: %s", id)
            frp.deallocateNodeResources(id)
            delete(frp.members, id)
        }
    }
}

// deallocateNodeResources deallocates all resources from a node back to the pool
func (frp *FederatedResourcePool) deallocateNodeResources(nodeID string) {
    node, exists := frp.members[nodeID]
    if !exists {
        return
    }

    for resourceID, quantity := range node.Resources {
        frp.Resources[resourceID] += quantity
        frp.Allocations[nodeID] -= quantity
    }
    node.Resources = make(map[string]int)
}

// SaveState serializes the current state of the resource pool
func (frp *FederatedResourcePool) SaveState() ([]byte, error) {
    frp.mu.Lock()
    defer frp.mu.Unlock()

    return json.Marshal(frp)
}

// LoadState deserializes the state into the resource pool
func (frp *FederatedResourcePool) LoadState(data []byte) error {
    frp.mu.Lock()
    defer frp.mu.Unlock()

    return json.Unmarshal(data, &frp)
}

func init() {
    rand.Seed(time.Now().UnixNano())
}
