package resource_pools

import (
    "crypto/sha256"
    "encoding/json"
    "errors"
    "fmt"
    "math/rand"
    "sync"
    "time"
)

// PoolManager manages the decentralized resource pools
type PoolManager struct {
    Pools map[string]*ResourcePool
    mu    sync.Mutex
}

// ResourcePool represents a resource pool in the network
type ResourcePool struct {
    ID          string
    Resources   map[string]int // Resource ID -> Quantity
    Allocations map[string]int // Node ID -> Allocated Resource Quantity
    mu          sync.Mutex
}

// Node represents a network participant
type Node struct {
    ID         string
    Reputation int
    Resources  map[string]int // Resource ID -> Quantity
}

// NewPoolManager initializes a new PoolManager
func NewPoolManager() *PoolManager {
    return &PoolManager{
        Pools: make(map[string]*ResourcePool),
    }
}

// CreatePool creates a new resource pool
func (pm *PoolManager) CreatePool(id string, initialResources map[string]int) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    if _, exists := pm.Pools[id]; exists {
        return errors.New("pool already exists")
    }

    pool := &ResourcePool{
        ID:          id,
        Resources:   initialResources,
        Allocations: make(map[string]int),
    }
    pm.Pools[id] = pool
    return nil
}

// AllocateResources allocates resources from the pool to a node
func (pm *PoolManager) AllocateResources(poolID, nodeID string, quantity int) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    pool, exists := pm.Pools[poolID]
    if !exists {
        return errors.New("pool not found")
    }

    pool.mu.Lock()
    defer pool.mu.Unlock()

    available, ok := pool.Resources[nodeID]
    if !ok || available < quantity {
        return errors.New("insufficient resources")
    }

    pool.Resources[nodeID] -= quantity
    pool.Allocations[nodeID] += quantity
    return nil
}

// ReleaseResources releases resources back to the pool from a node
func (pm *PoolManager) ReleaseResources(poolID, nodeID string, quantity int) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    pool, exists := pm.Pools[poolID]
    if !exists {
        return errors.New("pool not found")
    }

    pool.mu.Lock()
    defer pool.mu.Unlock()

    allocated, ok := pool.Allocations[nodeID]
    if !ok || allocated < quantity {
        return errors.New("invalid release quantity")
    }

    pool.Allocations[nodeID] -= quantity
    pool.Resources[nodeID] += quantity
    return nil
}

// GetPoolStatus returns the status of a specific pool
func (pm *PoolManager) GetPoolStatus(poolID string) (*ResourcePool, error) {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    pool, exists := pm.Pools[poolID]
    if !exists {
        return nil, errors.New("pool not found")
    }

    return pool, nil
}

// GetNodeAllocation returns the allocated resources for a specific node in a pool
func (pm *PoolManager) GetNodeAllocation(poolID, nodeID string) (int, error) {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    pool, exists := pm.Pools[poolID]
    if !exists {
        return 0, errors.New("pool not found")
    }

    allocation, ok := pool.Allocations[nodeID]
    if !ok {
        return 0, errors.New("node not found")
    }

    return allocation, nil
}

// HashNodeID generates a unique hash for a node ID using SHA-256
func HashNodeID(nodeID string) string {
    hash := sha256.New()
    hash.Write([]byte(nodeID))
    return fmt.Sprintf("%x", hash.Sum(nil))
}

// SaveState serializes the current state of the pool manager
func (pm *PoolManager) SaveState() ([]byte, error) {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    return json.Marshal(pm.Pools)
}

// LoadState deserializes and loads the state into the pool manager
func (pm *PoolManager) LoadState(data []byte) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    return json.Unmarshal(data, &pm.Pools)
}

func init() {
    rand.Seed(time.Now().UnixNano())
}
