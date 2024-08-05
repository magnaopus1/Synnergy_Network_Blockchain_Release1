package resourcepools

import (
	"sync"
	"time"
	"errors"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
)

// Resource represents a resource in the pool (e.g., CPU, memory, bandwidth)
type Resource struct {
	Type   string
	Amount float64
}

// Pool holds resources contributed by nodes
type Pool struct {
	Resources map[string]Resource
	mu        sync.Mutex
}

// Node represents a network participant contributing resources
type Node struct {
	ID       string
	Reputation float64
	Resources []Resource
}

// Contribution records a node's contribution to the pool
type Contribution struct {
	NodeID    string
	Resource  Resource
	Timestamp time.Time
}

// ResourcePoolManager manages the resource pool and allocation
type ResourcePoolManager struct {
	Pool          Pool
	Contributions []Contribution
	Nodes         map[string]Node
	mu            sync.Mutex
}

// NewResourcePoolManager creates a new ResourcePoolManager
func NewResourcePoolManager() *ResourcePoolManager {
	return &ResourcePoolManager{
		Pool: Pool{
			Resources: make(map[string]Resource),
		},
		Nodes: make(map[string]Node),
	}
}

// AddResource adds a resource to the pool
func (rpm *ResourcePoolManager) AddResource(nodeID string, resource Resource) error {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	node, exists := rpm.Nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	// Update the node's resources
	node.Resources = append(node.Resources, resource)
	rpm.Nodes[nodeID] = node

	// Add to the pool
	if existingResource, ok := rpm.Pool.Resources[resource.Type]; ok {
		existingResource.Amount += resource.Amount
		rpm.Pool.Resources[resource.Type] = existingResource
	} else {
		rpm.Pool.Resources[resource.Type] = resource
	}

	// Record the contribution
	rpm.Contributions = append(rpm.Contributions, Contribution{
		NodeID:    nodeID,
		Resource:  resource,
		Timestamp: time.Now(),
	})

	return nil
}

// AllocateResource allocates resources from the pool based on demand and availability
func (rpm *ResourcePoolManager) AllocateResource(resourceType string, amount float64) (Resource, error) {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	resource, exists := rpm.Pool.Resources[resourceType]
	if !exists || resource.Amount < amount {
		return Resource{}, errors.New("insufficient resources")
	}

	// Allocate the requested amount
	resource.Amount -= amount
	rpm.Pool.Resources[resourceType] = resource

	return Resource{Type: resourceType, Amount: amount}, nil
}

// EncryptData encrypts data using AES
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptData decrypts data using AES
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ExportContributions exports contributions to JSON for transparency and auditing
func (rpm *ResourcePoolManager) ExportContributions() ([]byte, error) {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	data, err := json.Marshal(rpm.Contributions)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ImportContributions imports contributions from JSON for auditing
func (rpm *ResourcePoolManager) ImportContributions(data []byte) error {
	var contributions []Contribution
	if err := json.Unmarshal(data, &contributions); err != nil {
		return err
	}

	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	rpm.Contributions = contributions
	return nil
}

// AuditTrail logs contributions for auditing purposes
func (rpm *ResourcePoolManager) AuditTrail() {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	for _, contribution := range rpm.Contributions {
		log.Printf("Node %s contributed %f of %s at %s", contribution.NodeID, contribution.Resource.Amount, contribution.Resource.Type, contribution.Timestamp)
	}
}
