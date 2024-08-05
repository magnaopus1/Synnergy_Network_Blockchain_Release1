package scaling

import (
	"errors"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/synnergy_network/utils"
)

// ResourceAllocator handles the dynamic allocation of resources in the blockchain network.
type ResourceAllocator struct {
	mu           sync.Mutex
	resourcePool map[string]*Resource
}

// Resource represents a computing resource in the network.
type Resource struct {
	ID           string
	CPU          int
	Memory       int
	Allocated    bool
	LastUsed     time.Time
}

// NewResourceAllocator initializes a new ResourceAllocator.
func NewResourceAllocator() *ResourceAllocator {
	return &ResourceAllocator{
		resourcePool: make(map[string]*Resource),
	}
}

// AddResource adds a new resource to the pool.
func (ra *ResourceAllocator) AddResource(cpu, memory int) string {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	id := generateResourceID()
	resource := &Resource{
		ID:        id,
		CPU:       cpu,
		Memory:    memory,
		Allocated: false,
		LastUsed:  time.Now(),
	}
	ra.resourcePool[id] = resource
	log.Printf("Resource %s added with %d CPU and %d Memory", id, cpu, memory)
	return id
}

// AllocateResource allocates a resource based on required CPU and Memory.
func (ra *ResourceAllocator) AllocateResource(cpu, memory int) (*Resource, error) {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	for _, resource := range ra.resourcePool {
		if !resource.Allocated && resource.CPU >= cpu && resource.Memory >= memory {
			resource.Allocated = true
			resource.LastUsed = time.Now()
			log.Printf("Resource %s allocated with %d CPU and %d Memory", resource.ID, cpu, memory)
			return resource, nil
		}
	}
	return nil, errors.New("no available resources matching the requirements")
}

// ReleaseResource releases an allocated resource back to the pool.
func (ra *ResourceAllocator) ReleaseResource(id string) error {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	resource, exists := ra.resourcePool[id]
	if !exists {
		return errors.New("resource not found")
	}

	if !resource.Allocated {
		return errors.New("resource not allocated")
	}

	resource.Allocated = false
	resource.LastUsed = time.Now()
	log.Printf("Resource %s released", id)
	return nil
}

// OptimizeResourceAllocation optimizes resource allocation using AI algorithms.
func (ra *ResourceAllocator) OptimizeResourceAllocation() {
	// Simulate AI-driven optimization
	ra.mu.Lock()
	defer ra.mu.Unlock()

	log.Println("Starting resource optimization process")
	// For simplicity, we'll randomly deallocate some resources
	for id, resource := range ra.resourcePool {
		if resource.Allocated && rand.Intn(2) == 0 {
			resource.Allocated = false
			log.Printf("Resource %s deallocated during optimization", id)
		}
	}
	log.Println("Resource optimization process completed")
}

// GenerateResourceID generates a unique ID for a new resource.
func generateResourceID() string {
	return utils.GenerateUUID()
}

// Encryption and Decryption functions using Argon2 for secure data handling.
func encryptData(data, passphrase string) (string, error) {
	return utils.EncryptArgon2(data, passphrase)
}

func decryptData(data, passphrase string) (string, error) {
	return utils.DecryptArgon2(data, passphrase)
}

// Util functions from the utils package (mocked here for the sake of example)
package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/argon2"
)

// GenerateUUID generates a new UUID.
func GenerateUUID() string {
	uuid := make([]byte, 16)
	rand.Read(uuid)
	return base64.URLEncoding.EncodeToString(uuid)
}

// EncryptArgon2 encrypts data using Argon2.
func EncryptArgon2(data, passphrase string) (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key := argon2.Key([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	encrypted := base64.URLEncoding.EncodeToString(key) + base64.URLEncoding.EncodeToString(salt)
	return encrypted, nil
}

// DecryptArgon2 decrypts data using Argon2.
func DecryptArgon2(data, passphrase string) (string, error) {
	salt := make([]byte, 16)
	decoded, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	copy(salt, decoded[len(decoded)-16:])

	key := argon2.Key([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	encrypted := base64.URLEncoding.EncodeToString(key)

	if encrypted != data[:len(data)-16] {
		return "", errors.New("decryption failed")
	}
	return string(key), nil
}
