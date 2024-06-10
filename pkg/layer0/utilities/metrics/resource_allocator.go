package metrics

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
	"github.com/prometheus/client_golang/prometheus"
)

// ResourceAllocator dynamically allocates resources based on metrics data.
type ResourceAllocator struct {
	allocations    map[string]float64
	allocationsMux sync.RWMutex
	password       []byte
}

// NewResourceAllocator creates a new ResourceAllocator.
func NewResourceAllocator(password []byte) *ResourceAllocator {
	return &ResourceAllocator{
		allocations: make(map[string]float64),
		password:    password,
	}
}

// SetAllocation sets the resource allocation for a specific node or component.
func (ra *ResourceAllocator) SetAllocation(name string, value float64) {
	ra.allocationsMux.Lock()
	defer ra.allocationsMux.Unlock()

	ra.allocations[name] = value
}

// GetAllocation gets the resource allocation for a specific node or component.
func (ra *ResourceAllocator) GetAllocation(name string) (float64, bool) {
	ra.allocationsMux.RLock()
	defer ra.allocationsMux.RUnlock()

	value, exists := ra.allocations[name]
	return value, exists
}

// ExportAllocations securely exports the resource allocations using Argon2 and AES encryption.
func (ra *ResourceAllocator) ExportAllocations() ([]byte, error) {
	ra.allocationsMux.RLock()
	defer ra.allocationsMux.RUnlock()

	data, err := json.Marshal(ra.allocations)
	if err != nil {
		return nil, err
	}

	return ra.encryptData(data)
}

// ImportAllocations securely imports the resource allocations using Argon2 and AES encryption.
func (ra *ResourceAllocator) ImportAllocations(encryptedData []byte) error {
	data, err := ra.decryptData(encryptedData)
	if err != nil {
		return err
	}

	var allocations map[string]float64
	if err := json.Unmarshal(data, &allocations); err != nil {
		return err
	}

	ra.allocationsMux.Lock()
	defer ra.allocationsMux.Unlock()

	ra.allocations = allocations
	return nil
}

func (ra *ResourceAllocator) encryptData(data []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey(ra.password, salt, 1, 64*1024, 4, 32)
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

	return append(salt, ciphertext...), nil
}

func (ra *ResourceAllocator) decryptData(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("data too short")
	}

	salt := data[:16]
	data = data[16:]

	key := argon2.IDKey(ra.password, salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

// DynamicAllocation adjusts the allocations dynamically based on metrics data.
func (ra *ResourceAllocator) DynamicAllocation(metricName string, threshold float64, adjustmentFactor float64) {
	metricValue := getMetricValue(metricName)

	ra.allocationsMux.Lock()
	defer ra.allocationsMux.Unlock()

	for name, value := range ra.allocations {
		if metricValue > threshold {
			ra.allocations[name] = value * adjustmentFactor
		} else {
			ra.allocations[name] = value / adjustmentFactor
		}
	}
}

func getMetricValue(metricName string) float64 {
	// Placeholder function to get metric values.
	// This should interface with the Prometheus client to get real metrics.
	return prometheus.NewGauge(prometheus.GaugeOpts{
		Name: metricName,
		Help: "Placeholder metric",
	}).Set(1.0)
}
