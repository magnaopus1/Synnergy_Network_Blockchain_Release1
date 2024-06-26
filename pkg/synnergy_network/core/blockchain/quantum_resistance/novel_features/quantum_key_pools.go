package novel_features

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// QuantumKey represents a quantum-generated key with metadata
type QuantumKey struct {
	Key       []byte
	CreatedAt time.Time
	Used      bool
}

// QuantumKeyPool manages a pool of quantum-generated keys
type QuantumKeyPool struct {
	keys     []*QuantumKey
	capacity int
	mutex    sync.Mutex
}

// NewQuantumKeyPool creates a new QuantumKeyPool with the specified capacity
func NewQuantumKeyPool(capacity int) *QuantumKeyPool {
	return &QuantumKeyPool{
		keys:     make([]*QuantumKey, 0, capacity),
		capacity: capacity,
	}
}

// GenerateQuantumKey generates a new quantum key
func GenerateQuantumKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// AddKey adds a new key to the pool
func (qp *QuantumKeyPool) AddKey(key []byte) error {
	qp.mutex.Lock()
	defer qp.mutex.Unlock()

	if len(qp.keys) >= qp.capacity {
		return errors.New("key pool is at full capacity")
	}

	quantumKey := &QuantumKey{
		Key:       key,
		CreatedAt: time.Now(),
		Used:      false,
	}

	qp.keys = append(qp.keys, quantumKey)
	return nil
}

// GetKey retrieves an unused key from the pool
func (qp *QuantumKeyPool) GetKey() (*QuantumKey, error) {
	qp.mutex.Lock()
	defer qp.mutex.Unlock()

	for _, key := range qp.keys {
		if !key.Used {
			key.Used = true
			return key, nil
		}
	}
	return nil, errors.New("no available keys in the pool")
}

// ManageKeyPool manages the key pool by adding new keys as needed
func (qp *QuantumKeyPool) ManageKeyPool() {
	for {
		time.Sleep(10 * time.Second)
		qp.mutex.Lock()
		if len(qp.keys) < qp.capacity {
			key, err := GenerateQuantumKey()
			if err == nil {
				qp.keys = append(qp.keys, &QuantumKey{
					Key:       key,
					CreatedAt: time.Now(),
					Used:      false,
				})
			}
		}
		qp.mutex.Unlock()
	}
}

// EncodeKeyPool encodes the key pool to a string format
func (qp *QuantumKeyPool) EncodeKeyPool() (string, error) {
	qp.mutex.Lock()
	defer qp.mutex.Unlock()

	encodedKeys := make([]string, len(qp.keys))
	for i, key := range qp.keys {
		encodedKeys[i] = hex.EncodeToString(key.Key)
	}

	return hex.EncodeToString([]byte(encodedKeys)), nil
}

// DecodeKeyPool decodes the key pool from a string format
func DecodeKeyPool(encoded string) (*QuantumKeyPool, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	keys := make([]*QuantumKey, len(decoded)/32)
	for i := 0; i < len(keys); i++ {
		keys[i] = &QuantumKey{
			Key: decoded[i*32 : (i+1)*32],
		}
	}

	return &QuantumKeyPool{keys: keys}, nil
}

// main function for testing the implementation
func main() {
	qkp := NewQuantumKeyPool(10)

	for i := 0; i < 5; i++ {
		key, _ := GenerateQuantumKey()
		qkp.AddKey(key)
	}

	// Simulate managing the key pool in a separate goroutine
	go qkp.ManageKeyPool()

	time.Sleep(1 * time.Minute) // Wait for some keys to be generated

	key, err := qkp.GetKey()
	if err != nil {
		panic(err)
	}

	println("Retrieved Key:", hex.EncodeToString(key.Key))

	encoded, _ := qkp.EncodeKeyPool()
	println("Encoded Key Pool:", encoded)

	decodedPool, _ := DecodeKeyPool(encoded)
	println("Decoded Key Pool Capacity:", decodedPool.capacity)
}
