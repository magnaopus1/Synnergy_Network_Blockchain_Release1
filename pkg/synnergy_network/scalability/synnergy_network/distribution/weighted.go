package distribution

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

// WeightedNode represents a node in the weighted distribution system.
type WeightedNode struct {
	Address string
	Weight  int
	Load    int
}

// WeightedDistribution manages weighted distribution of data across nodes.
type WeightedDistribution struct {
	nodes []*WeightedNode
	mu    sync.RWMutex
	key   []byte
}

// NewWeightedDistribution initializes a new WeightedDistribution with an optional passphrase for data encryption.
func NewWeightedDistribution(passphrase string) (*WeightedDistribution, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &WeightedDistribution{
		nodes: []*WeightedNode{},
		key:   key,
	}, nil
}

// AddNode adds a new node to the distribution system with a specified weight.
func (wd *WeightedDistribution) AddNode(address string, weight int) {
	wd.mu.Lock()
	defer wd.mu.Unlock()

	wd.nodes = append(wd.nodes, &WeightedNode{Address: address, Weight: weight, Load: 0})
}

// RemoveNode removes a node from the distribution system.
func (wd *WeightedDistribution) RemoveNode(address string) {
	wd.mu.Lock()
	defer wd.mu.Unlock()

	for i, node := range wd.nodes {
		if node.Address == address {
			wd.nodes = append(wd.nodes[:i], wd.nodes[i+1:]...)
			break
		}
	}
}

// DistributeData distributes data to the optimal node based on weight and current load.
func (wd *WeightedDistribution) DistributeData(data []byte) (string, error) {
	wd.mu.RLock()
	defer wd.mu.RUnlock()

	if len(wd.nodes) == 0 {
		return "", errors.New("no nodes available for distribution")
	}

	optimalNode := wd.selectOptimalNode()
	encryptedData, err := encrypt(data, wd.key)
	if err != nil {
		return "", err
	}

	err = wd.sendDataToNode(optimalNode.Address, encryptedData)
	if err != nil {
		return "", err
	}

	wd.mu.Lock()
	optimalNode.Load++
	wd.mu.Unlock()

	return optimalNode.Address, nil
}

// selectOptimalNode selects the optimal node for data distribution based on weight and current load.
func (wd *WeightedDistribution) selectOptimalNode() *WeightedNode {
	var totalWeight int
	for _, node := range wd.nodes {
		totalWeight += node.Weight
	}

	r := rand.Intn(totalWeight)
	var cumulativeWeight int

	for _, node := range wd.nodes {
		cumulativeWeight += node.Weight
		if r < cumulativeWeight {
			return node
		}
	}

	return wd.nodes[0]
}

// sendDataToNode sends encrypted data to the specified node.
func (wd *WeightedDistribution) sendDataToNode(address string, data []byte) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// generateKey derives a key from the given passphrase using Argon2.
func generateKey(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	return key, nil
}

// encrypt encrypts the given data with the provided key using AES.
func encrypt(data, key []byte) ([]byte, error) {
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

// decrypt decrypts the given data with the provided key using AES.
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// saveToFile saves the data to a file.
func saveToFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}

// loadFromFile loads the data from a file.
func loadFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}

// Export exports the entire distribution system state to a JSON file.
func (wd *WeightedDistribution) Export(filename string) error {
	wd.mu.RLock()
	defer wd.mu.RUnlock()

	data, err := json.Marshal(wd)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports the distribution system state from a JSON file.
func (wd *WeightedDistribution) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, wd)
	if err != nil {
		return err
	}

	return nil
}
