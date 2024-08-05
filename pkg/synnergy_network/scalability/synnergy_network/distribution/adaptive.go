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
	"math"
	"net"
	"sync"
	"time"
)

// AdaptiveDistribution manages adaptive distribution of data across nodes.
type AdaptiveDistribution struct {
	nodes         []string
	nodeLoad      map[string]int
	mu            sync.RWMutex
	key           []byte
	latencyMatrix map[string]map[string]time.Duration
}

// NewAdaptiveDistribution initializes a new AdaptiveDistribution with an optional passphrase for data encryption.
func NewAdaptiveDistribution(passphrase string) (*AdaptiveDistribution, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &AdaptiveDistribution{
		nodes:         []string{},
		nodeLoad:      make(map[string]int),
		key:           key,
		latencyMatrix: make(map[string]map[string]time.Duration),
	}, nil
}

// AddNode adds a new node to the distribution system.
func (ad *AdaptiveDistribution) AddNode(node string) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.nodes = append(ad.nodes, node)
	ad.nodeLoad[node] = 0
	ad.latencyMatrix[node] = make(map[string]time.Duration)
}

// RemoveNode removes a node from the distribution system.
func (ad *AdaptiveDistribution) RemoveNode(node string) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	delete(ad.nodeLoad, node)
	delete(ad.latencyMatrix, node)
	for _, latencies := range ad.latencyMatrix {
		delete(latencies, node)
	}

	for i, n := range ad.nodes {
		if n == node {
			ad.nodes = append(ad.nodes[:i], ad.nodes[i+1:]...)
			break
		}
	}
}

// DistributeData distributes data to the optimal node based on load and latency.
func (ad *AdaptiveDistribution) DistributeData(data []byte) (string, error) {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	if len(ad.nodes) == 0 {
		return "", errors.New("no nodes available for distribution")
	}

	optimalNode := ad.selectOptimalNode()
	encryptedData, err := encrypt(data, ad.key)
	if err != nil {
		return "", err
	}

	err = ad.sendDataToNode(optimalNode, encryptedData)
	if err != nil {
		return "", err
	}

	ad.mu.Lock()
	ad.nodeLoad[optimalNode]++
	ad.mu.Unlock()

	return optimalNode, nil
}

// selectOptimalNode selects the optimal node for data distribution based on load and latency.
func (ad *AdaptiveDistribution) selectOptimalNode() string {
	var optimalNode string
	minLoad := math.MaxInt32

	for _, node := range ad.nodes {
		load := ad.nodeLoad[node]
		if load < minLoad {
			minLoad = load
			optimalNode = node
		} else if load == minLoad {
			if ad.compareLatency(optimalNode, node) {
				optimalNode = node
			}
		}
	}

	return optimalNode
}

// compareLatency compares the latency between two nodes.
func (ad *AdaptiveDistribution) compareLatency(node1, node2 string) bool {
	totalLatencyNode1 := time.Duration(0)
	totalLatencyNode2 := time.Duration(0)

	for _, node := range ad.nodes {
		totalLatencyNode1 += ad.latencyMatrix[node1][node]
		totalLatencyNode2 += ad.latencyMatrix[node2][node]
	}

	return totalLatencyNode1 < totalLatencyNode2
}

// sendDataToNode sends encrypted data to the specified node.
func (ad *AdaptiveDistribution) sendDataToNode(node string, data []byte) error {
	conn, err := net.Dial("tcp", node)
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

// RecordLatency records the latency between two nodes.
func (ad *AdaptiveDistribution) RecordLatency(node1, node2 string, latency time.Duration) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	if _, exists := ad.latencyMatrix[node1]; !exists {
		ad.latencyMatrix[node1] = make(map[string]time.Duration)
	}
	ad.latencyMatrix[node1][node2] = latency
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
func (ad *AdaptiveDistribution) Export(filename string) error {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	data, err := json.Marshal(ad)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports the distribution system state from a JSON file.
func (ad *AdaptiveDistribution) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, ad)
	if err != nil {
		return err
	}

	return nil
}
