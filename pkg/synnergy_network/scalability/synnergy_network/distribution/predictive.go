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

// PredictiveDistribution manages predictive distribution of data across nodes.
type PredictiveDistribution struct {
	nodes         []string
	nodeLoad      map[string]int
	nodePredicted map[string]int
	mu            sync.RWMutex
	key           []byte
	latencyMatrix map[string]map[string]time.Duration
	predictionFn  func(string, map[string]int, map[string]time.Duration) int
}

// NewPredictiveDistribution initializes a new PredictiveDistribution with an optional passphrase for data encryption.
func NewPredictiveDistribution(passphrase string, predictionFn func(string, map[string]int, map[string]time.Duration) int) (*PredictiveDistribution, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &PredictiveDistribution{
		nodes:         []string{},
		nodeLoad:      make(map[string]int),
		nodePredicted: make(map[string]int),
		key:           key,
		latencyMatrix: make(map[string]map[string]time.Duration),
		predictionFn:  predictionFn,
	}, nil
}

// AddNode adds a new node to the distribution system.
func (pd *PredictiveDistribution) AddNode(node string) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	pd.nodes = append(pd.nodes, node)
	pd.nodeLoad[node] = 0
	pd.nodePredicted[node] = 0
	pd.latencyMatrix[node] = make(map[string]time.Duration)
}

// RemoveNode removes a node from the distribution system.
func (pd *PredictiveDistribution) RemoveNode(node string) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	delete(pd.nodeLoad, node)
	delete(pd.nodePredicted, node)
	delete(pd.latencyMatrix, node)
	for _, latencies := range pd.latencyMatrix {
		delete(latencies, node)
	}

	for i, n := range pd.nodes {
		if n == node {
			pd.nodes = append(pd.nodes[:i], pd.nodes[i+1:]...)
			break
		}
	}
}

// DistributeData distributes data to the optimal node based on predictive load and latency.
func (pd *PredictiveDistribution) DistributeData(data []byte) (string, error) {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	if len(pd.nodes) == 0 {
		return "", errors.New("no nodes available for distribution")
	}

	optimalNode := pd.selectOptimalNode()
	encryptedData, err := encrypt(data, pd.key)
	if err != nil {
		return "", err
	}

	err = pd.sendDataToNode(optimalNode, encryptedData)
	if err != nil {
		return "", err
	}

	pd.mu.Lock()
	pd.nodeLoad[optimalNode]++
	pd.mu.Unlock()

	return optimalNode, nil
}

// selectOptimalNode selects the optimal node for data distribution based on predicted load and latency.
func (pd *PredictiveDistribution) selectOptimalNode() string {
	var optimalNode string
	minPredictedLoad := math.MaxInt32

	for _, node := range pd.nodes {
		predictedLoad := pd.predictionFn(node, pd.nodeLoad, pd.latencyMatrix[node])
		if predictedLoad < minPredictedLoad {
			minPredictedLoad = predictedLoad
			optimalNode = node
		} else if predictedLoad == minPredictedLoad {
			if pd.compareLatency(optimalNode, node) {
				optimalNode = node
			}
		}
	}

	return optimalNode
}

// compareLatency compares the latency between two nodes.
func (pd *PredictiveDistribution) compareLatency(node1, node2 string) bool {
	totalLatencyNode1 := time.Duration(0)
	totalLatencyNode2 := time.Duration(0)

	for _, node := range pd.nodes {
		totalLatencyNode1 += pd.latencyMatrix[node1][node]
		totalLatencyNode2 += pd.latencyMatrix[node2][node]
	}

	return totalLatencyNode1 < totalLatencyNode2
}

// sendDataToNode sends encrypted data to the specified node.
func (pd *PredictiveDistribution) sendDataToNode(node string, data []byte) error {
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
func (pd *PredictiveDistribution) RecordLatency(node1, node2 string, latency time.Duration) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if _, exists := pd.latencyMatrix[node1]; !exists {
		pd.latencyMatrix[node1] = make(map[string]time.Duration)
	}
	pd.latencyMatrix[node1][node2] = latency
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
func (pd *PredictiveDistribution) Export(filename string) error {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	data, err := json.Marshal(pd)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports the distribution system state from a JSON file.
func (pd *PredictiveDistribution) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, pd)
	if err != nil {
		return err
	}

	return nil
}
