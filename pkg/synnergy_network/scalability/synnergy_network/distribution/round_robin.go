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
	"net"
	"sync"
	"time"
)

// RoundRobinDistribution manages round-robin distribution of data across nodes.
type RoundRobinDistribution struct {
	nodes []string
	index int
	mu    sync.RWMutex
	key   []byte
}

// NewRoundRobinDistribution initializes a new RoundRobinDistribution with an optional passphrase for data encryption.
func NewRoundRobinDistribution(passphrase string) (*RoundRobinDistribution, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &RoundRobinDistribution{
		nodes: []string{},
		index: 0,
		key:   key,
	}, nil
}

// AddNode adds a new node to the distribution system.
func (rr *RoundRobinDistribution) AddNode(node string) {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	rr.nodes = append(rr.nodes, node)
}

// RemoveNode removes a node from the distribution system.
func (rr *RoundRobinDistribution) RemoveNode(node string) {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	for i, n := range rr.nodes {
		if n == node {
			rr.nodes = append(rr.nodes[:i], rr.nodes[i+1:]...)
			if rr.index >= len(rr.nodes) {
				rr.index = 0
			}
			break
		}
	}
}

// DistributeData distributes data to the next node in a round-robin fashion.
func (rr *RoundRobinDistribution) DistributeData(data []byte) (string, error) {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	if len(rr.nodes) == 0 {
		return "", errors.New("no nodes available for distribution")
	}

	encryptedData, err := encrypt(data, rr.key)
	if err != nil {
		return "", err
	}

	node := rr.nodes[rr.index]
	err = rr.sendDataToNode(node, encryptedData)
	if err != nil {
		return "", err
	}

	rr.index = (rr.index + 1) % len(rr.nodes)

	return node, nil
}

// sendDataToNode sends encrypted data to the specified node.
func (rr *RoundRobinDistribution) sendDataToNode(node string, data []byte) error {
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
func (rr *RoundRobinDistribution) Export(filename string) error {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	data, err := json.Marshal(rr)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports the distribution system state from a JSON file.
func (rr *RoundRobinDistribution) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, rr)
	if err != nil {
		return err
	}

	return nil
}
