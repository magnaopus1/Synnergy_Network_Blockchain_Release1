package monitoring

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// NodeHealth represents the health status of a node.
type NodeHealth struct {
	Address      string
	LastChecked  time.Time
	HealthStatus string
}

// NodeMonitor monitors the health and performance of nodes.
type NodeMonitor struct {
	nodes         map[string]NodeHealth
	mu            sync.RWMutex
	monitorFreq   time.Duration
	alertThreshold time.Duration
	alertFunc     func(NodeHealth)
	key           []byte
	shutdownCh    chan struct{}
}

// NewNodeMonitor initializes a new NodeMonitor.
func NewNodeMonitor(passphrase string, monitorFreq, alertThreshold time.Duration, alertFunc func(NodeHealth)) (*NodeMonitor, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &NodeMonitor{
		nodes:         make(map[string]NodeHealth),
		monitorFreq:   monitorFreq,
		alertThreshold: alertThreshold,
		alertFunc:     alertFunc,
		key:           key,
		shutdownCh:    make(chan struct{}),
	}, nil
}

// AddNode adds a new node to the node monitor.
func (nm *NodeMonitor) AddNode(address string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nm.nodes[address] = NodeHealth{
		Address:      address,
		LastChecked:  time.Now(),
		HealthStatus: "Healthy",
	}
}

// RemoveNode removes a node from the node monitor.
func (nm *NodeMonitor) RemoveNode(address string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	delete(nm.nodes, address)
}

// Start begins the node monitoring process.
func (nm *NodeMonitor) Start() {
	go nm.monitorNodes()
}

// Stop stops the node monitoring process.
func (nm *NodeMonitor) Stop() {
	close(nm.shutdownCh)
}

// monitorNodes periodically checks the status of all nodes.
func (nm *NodeMonitor) monitorNodes() {
	ticker := time.NewTicker(nm.monitorFreq)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			nm.checkNodes()
		case <-nm.shutdownCh:
			return
		}
	}
}

// checkNodes checks the status of each node and triggers alerts if necessary.
func (nm *NodeMonitor) checkNodes() {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	for address, health := range nm.nodes {
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			health.HealthStatus = "Unreachable"
			if nm.alertFunc != nil {
				nm.alertFunc(health)
			}
		} else {
			health.HealthStatus = "Healthy"
			conn.Close()
		}
		health.LastChecked = time.Now()
		nm.nodes[address] = health
	}
}

// UpdateNodeHealth updates the last checked time and health status for a node.
func (nm *NodeMonitor) UpdateNodeHealth(address string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if health, exists := nm.nodes[address]; exists {
		health.LastChecked = time.Now()
		health.HealthStatus = "Healthy"
		nm.nodes[address] = health
	}
}

// Export exports the node monitor state to a JSON file.
func (nm *NodeMonitor) Export(filename string) error {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	data, err := json.Marshal(nm.nodes)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports the node monitor state from a JSON file.
func (nm *NodeMonitor) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	var nodes map[string]NodeHealth
	if err := json.Unmarshal(data, &nodes); err != nil {
		return err
	}

	nm.mu.Lock()
	nm.nodes = nodes
	nm.mu.Unlock()

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
