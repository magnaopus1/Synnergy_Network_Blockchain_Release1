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

// NodeStatus represents the status of a node in the network.
type NodeStatus struct {
	Address      string
	LastSeen     time.Time
	HealthStatus string
}

// NetworkMonitor monitors the network and tracks the status of nodes.
type NetworkMonitor struct {
	nodes         map[string]NodeStatus
	mu            sync.RWMutex
	monitorFreq   time.Duration
	alertThreshold time.Duration
	alertFunc     func(NodeStatus)
	key           []byte
	shutdownCh    chan struct{}
}

// NewNetworkMonitor initializes a new NetworkMonitor.
func NewNetworkMonitor(passphrase string, monitorFreq, alertThreshold time.Duration, alertFunc func(NodeStatus)) (*NetworkMonitor, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &NetworkMonitor{
		nodes:         make(map[string]NodeStatus),
		monitorFreq:   monitorFreq,
		alertThreshold: alertThreshold,
		alertFunc:     alertFunc,
		key:           key,
		shutdownCh:    make(chan struct{}),
	}, nil
}

// AddNode adds a new node to the network monitor.
func (nm *NetworkMonitor) AddNode(address string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nm.nodes[address] = NodeStatus{
		Address:      address,
		LastSeen:     time.Now(),
		HealthStatus: "Healthy",
	}
}

// RemoveNode removes a node from the network monitor.
func (nm *NetworkMonitor) RemoveNode(address string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	delete(nm.nodes, address)
}

// Start begins the network monitoring process.
func (nm *NetworkMonitor) Start() {
	go nm.monitorNodes()
}

// Stop stops the network monitoring process.
func (nm *NetworkMonitor) Stop() {
	close(nm.shutdownCh)
}

// monitorNodes periodically checks the status of all nodes.
func (nm *NetworkMonitor) monitorNodes() {
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
func (nm *NetworkMonitor) checkNodes() {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	for address, status := range nm.nodes {
		if time.Since(status.LastSeen) > nm.alertThreshold {
			status.HealthStatus = "Unreachable"
			nm.nodes[address] = status
			if nm.alertFunc != nil {
				nm.alertFunc(status)
			}
		} else {
			status.HealthStatus = "Healthy"
			nm.nodes[address] = status
		}
	}
}

// UpdateNodeStatus updates the last seen time for a node.
func (nm *NetworkMonitor) UpdateNodeStatus(address string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if status, exists := nm.nodes[address]; exists {
		status.LastSeen = time.Now()
		status.HealthStatus = "Healthy"
		nm.nodes[address] = status
	}
}

// Export exports the network monitor state to a JSON file.
func (nm *NetworkMonitor) Export(filename string) error {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	data, err := json.Marshal(nm.nodes)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports the network monitor state from a JSON file.
func (nm *NetworkMonitor) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	var nodes map[string]NodeStatus
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

// MonitorNetworkConnectivity checks the network connectivity to each node.
func (nm *NetworkMonitor) MonitorNetworkConnectivity() {
	ticker := time.NewTicker(nm.monitorFreq)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			nm.mu.Lock()
			for address, status := range nm.nodes {
				conn, err := net.DialTimeout("tcp", address, 5*time.Second)
				if err != nil {
					status.HealthStatus = "Unreachable"
					if nm.alertFunc != nil {
						nm.alertFunc(status)
					}
				} else {
					status.HealthStatus = "Healthy"
					conn.Close()
				}
				nm.nodes[address] = status
			}
			nm.mu.Unlock()
		case <-nm.shutdownCh:
			return
		}
	}
}
