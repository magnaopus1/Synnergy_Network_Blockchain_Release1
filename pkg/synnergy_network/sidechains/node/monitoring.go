// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including monitoring capabilities for real-world use.
package node

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// Node represents a blockchain node with monitoring capabilities.
type Node struct {
	ID               string
	Address          string
	Peers            map[string]*Peer
	mutex            sync.Mutex
	MonitoringAPI    *MonitoringAPI
	Metrics          Metrics
}

// Peer represents a peer node in the network.
type Peer struct {
	ID      string
	Address string
	Load    int
}

// Metrics represents the metrics for a node.
type Metrics struct {
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
	NetworkIO   float64
}

// MonitoringAPI represents the monitoring API for node interactions.
type MonitoringAPI struct {
	Node   *Node
	Server *http.Server
}

// NewNode creates a new Node instance with specified parameters.
func NewNode(id, address string) *Node {
	return &Node{
		ID:            id,
		Address:       address,
		Peers:         make(map[string]*Peer),
		MonitoringAPI: &MonitoringAPI{},
		Metrics:       Metrics{},
	}
}

// StartMonitoringAPI starts the monitoring API server for the node.
func (api *MonitoringAPI) StartMonitoringAPI(port int) error {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", api.MetricsHandler)
	mux.HandleFunc("/peers", api.PeersHandler)
	mux.HandleFunc("/addPeer", api.AddPeerHandler)
	mux.HandleFunc("/removePeer", api.RemovePeerHandler)

	api.Server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		if err := api.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Error starting Monitoring API server: %v\n", err)
		}
	}()
	log.Printf("Monitoring API server started on port %d\n", port)
	return nil
}

// StopMonitoringAPI stops the monitoring API server for the node.
func (api *MonitoringAPI) StopMonitoringAPI() error {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	if api.Server != nil {
		if err := api.Server.Close(); err != nil {
			return err
		}
		log.Println("Monitoring API server stopped")
	}
	return nil
}

// MetricsHandler handles requests for node metrics.
func (api *MonitoringAPI) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	metrics := api.Node.Metrics
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// PeersHandler handles requests for the list of peers.
func (api *MonitoringAPI) PeersHandler(w http.ResponseWriter, r *http.Request) {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	peers := make([]*Peer, 0, len(api.Node.Peers))
	for _, peer := range api.Node.Peers {
		peers = append(peers, peer)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

// AddPeerHandler handles requests to add a new peer.
func (api *MonitoringAPI) AddPeerHandler(w http.ResponseWriter, r *http.Request) {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	var peer Peer
	if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, exists := api.Node.Peers[peer.ID]; exists {
		http.Error(w, "Peer already exists", http.StatusConflict)
		return
	}

	api.Node.Peers[peer.ID] = &peer
	w.WriteHeader(http.StatusCreated)
}

// RemovePeerHandler handles requests to remove a peer.
func (api *MonitoringAPI) RemovePeerHandler(w http.ResponseWriter, r *http.Request) {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	var peer Peer
	if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, exists := api.Node.Peers[peer.ID]; !exists {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}

	delete(api.Node.Peers, peer.ID)
	w.WriteHeader(http.StatusOK)
}

// UpdateMetrics updates the metrics of the node.
func (n *Node) UpdateMetrics(cpu, memory, disk, network float64) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.Metrics = Metrics{
		CPUUsage:    cpu,
		MemoryUsage: memory,
		DiskUsage:   disk,
		NetworkIO:   network,
	}
}

// MonitorMetrics monitors and updates the node metrics periodically.
func (n *Node) MonitorMetrics(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		// Simulate metric collection
		cpu := getCPUUsage()
		memory := getMemoryUsage()
		disk := getDiskUsage()
		network := getNetworkIO()

		n.UpdateMetrics(cpu, memory, disk, network)
	}
}

// Simulated functions for metric collection (replace with real implementations)
func getCPUUsage() float64    { return 30.5 }
func getMemoryUsage() float64 { return 40.2 }
func getDiskUsage() float64   { return 50.8 }
func getNetworkIO() float64   { return 60.1 }

// Example usage:
// func main() {
// 	node := NewNode("node-1", "address-1")
// 	go node.MonitorMetrics(10 * time.Second)
// 	node.MonitoringAPI.StartMonitoringAPI(8080)
// 	defer node.MonitoringAPI.StopMonitoringAPI()
// }
