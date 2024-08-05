package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/sidechains/bridge/cross_chain_messaging"
	"github.com/synnergy_network/pkg/synnergy_network/sidechains/bridge/asset_transfer"
	"github.com/synnergy_network/pkg/synnergy_network/sidechains/management/consensus_algorithms"
)

// MonitoringManager handles the monitoring and analytics of blockchain management
type MonitoringManager struct {
	mutex                  sync.Mutex
	nodeStatus             map[string]NodeStatus
	consensusMetrics       map[string]ConsensusMetrics
	crossChainMessagingSvc cross_chain_messaging.Service
	assetTransferSvc       asset_transfer.Service
	server                 *http.Server
	port                   string
}

// NodeStatus represents the status of a node in the network
type NodeStatus struct {
	NodeID           string    `json:"node_id"`
	Active           bool      `json:"active"`
	LastUpdated      time.Time `json:"last_updated"`
	BlockHeight      int       `json:"block_height"`
	CurrentConsensus string    `json:"current_consensus"`
}

// ConsensusMetrics represents metrics related to the consensus algorithm
type ConsensusMetrics struct {
	Algorithm      string  `json:"algorithm"`
	BlockTime      float64 `json:"block_time"`
	TransactionRate float64 `json:"transaction_rate"`
}

// NewMonitoringManager creates a new MonitoringManager
func NewMonitoringManager(port string) *MonitoringManager {
	return &MonitoringManager{
		nodeStatus:             make(map[string]NodeStatus),
		consensusMetrics:       make(map[string]ConsensusMetrics),
		crossChainMessagingSvc: cross_chain_messaging.NewService(),
		assetTransferSvc:       asset_transfer.NewService(),
		port:                   port,
	}
}

// UpdateNodeStatus updates the status of a node in the network
func (mm *MonitoringManager) UpdateNodeStatus(status NodeStatus) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	status.LastUpdated = time.Now()
	mm.nodeStatus[status.NodeID] = status
}

// GetNodeStatus retrieves the status of a specific node
func (mm *MonitoringManager) GetNodeStatus(nodeID string) (NodeStatus, error) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	status, exists := mm.nodeStatus[nodeID]
	if !exists {
		return NodeStatus{}, errors.New("node not found")
	}
	return status, nil
}

// UpdateConsensusMetrics updates the metrics of a consensus algorithm
func (mm *MonitoringManager) UpdateConsensusMetrics(algorithm string, metrics ConsensusMetrics) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	mm.consensusMetrics[algorithm] = metrics
}

// GetConsensusMetrics retrieves the metrics of a specific consensus algorithm
func (mm *MonitoringManager) GetConsensusMetrics(algorithm string) (ConsensusMetrics, error) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	metrics, exists := mm.consensusMetrics[algorithm]
	if !exists {
		return ConsensusMetrics{}, errors.New("consensus algorithm not found")
	}
	return metrics, nil
}

// StartServer starts the HTTP server for monitoring management
func (mm *MonitoringManager) StartServer() {
	mm.server = &http.Server{
		Addr:    ":" + mm.port,
		Handler: mm.setupRoutes(),
	}
	log.Printf("Starting monitoring server on port %s", mm.port)
	if err := mm.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not start server: %s", err)
	}
}

// setupRoutes sets up the HTTP routes for monitoring management
func (mm *MonitoringManager) setupRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/node_status", mm.handleNodeStatus)
	mux.HandleFunc("/consensus_metrics", mm.handleConsensusMetrics)
	return mux
}

// handleNodeStatus handles the retrieval and update of node statuses
func (mm *MonitoringManager) handleNodeStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		nodeID := r.URL.Query().Get("node_id")
		if nodeID == "" {
			http.Error(w, "missing node ID", http.StatusBadRequest)
			return
		}

		status, err := mm.GetNodeStatus(nodeID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		if err := json.NewEncoder(w).Encode(status); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

	case http.MethodPost:
		var status NodeStatus
		if err := json.NewDecoder(r.Body).Decode(&status); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		mm.UpdateNodeStatus(status)
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleConsensusMetrics handles the retrieval and update of consensus metrics
func (mm *MonitoringManager) handleConsensusMetrics(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		algorithm := r.URL.Query().Get("algorithm")
		if algorithm == "" {
			http.Error(w, "missing algorithm", http.StatusBadRequest)
			return
		}

		metrics, err := mm.GetConsensusMetrics(algorithm)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		if err := json.NewEncoder(w).Encode(metrics); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

	case http.MethodPost:
		var metrics ConsensusMetrics
		if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		mm.UpdateConsensusMetrics(metrics.Algorithm, metrics)
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// StopServer stops the HTTP server for monitoring management
func (mm *MonitoringManager) StopServer() {
	if mm.server != nil {
		if err := mm.server.Close(); err != nil {
			log.Fatalf("Could not stop server: %s", err)
		}
	}
}

// LogEvent logs important events related to monitoring management
func (mm *MonitoringManager) LogEvent(event string) {
	log.Println(event)
}

// AddConsensusAlgorithm adds a new consensus algorithm for monitoring
func (mm *MonitoringManager) AddConsensusAlgorithm(name string, algorithm consensus_algorithms.ConsensusAlgorithm) error {
	return consensus_algorithms.RegisterAlgorithm(name, algorithm)
}
