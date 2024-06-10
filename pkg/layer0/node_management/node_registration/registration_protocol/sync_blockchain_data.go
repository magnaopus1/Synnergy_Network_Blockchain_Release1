package registration_protocol

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/node_management/node_discovery"
	"github.com/synthron_blockchain_final/pkg/layer0/node_management/node_health_check"
)

type BlockchainSync struct {
	mu           sync.Mutex
	nodes        map[string]*NodeData
	discovery    *node_discovery.NodeDiscovery
	healthCheck  *node_health_check.NodeHealthCheck
}

type NodeData struct {
	ID          string
	Blockchain  []Block
	LastSynced  time.Time
	HealthStats node_health_check.NodeHealthMetrics
}

type Block struct {
	Index     int
	Timestamp string
	Data      string
	Hash      string
	PrevHash  string
}

func NewBlockchainSync(discovery *node_discovery.NodeDiscovery, healthCheck *node_health_check.NodeHealthCheck) *BlockchainSync {
	return &BlockchainSync{
		nodes:       make(map[string]*NodeData),
		discovery:   discovery,
		healthCheck: healthCheck,
	}
}

func (bcs *BlockchainSync) AddNode(nodeID string) error {
	bcs.mu.Lock()
	defer bcs.mu.Unlock()

	if _, exists := bcs.nodes[nodeID]; exists {
		return errors.New("node already exists")
	}

	bcs.nodes[nodeID] = &NodeData{
		ID:          nodeID,
		Blockchain:  []Block{},
		LastSynced:  time.Now(),
		HealthStats: node_health_check.NodeHealthMetrics{},
	}

	return nil
}

func (bcs *BlockchainSync) SyncNodeBlockchain(nodeID string) error {
	bcs.mu.Lock()
	defer bcs.mu.Unlock()

	nodeData, exists := bcs.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	peers := bcs.discovery.GetPeers(nodeID)
	if len(peers) == 0 {
		return errors.New("no peers found for synchronization")
	}

	latestBlockchain := bcs.getLatestBlockchainFromPeers(peers)
	if latestBlockchain == nil {
		return errors.New("failed to get blockchain from peers")
	}

	nodeData.Blockchain = latestBlockchain
	nodeData.LastSynced = time.Now()

	return nil
}

func (bcs *BlockchainSync) getLatestBlockchainFromPeers(peers []string) []Block {
	var latestBlockchain []Block

	for _, peer := range peers {
		peerData, err := bcs.fetchBlockchainFromPeer(peer)
		if err != nil {
			fmt.Printf("Failed to fetch blockchain from peer %s: %v\n", peer, err)
			continue
		}

		if len(peerData) > len(latestBlockchain) {
			latestBlockchain = peerData
		}
	}

	return latestBlockchain
}

func (bcs *BlockchainSync) fetchBlockchainFromPeer(peerID string) ([]Block, error) {
	// Simulate fetching blockchain data from peer
	// In a real-world scenario, this would involve network calls to the peer node
	return []Block{
		{Index: 1, Timestamp: "2022-01-01T00:00:00Z", Data: "Genesis Block", Hash: "abcd1234", PrevHash: ""},
		{Index: 2, Timestamp: "2022-01-02T00:00:00Z", Data: "Block 2", Hash: "efgh5678", PrevHash: "abcd1234"},
	}, nil
}

func (bcs *BlockchainSync) GetNodeHealthStats(nodeID string) (node_health_check.NodeHealthMetrics, error) {
	bcs.mu.Lock()
	defer bcs.mu.Unlock()

	nodeData, exists := bcs.nodes[nodeID]
	if !exists {
		return node_health_check.NodeHealthMetrics{}, errors.New("node not found")
	}

	healthStats, err := bcs.healthCheck.GetHealthMetrics(nodeID)
	if err != nil {
		return node_health_check.NodeHealthMetrics{}, err
	}

	nodeData.HealthStats = healthStats
	return healthStats, nil
}

func (bcs *BlockchainSync) DisplayNodeData(nodeID string) {
	bcs.mu.Lock()
	defer bcs.mu.Unlock()

	nodeData, exists := bcs.nodes[nodeID]
	if !exists {
		fmt.Printf("Node %s not found\n", nodeID)
		return
	}

	fmt.Printf("Node ID: %s\n", nodeID)
	fmt.Printf("Blockchain Length: %d\n", len(nodeData.Blockchain))
	fmt.Printf("Last Synced: %s\n", nodeData.LastSynced)
	fmt.Printf("Health Stats: %+v\n", nodeData.HealthStats)
}

// Main function to demonstrate the process
func main() {
	discovery := node_discovery.NewNodeDiscovery()
	healthCheck := node_health_check.NewNodeHealthCheck()

	blockchainSync := NewBlockchainSync(discovery, healthCheck)
	nodeID := "node123"

	err := blockchainSync.AddNode(nodeID)
	if err != nil {
		fmt.Printf("Error adding node: %v\n", err)
		return
	}

	err = blockchainSync.SyncNodeBlockchain(nodeID)
	if err != nil {
		fmt.Printf("Error syncing blockchain for node %s: %v\n", nodeID, err)
		return
	}

	_, err = blockchainSync.GetNodeHealthStats(nodeID)
	if err != nil {
		fmt.Printf("Error getting health stats for node %s: %v\n", nodeID, err)
		return
	}

	blockchainSync.DisplayNodeData(nodeID)
}
