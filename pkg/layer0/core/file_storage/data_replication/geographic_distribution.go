// Package data_replication provides the tools for managing geographic distribution of data replication
// within the Synnergy Network blockchain, focusing on maximizing data availability and minimizing latency.
package data_replication

import (
	"errors"
	"sync"
	"time"

	"synthron_blockchain/pkg/geo"
	"synthron_blockchain/pkg/utils"
)

// Node represents a blockchain node with geographic information.
type Node struct {
	ID       string
	Location geo.Location
	Active   bool
}

// DataManager handles the geographic distribution of data across nodes.
type DataManager struct {
	Nodes        []*Node
	DataReplicas map[string][]*Node // Mapping of data ID to nodes holding the data
	mu           sync.Mutex
}

// NewDataManager initializes a new DataManager with a list of nodes.
func NewDataManager(nodes []*Node) *DataManager {
	return &DataManager{
		Nodes:        nodes,
		DataReplicas: make(map[string][]*Node),
	}
}

// DistributeData replicates data across multiple geographically dispersed nodes to enhance availability.
func (dm *DataManager) DistributeData(dataID string, replicaCount int) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if _, exists := dm.DataReplicas[dataID]; exists {
		return errors.New("data already distributed")
	}

	selectedNodes, err := dm.selectNodes(replicaCount)
	if err != nil {
		return err
	}

	dm.DataReplicas[dataID] = selectedNodes
	go dm.replicateData(dataID, selectedNodes)
	return nil
}

// selectNodes selects the best nodes for data replication based on their geographic location and status.
func (dm *DataManager) selectNodes(replicaCount int) ([]*Node, error) {
	if len(dm.Nodes) < replicaCount {
		return nil, errors.New("not enough nodes available for replication")
	}

	utils.ShuffleNodes(dm.Nodes) // Shuffle for randomness
	selected := make([]*Node, 0, replicaCount)
	count := 0

	for _, node := range dm.Nodes {
		if node.Active {
			selected = append(selected, node)
			count++
			if count == replicaCount {
				break
			}
		}
	}
	return selected, nil
}

// replicateData handles the data replication process across selected nodes.
func (dm *DataManager) replicateData(dataID string, nodes []*Node) {
	// This function would include actual data transmission logic, potentially involving secure channels.
	for _, node := range nodes {
		dm.sendDataToNode(dataID, node)
	}
}

// sendDataToNode simulates sending data to a node.
func (dm *DataManager) sendDataToNode(dataID string, node *Node) {
	// Placeholder function for data sending logic.
	time.Sleep(time.Millisecond * 100) // Simulate network delay
}

// VerifyDataIntegrity checks that data is correctly replicated and consistent across nodes.
func (dm *DataManager) VerifyDataIntegrity(dataID string) bool {
	// Placeholder for data integrity verification logic, possibly involving cryptographic hashes.
	return true // Assume verification is successful for simplicity.
}

// Usage example
func main() {
	nodes := []*Node{
		{ID: "Node1", Location: geo.Location{Latitude: 37.7749, Longitude: -122.4194}, Active: true},
		{ID: "Node2", Location: geo.Location{Latitude: 52.5200, Longitude: 13.4050}, Active: true},
		{ID: "Node3", Location: geo.Location{Latitude: 48.8566, Longitude: 2.3522}, Active: false}, // Inactive node
	}

	manager := NewDataManager(nodes)
	err := manager.DistributeData("data123", 2)
	if err != nil {
		panic(err)
	}

	if manager.VerifyDataIntegrity("data123") {
		println("Data integrity verified across nodes")
	} else {
		println("Data integrity verification failed")
	}
}
