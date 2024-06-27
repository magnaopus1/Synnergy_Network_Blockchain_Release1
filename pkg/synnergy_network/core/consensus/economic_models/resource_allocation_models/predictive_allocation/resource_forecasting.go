package predictive_allocation

import (
	"math"
	"sync"
	"time"
)

// ResourceForecast represents the resource forecast data structure
type ResourceForecast struct {
	NodeID      string
	Allocated   int
	Predicted   int
	Confidence  float64
	LastUpdated time.Time
}

// NetworkState represents the current state of the network
type NetworkState struct {
	mu        sync.Mutex
	Nodes     map[string]*ResourceForecast
	TotalLoad int
}

// NewNetworkState initializes a new NetworkState
func NewNetworkState() *NetworkState {
	return &NetworkState{
		Nodes:     make(map[string]*ResourceForecast),
		TotalLoad: 0,
	}
}

// UpdateNodeLoad updates the current load and prediction for a node
func (n *NetworkState) UpdateNodeLoad(nodeID string, load int, confidence float64) {
	n.mu.Lock()
	defer n.mu.Unlock()

	node, exists := n.Nodes[nodeID]
	if !exists {
		node = &ResourceForecast{NodeID: nodeID}
		n.Nodes[nodeID] = node
	}

	node.Allocated = load
	node.Predicted = int(math.Round(float64(load) * (1 + confidence)))
	node.Confidence = confidence
	node.LastUpdated = time.Now()
	n.TotalLoad += load
}

// PredictiveAllocation allocates resources based on predictions
func (n *NetworkState) PredictiveAllocation(totalResources int) map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()

	allocation := make(map[string]int)
	totalPredicted := 0

	for _, node := range n.Nodes {
		totalPredicted += node.Predicted
	}

	for id, node := range n.Nodes {
		allocation[id] = int(math.Round(float64(node.Predicted) / float64(totalPredicted) * float64(totalResources)))
	}

	return allocation
}

// RemoveNode removes a node from the network state
func (n *NetworkState) RemoveNode(nodeID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.Nodes, nodeID)
}

// GetNodeForecast returns the resource forecast for a node
func (n *NetworkState) GetNodeForecast(nodeID string) (*ResourceForecast, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	node, exists := n.Nodes[nodeID]
	return node, exists
}

// ListNodeForecasts lists all node forecasts
func (n *NetworkState) ListNodeForecasts() []*ResourceForecast {
	n.mu.Lock()
	defer n.mu.Unlock()
	forecasts := []*ResourceForecast{}
	for _, forecast := range n.Nodes {
		forecasts = append(forecasts, forecast)
	}
	return forecasts
}

// EconomicModel represents an economic model for predictive resource allocation
type EconomicModel struct {
	networkState *NetworkState
}

// NewEconomicModel initializes a new EconomicModel
func NewEconomicModel() *EconomicModel {
	return &EconomicModel{
		networkState: NewNetworkState(),
	}
}

// AllocateResourcesBasedOnPredictions allocates resources based on predictions and network state
func (e *EconomicModel) AllocateResourcesBasedOnPredictions(totalResources int) map[string]int {
	return e.networkState.PredictiveAllocation(totalResources)
}

// UpdateNetworkLoad updates the network load and predictions
func (e *EconomicModel) UpdateNetworkLoad(nodeID string, load int, confidence float64) {
	e.networkState.UpdateNodeLoad(nodeID, load, confidence)
}

// RemoveNetworkNode removes a node from the network
func (e *EconomicModel) RemoveNetworkNode(nodeID string) {
	e.networkState.RemoveNode(nodeID)
}

// GetNetworkNodeForecast returns the forecast for a specific node
func (e *EconomicModel) GetNetworkNodeForecast(nodeID string) (*ResourceForecast, bool) {
	return e.networkState.GetNodeForecast(nodeID)
}

// ListNetworkNodeForecasts lists all node forecasts in the network
func (e *EconomicModel) ListNetworkNodeForecasts() []*ResourceForecast {
	return e.networkState.ListNodeForecasts()
}
