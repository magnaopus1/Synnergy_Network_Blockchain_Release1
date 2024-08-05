package management

import (
	"log"
	"math"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/sidechains/analytics"
	"github.com/synnergy_network/pkg/synnergy_network/sidechains/management/consensus_algorithms"
)

// PredictiveScalingManager handles predictive scaling for the blockchain network
type PredictiveScalingManager struct {
	mutex           sync.Mutex
	analyticsSvc    analytics.Service
	scalingPolicy   ScalingPolicy
	nodes           map[string]NodeStatus
	currentLoad     float64
	targetLoad      float64
	scalingFactor   float64
	consensusSvc    consensus_algorithms.Service
	pollingInterval time.Duration
}

// ScalingPolicy defines the parameters for scaling decisions
type ScalingPolicy struct {
	MaxLoad        float64
	MinLoad        float64
	ScaleUpFactor  float64
	ScaleDownFactor float64
	MaxNodes       int
	MinNodes       int
}

// NodeStatus represents the status of a node in the network
type NodeStatus struct {
	NodeID      string
	IsActive    bool
	LastUpdated time.Time
	Load        float64
}

// NewPredictiveScalingManager creates a new PredictiveScalingManager
func NewPredictiveScalingManager(analyticsSvc analytics.Service, consensusSvc consensus_algorithms.Service, policy ScalingPolicy, pollingInterval time.Duration) *PredictiveScalingManager {
	return &PredictiveScalingManager{
		analyticsSvc:    analyticsSvc,
		consensusSvc:    consensusSvc,
		scalingPolicy:   policy,
		nodes:           make(map[string]NodeStatus),
		pollingInterval: pollingInterval,
	}
}

// UpdateNodeStatus updates the status of a node in the network
func (psm *PredictiveScalingManager) UpdateNodeStatus(status NodeStatus) {
	psm.mutex.Lock()
	defer psm.mutex.Unlock()

	status.LastUpdated = time.Now()
	psm.nodes[status.NodeID] = status
	psm.calculateCurrentLoad()
}

// calculateCurrentLoad calculates the current load of the network
func (psm *PredictiveScalingManager) calculateCurrentLoad() {
	var totalLoad float64
	var activeNodes int

	for _, node := range psm.nodes {
		if node.IsActive {
			totalLoad += node.Load
			activeNodes++
		}
	}

	if activeNodes > 0 {
		psm.currentLoad = totalLoad / float64(activeNodes)
	} else {
		psm.currentLoad = 0
	}
}

// Scale adjusts the number of nodes based on the current load
func (psm *PredictiveScalingManager) Scale() {
	psm.mutex.Lock()
	defer psm.mutex.Unlock()

	if psm.currentLoad > psm.scalingPolicy.MaxLoad {
		psm.scaleUp()
	} else if psm.currentLoad < psm.scalingPolicy.MinLoad {
		psm.scaleDown()
	}
}

// scaleUp adds more nodes to the network to handle the load
func (psm *PredictiveScalingManager) scaleUp() {
	activeNodes := psm.getActiveNodeCount()
	if activeNodes >= psm.scalingPolicy.MaxNodes {
		log.Println("Max nodes reached, cannot scale up further")
		return
	}

	nodesToAdd := int(math.Ceil(psm.currentLoad/psm.scalingPolicy.ScaleUpFactor)) - activeNodes
	if nodesToAdd+activeNodes > psm.scalingPolicy.MaxNodes {
		nodesToAdd = psm.scalingPolicy.MaxNodes - activeNodes
	}

	for i := 0; i < nodesToAdd; i++ {
		nodeID := generateNodeID()
		psm.nodes[nodeID] = NodeStatus{NodeID: nodeID, IsActive: true, Load: 0, LastUpdated: time.Now()}
		psm.consensusSvc.AddNode(nodeID)
		log.Printf("Node %s added to the network\n", nodeID)
	}
}

// scaleDown removes nodes from the network to optimize resource usage
func (psm *PredictiveScalingManager) scaleDown() {
	activeNodes := psm.getActiveNodeCount()
	if activeNodes <= psm.scalingPolicy.MinNodes {
		log.Println("Min nodes reached, cannot scale down further")
		return
	}

	nodesToRemove := activeNodes - int(math.Floor(psm.currentLoad/psm.scalingPolicy.ScaleDownFactor))
	if activeNodes-nodesToRemove < psm.scalingPolicy.MinNodes {
		nodesToRemove = activeNodes - psm.scalingPolicy.MinNodes
	}

	for i := 0; i < nodesToRemove; i++ {
		for nodeID, node := range psm.nodes {
			if node.IsActive {
				node.IsActive = false
				psm.nodes[nodeID] = node
				psm.consensusSvc.RemoveNode(nodeID)
				log.Printf("Node %s removed from the network\n", nodeID)
				break
			}
		}
	}
}

// getActiveNodeCount returns the number of active nodes in the network
func (psm *PredictiveScalingManager) getActiveNodeCount() int {
	var activeNodes int
	for _, node := range psm.nodes {
		if node.IsActive {
			activeNodes++
		}
	}
	return activeNodes
}

// Monitor continuously monitors and scales the network based on load
func (psm *PredictiveScalingManager) Monitor() {
	ticker := time.NewTicker(psm.pollingInterval)
	defer ticker.Stop()

	for range ticker.C {
		psm.calculateCurrentLoad()
		psm.Scale()
	}
}

// generateNodeID generates a unique identifier for a new node
func generateNodeID() string {
	// Implementation for generating a unique node ID (could be a UUID or any unique string generator)
	return fmt.Sprintf("node-%d", time.Now().UnixNano())
}
