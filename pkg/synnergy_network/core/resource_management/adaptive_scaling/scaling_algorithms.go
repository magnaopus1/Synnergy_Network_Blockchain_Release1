package adaptive_scaling

import (
	"sync"
	"time"
	"log"
	"math/rand"
	"errors"
)

// Node represents a computational node in the network
type Node struct {
	ID             string
	CPU            int
	Memory         int
	NetworkBandwidth int
	IsActive       bool
	LastUpdateTime time.Time
}

// ScalingAlgorithm provides the interface for implementing scaling algorithms
type ScalingAlgorithm interface {
	ScaleUp(nodes []*Node, requiredCapacity int) ([]*Node, error)
	ScaleDown(nodes []*Node, excessCapacity int) ([]*Node, error)
}

// DynamicScaler implements the ScalingAlgorithm interface
type DynamicScaler struct {
	mu                 sync.Mutex
	maxNodes           int
	minNodes           int
	nodeProvisioner    NodeProvisioner
	resourceMonitor    ResourceMonitor
	resourceThresholds ResourceThresholds
}

// ResourceThresholds defines the thresholds for scaling actions
type ResourceThresholds struct {
	CPUUtilizationHigh float64
	CPUUtilizationLow  float64
	MemoryUtilizationHigh float64
	MemoryUtilizationLow  float64
	NetworkUtilizationHigh float64
	NetworkUtilizationLow  float64
}

// NodeProvisioner interface for adding and removing nodes
type NodeProvisioner interface {
	AddNode() (*Node, error)
	RemoveNode(nodeID string) error
}

// ResourceMonitor interface for monitoring resource usage
type ResourceMonitor interface {
	GetCurrentUsage() (cpuUtilization, memoryUtilization, networkUtilization float64, err error)
}

// NewDynamicScaler creates a new instance of DynamicScaler
func NewDynamicScaler(maxNodes, minNodes int, np NodeProvisioner, rm ResourceMonitor, rt ResourceThresholds) *DynamicScaler {
	return &DynamicScaler{
		maxNodes:           maxNodes,
		minNodes:           minNodes,
		nodeProvisioner:    np,
		resourceMonitor:    rm,
		resourceThresholds: rt,
	}
}

// ScaleUp adds new nodes when the resource demand exceeds capacity
func (ds *DynamicScaler) ScaleUp(nodes []*Node, requiredCapacity int) ([]*Node, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if len(nodes) >= ds.maxNodes {
		return nil, errors.New("maximum number of nodes reached, cannot scale up")
	}

	newNode, err := ds.nodeProvisioner.AddNode()
	if err != nil {
		return nil, err
	}

	nodes = append(nodes, newNode)
	log.Printf("Node %s added successfully to scale up resources.", newNode.ID)
	return nodes, nil
}

// ScaleDown removes nodes when there is excess capacity
func (ds *DynamicScaler) ScaleDown(nodes []*Node, excessCapacity int) ([]*Node, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if len(nodes) <= ds.minNodes {
		return nil, errors.New("minimum number of nodes reached, cannot scale down")
	}

	// Logic to find and remove the most idle or least utilized node
	var nodeToRemove *Node
	for _, node := range nodes {
		if node.IsActive && (nodeToRemove == nil || node.LastUpdateTime.Before(nodeToRemove.LastUpdateTime)) {
			nodeToRemove = node
		}
	}

	if nodeToRemove != nil {
		err := ds.nodeProvisioner.RemoveNode(nodeToRemove.ID)
		if err != nil {
			return nil, err
		}
		// Remove the node from the slice
		for i, n := range nodes {
			if n.ID == nodeToRemove.ID {
				nodes = append(nodes[:i], nodes[i+1:]...)
				break
			}
		}
		log.Printf("Node %s removed successfully to scale down resources.", nodeToRemove.ID)
	}

	return nodes, nil
}

// MonitorAndScale monitors resource usage and scales the network up or down
func (ds *DynamicScaler) MonitorAndScale() {
	for {
		cpuUtilization, memoryUtilization, networkUtilization, err := ds.resourceMonitor.GetCurrentUsage()
		if err != nil {
			log.Println("Error getting current usage:", err)
			time.Sleep(time.Minute)
			continue
		}

		if cpuUtilization > ds.resourceThresholds.CPUUtilizationHigh || memoryUtilization > ds.resourceThresholds.MemoryUtilizationHigh || networkUtilization > ds.resourceThresholds.NetworkUtilizationHigh {
			ds.ScaleUp(nil, 1) // Assuming scale-up by 1 node as an example
		} else if cpuUtilization < ds.resourceThresholds.CPUUtilizationLow && memoryUtilization < ds.resourceThresholds.MemoryUtilizationLow && networkUtilization < ds.resourceThresholds.NetworkUtilizationLow {
			ds.ScaleDown(nil, 1) // Assuming scale-down by 1 node as an example
		}

		time.Sleep(time.Minute) // Monitor interval
	}
}

// ExampleNodeProvisioner implements NodeProvisioner for demonstration
type ExampleNodeProvisioner struct{}

// AddNode adds a new node
func (np *ExampleNodeProvisioner) AddNode() (*Node, error) {
	// Implement actual node addition logic
	return &Node{
		ID:             generateNodeID(),
		CPU:            rand.Intn(100) + 50,
		Memory:         rand.Intn(2048) + 1024,
		NetworkBandwidth: rand.Intn(1000) + 500,
		IsActive:       true,
		LastUpdateTime: time.Now(),
	}, nil
}

// RemoveNode removes an existing node
func (np *ExampleNodeProvisioner) RemoveNode(nodeID string) error {
	// Implement actual node removal logic
	log.Printf("Node %s is removed from the provisioner.", nodeID)
	return nil
}

// ExampleResourceMonitor implements ResourceMonitor for demonstration
type ExampleResourceMonitor struct{}

// GetCurrentUsage returns dummy data for resource usage
func (rm *ExampleResourceMonitor) GetCurrentUsage() (float64, float64, float64, error) {
	// Implement actual monitoring logic
	return rand.Float64() * 100, rand.Float64() * 100, rand.Float64() * 100, nil
}

// generateNodeID generates a unique ID for a node
func generateNodeID() string {
	return fmt.Sprintf("node-%d", rand.Intn(100000))
}
