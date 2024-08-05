// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including dynamic scaling capabilities for real-world use.
package node

import (
	"fmt"
	"sync"
	"time"
)

// Node represents a blockchain node with dynamic scaling capabilities.
type Node struct {
	ID                string
	CurrentLoad       int
	MaxLoad           int
	Peers             map[string]*Peer
	mutex             sync.Mutex
	ScalingThreshold  int
	ScalingFactor     int
	ScalingCooldown   time.Duration
	LastScalingAction time.Time
}

// Peer represents a peer node in the network.
type Peer struct {
	ID      string
	Address string
	Load    int
}

// NewNode creates a new Node instance.
func NewNode(id string, maxLoad, scalingThreshold, scalingFactor int, scalingCooldown time.Duration) *Node {
	return &Node{
		ID:               id,
		MaxLoad:          maxLoad,
		Peers:            make(map[string]*Peer),
		ScalingThreshold: scalingThreshold,
		ScalingFactor:    scalingFactor,
		ScalingCooldown:  scalingCooldown,
	}
}

// AddPeer adds a new peer to the network.
func (n *Node) AddPeer(peerID, address string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.Peers[peerID] = &Peer{ID: peerID, Address: address}
}

// RemovePeer removes a peer from the network.
func (n *Node) RemovePeer(peerID string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	delete(n.Peers, peerID)
}

// GetPeers returns the list of peers in the network.
func (n *Node) GetPeers() map[string]*Peer {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.Peers
}

// ScaleUp scales up the node's capacity by adding more peers.
func (n *Node) ScaleUp() {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Check cooldown period
	if time.Since(n.LastScalingAction) < n.ScalingCooldown {
		fmt.Println("Scaling action on cooldown. Please wait.")
		return
	}

	newPeers := n.ScalingFactor
	for i := 0; i < newPeers; i++ {
		peerID := fmt.Sprintf("%s-peer-%d", n.ID, len(n.Peers)+1)
		peerAddress := fmt.Sprintf("peer-%d-address", len(n.Peers)+1)
		n.Peers[peerID] = &Peer{ID: peerID, Address: peerAddress}
		fmt.Printf("Added new peer: %s with address: %s\n", peerID, peerAddress)
	}

	n.LastScalingAction = time.Now()
}

// ScaleDown scales down the node's capacity by removing peers.
func (n *Node) ScaleDown() {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Check cooldown period
	if time.Since(n.LastScalingAction) < n.ScalingCooldown {
		fmt.Println("Scaling action on cooldown. Please wait.")
		return
	}

	if len(n.Peers) <= n.ScalingFactor {
		fmt.Println("Cannot scale down below the scaling factor.")
		return
	}

	for i := 0; i < n.ScalingFactor; i++ {
		for peerID := range n.Peers {
			delete(n.Peers, peerID)
			fmt.Printf("Removed peer: %s\n", peerID)
			break
		}
	}

	n.LastScalingAction = time.Now()
}

// MonitorLoad continuously monitors the node's load and triggers scaling actions if needed.
func (n *Node) MonitorLoad() {
	for {
		n.mutex.Lock()
		load := n.CurrentLoad
		n.mutex.Unlock()

		if load > n.ScalingThreshold {
			fmt.Println("High load detected. Initiating scale up.")
			n.ScaleUp()
		} else if load < n.ScalingThreshold/2 && len(n.Peers) > n.ScalingFactor {
			fmt.Println("Low load detected. Initiating scale down.")
			n.ScaleDown()
		}

		time.Sleep(10 * time.Second) // Adjust the monitoring interval as needed
	}
}

// UpdateLoad updates the node's current load.
func (n *Node) UpdateLoad(load int) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.CurrentLoad = load
}

// CalculateOptimalPeers calculates the optimal number of peers based on the current load.
func (n *Node) CalculateOptimalPeers() int {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.MaxLoad / (n.CurrentLoad + 1)
}

// AddLoad distributes additional load to the peers.
func (n *Node) AddLoad(additionalLoad int) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.CurrentLoad += additionalLoad
}

// RemoveLoad reduces load from the peers.
func (n *Node) RemoveLoad(reducedLoad int) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if n.CurrentLoad-reducedLoad < 0 {
		n.CurrentLoad = 0
	} else {
		n.CurrentLoad -= reducedLoad
	}
}
