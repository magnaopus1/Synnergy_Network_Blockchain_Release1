package adaptive

import (
	"errors"
	"fmt"
	"sync"
)

// StorageNode represents a storage node in the scalable storage system.
type StorageNode struct {
	ID       string
	Capacity int
	Used     int
	Data     map[string][]byte
}

// ScalableStorage manages a dynamically scalable set of storage nodes.
type ScalableStorage struct {
	mu          sync.Mutex
	nodes       map[string]*StorageNode
	maxCapacity int
}

// NewScalableStorage initializes a new ScalableStorage instance.
func NewScalableStorage(maxCapacity int) *ScalableStorage {
	return &ScalableStorage{
		nodes:       make(map[string]*StorageNode),
		maxCapacity: maxCapacity,
	}
}

// AddNode adds a new storage node to the system.
func (ss *ScalableStorage) AddNode(id string, capacity int) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if _, exists := ss.nodes[id]; exists {
		return errors.New("node already exists")
	}

	ss.nodes[id] = &StorageNode{
		ID:       id,
		Capacity: capacity,
		Used:     0,
		Data:     make(map[string][]byte),
	}

	fmt.Printf("Storage node %s added with capacity %d.\n", id, capacity)
	return nil
}

// RemoveNode removes a storage node from the system.
func (ss *ScalableStorage) RemoveNode(id string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	node, exists := ss.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	if node.Used > 0 {
		return errors.New("cannot remove node with stored data")
	}

	delete(ss.nodes, id)
	fmt.Printf("Storage node %s removed.\n", id)
	return nil
}

// StoreData stores data in a suitable node, scaling if necessary.
func (ss *ScalableStorage) StoreData(key string, data []byte) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	node, err := ss.findNodeWithCapacity(len(data))
	if err != nil {
		if err := ss.scaleUp(len(data)); err != nil {
			return err
		}
		node, err = ss.findNodeWithCapacity(len(data))
		if err != nil {
			return err
		}
	}

	node.Data[key] = data
	node.Used += len(data)
	fmt.Printf("Stored data with key %s in node %s. Current usage: %d/%d.\n", key, node.ID, node.Used, node.Capacity)
	return nil
}

// RetrieveData retrieves data by key from the storage system.
func (ss *ScalableStorage) RetrieveData(key string) ([]byte, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	for _, node := range ss.nodes {
		if data, exists := node.Data[key]; exists {
			return data, nil
		}
	}

	return nil, errors.New("data not found")
}

// DeleteData deletes data by key from the storage system.
func (ss *ScalableStorage) DeleteData(key string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	for _, node := range ss.nodes {
		if data, exists := node.Data[key]; exists {
			node.Used -= len(data)
			delete(node.Data, key)
			fmt.Printf("Deleted data with key %s from node %s. Current usage: %d/%d.\n", key, node.ID, node.Used, node.Capacity)
			return nil
		}
	}

	return errors.New("data not found")
}

// findNodeWithCapacity finds a node with sufficient capacity for the given data size.
func (ss *ScalableStorage) findNodeWithCapacity(size int) (*StorageNode, error) {
	for _, node := range ss.nodes {
		if node.Capacity-node.Used >= size {
			return node, nil
		}
	}
	return nil, errors.New("no node with sufficient capacity found")
}

// scaleUp scales up the storage system by adding a new node to accommodate the data.
func (ss *ScalableStorage) scaleUp(size int) error {
	newNodeID := fmt.Sprintf("node-%d", len(ss.nodes)+1)
	newNodeCapacity := ss.maxCapacity

	err := ss.AddNode(newNodeID, newNodeCapacity)
	if err != nil {
		return err
	}

	fmt.Printf("Scaled up storage system with new node %s.\n", newNodeID)
	return nil
}

// MonitorStorage continuously monitors storage usage and scales the system as needed.
func (ss *ScalableStorage) MonitorStorage(interval int) {
	for {
		ss.mu.Lock()
		totalUsed := 0
		totalCapacity := 0

		for _, node := range ss.nodes {
			totalUsed += node.Used
			totalCapacity += node.Capacity
		}

		if totalUsed > totalCapacity {
			fmt.Println("Total usage exceeds capacity. Scaling up...")
			ss.scaleUp(totalUsed - totalCapacity)
		} else if totalCapacity-totalUsed > ss.maxCapacity {
			fmt.Println("Total capacity significantly exceeds usage. Scaling down...")
			ss.scaleDown()
		}

		ss.mu.Unlock()
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

// scaleDown scales down the storage system by removing underutilized nodes.
func (ss *ScalableStorage) scaleDown() {
	for id, node := range ss.nodes {
		if node.Used == 0 {
			ss.RemoveNode(id)
			fmt.Printf("Storage node %s removed due to underutilization.\n", id)
			return
		}
	}
}
