package adaptive_scaling

import (
    "errors"
    "log"
    "sync"
)

// Shard represents a shard within the blockchain network
type Shard struct {
    ID          int
    Nodes       []*Node
    TransactionLoad int
}

// Node represents a node within the blockchain network
type Node struct {
    ID       int
    Capacity int
    Load     int
}

// ShardAllocator handles the allocation of nodes to shards
type ShardAllocator struct {
    Shards       []*Shard
    Nodes        []*Node
    mutex        sync.Mutex
    AlertChannel chan string
}

// NewShardAllocator initializes a new ShardAllocator
func NewShardAllocator(shards []*Shard, nodes []*Node) *ShardAllocator {
    return &ShardAllocator{
        Shards:       shards,
        Nodes:        nodes,
        AlertChannel: make(chan string),
    }
}

// AllocateNodes dynamically allocates nodes to shards based on load and capacity
func (sa *ShardAllocator) AllocateNodes() {
    sa.mutex.Lock()
    defer sa.mutex.Unlock()

    for _, node := range sa.Nodes {
        if node.Load == 0 {
            continue
        }

        // Find the least loaded shard with available capacity
        bestShard := sa.findBestShard(node)
        if bestShard != nil {
            bestShard.Nodes = append(bestShard.Nodes, node)
            bestShard.TransactionLoad += node.Load
            log.Printf("Node %d allocated to Shard %d", node.ID, bestShard.ID)
        } else {
            sa.AlertChannel <- "No suitable shard found for node allocation"
        }
    }
}

// findBestShard finds the best shard for a given node
func (sa *ShardAllocator) findBestShard(node *Node) *Shard {
    var bestShard *Shard
    for _, shard := range sa.Shards {
        if shard.TransactionLoad+node.Load <= node.Capacity {
            if bestShard == nil || shard.TransactionLoad < bestShard.TransactionLoad {
                bestShard = shard
            }
        }
    }
    return bestShard
}

// MonitorAndReallocate continuously monitors shard loads and reallocates nodes as necessary
func (sa *ShardAllocator) MonitorAndReallocate() {
    for {
        sa.AllocateNodes()
        sa.detectOverloadAndReallocate()
        time.Sleep(10 * time.Second) // Adjust as needed
    }
}

// detectOverloadAndReallocate detects overloaded shards and reallocates nodes
func (sa *ShardAllocator) detectOverloadAndReallocate() {
    sa.mutex.Lock()
    defer sa.mutex.Unlock()

    for _, shard := range sa.Shards {
        if shard.TransactionLoad > shard.Nodes[0].Capacity { // Assuming homogeneous node capacity
            sa.AlertChannel <- "Shard overload detected"
            sa.rebalanceShard(shard)
        }
    }
}

// rebalanceShard rebalances the nodes in an overloaded shard
func (sa *ShardAllocator) rebalanceShard(overloadedShard *Shard) {
    for _, node := range overloadedShard.Nodes {
        bestShard := sa.findBestShard(node)
        if bestShard != nil && bestShard.ID != overloadedShard.ID {
            bestShard.Nodes = append(bestShard.Nodes, node)
            bestShard.TransactionLoad += node.Load
            overloadedShard.TransactionLoad -= node.Load
            overloadedShard.Nodes = removeNode(overloadedShard.Nodes, node)
            log.Printf("Node %d reallocated from Shard %d to Shard %d", node.ID, overloadedShard.ID, bestShard.ID)
            return
        }
    }
}

// removeNode removes a node from a slice of nodes
func removeNode(nodes []*Node, nodeToRemove *Node) []*Node {
    for i, node := range nodes {
        if node.ID == nodeToRemove.ID {
            return append(nodes[:i], nodes[i+1:]...)
        }
    }
    return nodes
}

// AddNode adds a new node to the network and allocates it to a shard
func (sa *ShardAllocator) AddNode(node *Node) error {
    sa.mutex.Lock()
    defer sa.mutex.Unlock()

    sa.Nodes = append(sa.Nodes, node)
    bestShard := sa.findBestShard(node)
    if bestShard != nil {
        bestShard.Nodes = append(bestShard.Nodes, node)
        bestShard.TransactionLoad += node.Load
        log.Printf("New Node %d added and allocated to Shard %d", node.ID, bestShard.ID)
        return nil
    }
    return errors.New("no suitable shard found for the new node")
}

// RemoveNode removes a node from the network
func (sa *ShardAllocator) RemoveNode(nodeID int) error {
    sa.mutex.Lock()
    defer sa.mutex.Unlock()

    for i, node := range sa.Nodes {
        if node.ID == nodeID {
            sa.Nodes = append(sa.Nodes[:i], sa.Nodes[i+1:]...)
            for _, shard := range sa.Shards {
                shard.Nodes = removeNode(shard.Nodes, node)
                shard.TransactionLoad -= node.Load
                log.Printf("Node %d removed from Shard %d", nodeID, shard.ID)
                return nil
            }
        }
    }
    return errors.New("node not found")
}
