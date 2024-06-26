// Package file_retrieval implements consistent hashing mechanisms to enhance file distribution and retrieval in the Synnergy Network blockchain.
package file_retrieval

import (
	"hash/fnv"
	"sort"
	"sync"
)

// ConsistentHash manages the distribution of data across nodes using consistent hashing.
type ConsistentHash struct {
	sync.RWMutex
	hashCircle map[uint32]string
	nodes      []uint32
}

// NewConsistentHash initializes a new ConsistentHash.
func NewConsistentHash() *ConsistentHash {
	return &ConsistentHash{
		hashCircle: make(map[uint32]string),
	}
}

// generateHash generates a hash for a node or file.
func generateHash(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key))
	return h.Sum32()
}

// AddNode adds a new node to the hash circle.
func (ch *ConsistentHash) AddNode(nodeIdentifier string) {
	ch.Lock()
	defer ch.Unlock()

	hash := generateHash(nodeIdentifier)
	ch.nodes = append(ch.nodes, hash)
	sort.Slice(ch.nodes, func(i, j int) bool { return ch.nodes[i] < ch.nodes[j] })
	ch.hashCircle[hash] = nodeIdentifier
}

// RemoveNode removes a node from the hash circle.
func (ch *ConsistentHash) RemoveNode(nodeIdentifier string) {
	ch.Lock()
	defer ch.Unlock()

	hash := generateHash(nodeIdentifier)
	index := sort.Search(len(ch.nodes), func(i int) bool { return ch.nodes[i] == hash })
	if index < len(ch.nodes) && ch.nodes[index] == hash {
		ch.nodes = append(ch.nodes[:index], ch.nodes[index+1:]...)
		delete(ch.hashCircle, hash)
	}
}

// GetNode retrieves the node responsible for the given key.
func (ch *ConsistentHash) GetNode(key string) string {
	ch.RLock()
	defer ch.RUnlock()

	hash := generateHash(key)
	index := sort.Search(len(ch.nodes), func(i int) bool { return ch.nodes[i] >= hash })

	if index == len(ch.nodes) {
		index = 0
	}

	return ch.hashCircle[ch.nodes[index]]
}

// Example usage
func main() {
	ch := NewConsistentHash()
	ch.AddNode("Node1")
	ch.AddNode("Node2")
	ch.AddNode("Node3")

	fileKey := "examplefile.txt"
	node := ch.GetNode(fileKey)
	println("File", fileKey, "should be retrieved from", node)
}

