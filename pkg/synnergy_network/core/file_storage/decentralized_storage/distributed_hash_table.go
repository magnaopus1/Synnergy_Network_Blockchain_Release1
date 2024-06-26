// Package decentralized_storage implements a Distributed Hash Table (DHT) for the Synnergy Network blockchain.
// This file provides the functionality for storing and retrieving data in a decentralized manner, enhancing the security and reliability of the network.
package decentralized_storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"synthron_blockchain/pkg/crypto"
	"synthron_blockchain/pkg/network"
)

// Node represents a participant in the decentralized storage network.
type Node struct {
	ID       string
	Address  string
	Data     map[string]string // data store with key as hash and value as the data content
	Capacity int64             // Capacity in bytes
}

// DHT defines the structure for the distributed hash table.
type DHT struct {
	Nodes []Node
	mu    sync.Mutex
}

// NewDHT initializes a new distributed hash table.
func NewDHT() *DHT {
	return &DHT{}
}

// AddNode adds a new node to the DHT.
func (dht *DHT) AddNode(node Node) {
	dht.mu.Lock()
	defer dht.mu.Unlock()
	dht.Nodes = append(dht.Nodes, node)
}

// Store stores data in the DHT, distributing it based on hash keys.
func (dht *DHT) Store(data string) error {
	dht.mu.Lock()
	defer dht.mu.Unlock()

	hash := sha256.Sum256([]byte(data))
	key := hex.EncodeToString(hash[:])

	// Simulating data distribution by randomly selecting a node for storage
	nodeIndex := crypto.RandomInt(len(dht.Nodes))
	dht.Nodes[nodeIndex].Data[key] = data

	fmt.Printf("Data stored on node %s at key %s\n", dht.Nodes[nodeIndex].ID, key)
	return nil
}

// Retrieve retrieves data from the DHT using its hash key.
func (dht *DHT) Retrieve(key string) (string, error) {
	for _, node := range dht.Nodes {
		if data, found := node.Data[key]; found {
			return data, nil
		}
	}
	return "", fmt.Errorf("data not found")
}

// handleRequests manages network requests for data storage and retrieval.
func (dht *DHT) handleRequests() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer listener.Close()

	fmt.Println("Listening for connections on port :8080")
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			continue
		}
		go dht.handleConnection(conn)
	}
}

// handleConnection processes individual network connections for storing and retrieving data.
func (dht *DHT) handleConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 1024)
	len, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
		return
	}
	message := string(buffer[:len])

	// Example operation handling
	if message == "store" {
		data := "Data to store" // Placeholder
		_ = dht.Store(data)
	} else {
		_, _ = dht.Retrieve(message) // Assuming message is the key
	}
}

// Example usage
func main() {
	dht := NewDHT()
	dht.AddNode(Node{ID: "node1", Address: "192.168.1.1", Data: make(map[string]string), Capacity: 1000})

	// Start network handling
	go dht.handleRequests()

	// Store and retrieve data
	if err := dht.Store("Hello, Synnergy Network!"); err != nil {
		fmt.Println("Error storing data:", err)
	}

	retrievedData, err := dht.Retrieve("somehashkey")
	if err != nil {
		fmt.Println("Error retrieving data:", err)
	} else {
		fmt.Println("Retrieved data:", retrievedData)
	}
}
