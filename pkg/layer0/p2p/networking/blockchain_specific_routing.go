package networking

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/synthron_blockchain/pkg/layer0/p2p/messaging"
)

// Node represents a node in the blockchain network
type Node struct {
	ID           string
	Address      string
	neighbors    map[string]*Node
	routingTable map[string]string
	mutex        sync.Mutex
	messageChan  chan messaging.SecureMessage
}

// NewNode creates a new blockchain network node
func NewNode(id, address string) *Node {
	return &Node{
		ID:           id,
		Address:      address,
		neighbors:    make(map[string]*Node),
		routingTable: make(map[string]string),
		messageChan:  make(chan messaging.SecureMessage, 100),
	}
}

// AddNeighbor adds a neighbor node
func (n *Node) AddNeighbor(neighbor *Node) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.neighbors[neighbor.ID] = neighbor
}

// RemoveNeighbor removes a neighbor node
func (n *Node) RemoveNeighbor(neighborID string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	delete(n.neighbors, neighborID)
}

// UpdateRoutingTable updates the routing table with new entries
func (n *Node) UpdateRoutingTable(nodeID, address string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.routingTable[nodeID] = address
}

// RouteMessage routes a message based on the content and network topology
func (n *Node) RouteMessage(message messaging.SecureMessage) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Determine the next hop based on message content and routing table
	nextHopID, exists := n.routingTable[message.Metadata.ReceiverID]
	if !exists {
		return errors.New("no route to receiver")
	}

	nextHop, neighborExists := n.neighbors[nextHopID]
	if !neighborExists {
		return errors.New("next hop neighbor does not exist")
	}

	// Send the message to the next hop
	nextHop.ReceiveMessage(message)
	return nil
}

// ReceiveMessage processes an incoming message
func (n *Node) ReceiveMessage(message messaging.SecureMessage) {
	n.messageChan <- message
}

// ProcessMessages processes messages from the message channel
func (n *Node) ProcessMessages() {
	for message := range n.messageChan {
		fmt.Printf("Node %s received message: %s\n", n.ID, string(message.Content))

		// Check if the message is for this node
		if message.Metadata.ReceiverID == n.ID {
			fmt.Printf("Node %s processing message: %s\n", n.ID, string(message.Content))
			continue
		}

		// Route the message to the next hop
		err := n.RouteMessage(message)
		if err != nil {
			fmt.Printf("Node %s failed to route message: %s\n", n.ID, err)
		}
	}
}

// SecureHash generates a secure hash for routing table entries
func SecureHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// DiscoverPeers discovers peers using Kademlia DHT
func (n *Node) DiscoverPeers() {
	// Simulated peer discovery
	for i := 0; i < 5; i++ {
		peerID := fmt.Sprintf("Peer-%d", i)
		address := fmt.Sprintf("192.168.0.%d", rand.Intn(255))
		n.UpdateRoutingTable(peerID, address)
	}
}

// Start starts the node's message processing and peer discovery
func (n *Node) Start() {
	go n.ProcessMessages()
	n.DiscoverPeers()
}

// Example usage
func main() {
	nodeA := NewNode("A", "192.168.0.1")
	nodeB := NewNode("B", "192.168.0.2")
	nodeC := NewNode("C", "192.168.0.3")

	// Add neighbors
	nodeA.AddNeighbor(nodeB)
	nodeB.AddNeighbor(nodeA)
	nodeA.AddNeighbor(nodeC)
	nodeC.AddNeighbor(nodeA)

	// Start nodes
	nodeA.Start()
	nodeB.Start()
	nodeC.Start()

	// Encrypt a message
	key := messaging.SecureHash("mysecretkey")
	encryptedMessage, err := messaging.EncryptMessage([]byte(key), []byte("Hello, this is a test message"))
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	// Create and send messages with metadata
	metadata := messaging.Metadata{
		Timestamp:  time.Now(),
		SenderID:   nodeA.ID,
		ReceiverID: nodeB.ID,
		OtherData: map[string]string{
			"Info": "Test message",
		},
	}
	message := messaging.SecureMessage{
		Type:      messaging.GeneralMessage,
		Content:   []byte(encryptedMessage),
		Priority:  1,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	nodeA.ReceiveMessage(message)

	// Simulate some wait time
	time.Sleep(2 * time.Second)

	// Decrypt the message
	decryptedMessage, err := messaging.DecryptMessage([]byte(key), encryptedMessage)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}
	fmt.Println("Decrypted message:", string(decryptedMessage))
}
