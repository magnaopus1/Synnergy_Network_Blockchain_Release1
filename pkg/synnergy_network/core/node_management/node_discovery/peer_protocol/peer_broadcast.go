package peer_protocol

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Node represents a node in the network.
type Node struct {
	ID   string
	IP   string
	Port int
}

// PeerProtocol handles peer-to-peer communication for node discovery.
type PeerProtocol struct {
	mu          sync.Mutex
	nodes       map[string]*Node
	broadcastCh chan *Node
	listenAddr  string
	secretKey   []byte
}

// NewPeerProtocol creates a new PeerProtocol.
func NewPeerProtocol(listenAddr string, secretKey []byte) *PeerProtocol {
	return &PeerProtocol{
		nodes:       make(map[string]*Node),
		broadcastCh: make(chan *Node),
		listenAddr:  listenAddr,
		secretKey:   secretKey,
	}
}

// Start starts the peer protocol.
func (p *PeerProtocol) Start() {
	go p.listenForPeers()
	go p.handleBroadcasts()
}

// RegisterNode registers a new node in the network.
func (p *PeerProtocol) RegisterNode(node *Node) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nodes[node.ID] = node
}

// RemoveNode removes a node from the network.
func (p *PeerProtocol) RemoveNode(nodeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.nodes, nodeID)
}

// BroadcastNode broadcasts the presence of a node to the network.
func (p *PeerProtocol) BroadcastNode(node *Node) {
	p.broadcastCh <- node
}

// handleBroadcasts handles broadcasting node information.
func (p *PeerProtocol) handleBroadcasts() {
	for {
		node := <-p.broadcastCh
		p.mu.Lock()
		for _, peer := range p.nodes {
			go p.sendNodeInfo(node, peer)
		}
		p.mu.Unlock()
	}
}

// listenForPeers listens for incoming peer connections.
func (p *PeerProtocol) listenForPeers() {
	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		fmt.Printf("Error starting peer listener: %v\n", err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}
		go p.handlePeerConnection(conn)
	}
}

// handlePeerConnection handles an incoming peer connection.
func (p *PeerProtocol) handlePeerConnection(conn net.Conn) {
	defer conn.Close()

	var node Node
	decoder := json.NewDecoder(conn)
	err := decoder.Decode(&node)
	if err != nil {
		fmt.Printf("Error decoding node information: %v\n", err)
		return
	}

	p.RegisterNode(&node)
}

// sendNodeInfo sends node information to a peer.
func (p *PeerProtocol) sendNodeInfo(node *Node, peer *Node) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", peer.IP, peer.Port))
	if err != nil {
		fmt.Printf("Error connecting to peer %s: %v\n", peer.ID, err)
		return
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	err = encoder.Encode(node)
	if err != nil {
		fmt.Printf("Error sending node information to peer %s: %v\n", peer.ID, err)
	}
}

// generateNodeID generates a unique node ID using scrypt for added security.
func generateNodeID(ip string, port int, secretKey []byte) (string, error) {
	data := fmt.Sprintf("%s:%d", ip, port)
	hash, err := scrypt.Key([]byte(data), secretKey, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash), nil
}

// CreateSecretKey creates a new secret key for use with scrypt.
func CreateSecretKey() ([]byte, error) {
	secretKey := make([]byte, 32)
	_, err := rand.Read(secretKey)
	if err != nil {
		return nil, err
	}
	return secretKey, nil
}

// Usage Example for initializing the PeerProtocol and broadcasting a node.
func main() {
	listenAddr := ":8000"
	secretKey, err := CreateSecretKey()
	if err != nil {
		panic(err)
	}

	protocol := NewPeerProtocol(listenAddr, secretKey)
	protocol.Start()

	ip := "192.168.1.1"
	port := 8001
	nodeID, err := generateNodeID(ip, port, secretKey)
	if err != nil {
		panic(err)
	}

	node := &Node{
		ID:   nodeID,
		IP:   ip,
		Port: port,
	}

	protocol.RegisterNode(node)
	protocol.BroadcastNode(node)

	// Keep the main function running to allow the protocol to operate.
	select {}
}
