package peer_protocol

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p-discovery"
	"context"
	"math/rand"
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
	host        host.Host
	dht         *dht.IpfsDHT
	routingDiscovery *discovery.RoutingDiscovery
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
func (p *PeerProtocol) Start() error {
	var err error
	ctx := context.Background()
	p.host, err = libp2p.New()
	if err != nil {
		return fmt.Errorf("failed to create libp2p host: %w", err)
	}

	p.dht, err = dht.New(ctx, p.host)
	if err != nil {
		return fmt.Errorf("failed to create DHT: %w", err)
	}

	p.routingDiscovery = discovery.NewRoutingDiscovery(p.dht)
	discovery.Advertise(ctx, p.routingDiscovery, "synthron")

	go p.listenForPeers(ctx)
	go p.handleBroadcasts()

	return nil
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
func (p *PeerProtocol) listenForPeers(ctx context.Context) {
	peerChan, err := p.routingDiscovery.FindPeers(ctx, "synthron")
	if err != nil {
		fmt.Printf("Error finding peers: %v\n", err)
		return
	}

	for peerInfo := range peerChan {
		if peerInfo.ID == p.host.ID() {
			continue
		}

		err := p.host.Connect(ctx, peerInfo)
		if err != nil {
			fmt.Printf("Error connecting to peer: %v\n", err)
		} else {
			fmt.Printf("Connected to peer: %s\n", peerInfo.ID.Pretty())
		}
	}
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
	err = protocol.Start()
	if err != nil {
		panic(err)
	}

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
